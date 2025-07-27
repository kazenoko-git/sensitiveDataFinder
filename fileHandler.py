import os
import sys
import tempfile
import shutil
from datetime import datetime
from typing import Iterator

try:
    from ocr_utils import image_to_text, pdf_to_text
except ImportError:
    print("ERROR: Could not import 'ocr_utils'. Please ensure dependencies are installed.")
    sys.exit(1)

try:
    from gitHandler import clone_repository, cleanup_repository
except ImportError:
    print("ERROR: Could not import 'gitHandler'. Please ensure Git is installed and the handler is present.")
    sys.exit(1)

TEXT_EXTENSIONS = ('.txt', '.log', '.csv', '.json', '.xml', '.html', '.py', '.md', '.yml', '.ini', '')
IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp')
PDF_EXTENSIONS = ('.pdf',)
ALL_SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS + IMAGE_EXTENSIONS + PDF_EXTENSIONS


class FileModificationError(Exception):
    pass


class FileWriter:
    def __init__(self, target_path, create_backup=True, mode='w', backup_dir=None):
        self.target_path = target_path
        self.create_backup = create_backup
        self.mode = mode  # 'w' for overwrite, 'a' for append
        self.backup_dir = backup_dir or os.path.dirname(target_path)
        self.backup_path = None
        self.temp_path = None
        self.temp_file = None

    def __enter__(self):
        if self.create_backup and os.path.exists(self.target_path):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"{os.path.basename(self.target_path)}.backup_{timestamp}"
            self.backup_path = os.path.join(self.backup_dir, backup_filename)
            shutil.copy2(self.target_path, self.backup_path)

        target_dir = os.path.dirname(os.path.abspath(self.target_path))
        self.temp_file = tempfile.NamedTemporaryFile(
            mode=self.mode,
            dir=target_dir,
            delete=False,
            encoding='utf-8',
            prefix=f".tmp_{os.path.basename(self.target_path)}_",
            suffix='.tmp'
        )
        self.temp_path = self.temp_file.name
        return self.temp_file

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_file:
            self.temp_file.close()
        if exc_type is None:
            try:
                os.replace(self.temp_path, self.target_path)
            except Exception as e:
                if self.temp_path and os.path.exists(self.temp_path):
                    os.remove(self.temp_path)
                raise FileModificationError(f"Failed to update file {self.target_path}: {e}")
        else:
            if self.temp_path and os.path.exists(self.temp_path):
                os.remove(self.temp_path)

    def rollback(self):
        if self.backup_path and os.path.exists(self.backup_path):
            shutil.copy2(self.backup_path, self.target_path)
            print(f"File restoration from backup succeeded: {self.backup_path}")
            return True
        return False


def get_files(input_path: str) -> list[str]:
    filepaths = []
    if not os.path.exists(input_path):
        print(f"ERROR: Path does not exist: {input_path}")
        sys.exit(2)
    elif not os.path.isdir(input_path):
        print(f"ERROR: Provided path is not a directory: {input_path}")
        sys.exit(2)

    for root, _, files in os.walk(input_path):
        for file in files:
            if file.startswith('.') or file == '.DS_Store':  # exclude hidden and macOS system files
                continue
            file_path = os.path.join(root, file)
            if file_path.lower().endswith(ALL_SUPPORTED_EXTENSIONS) and os.path.getsize(file_path) > 0:
                filepaths.append(file_path)
    return filepaths


def get_data_with_paths(input_source: str) -> Iterator[tuple[str, str]]:
    is_github_url = input_source.startswith(("http://", "https://"))
    local_dir = input_source
    temp_dir = None

    if is_github_url:
        temp_dir = tempfile.mkdtemp(prefix="pii_repo_")
        if not clone_repository(input_source, temp_dir):
            if temp_dir:
                cleanup_repository(temp_dir)
            return  # yield nothing
        local_dir = temp_dir

    if not os.path.isdir(local_dir):
        print(f"ERROR: Path is not a directory: {local_dir}")
        return  # yield nothing

    try:
        files = get_files(local_dir)
        for fp in files:
            if os.path.basename(fp).startswith('.') or os.path.basename(fp).lower() == '.ds_store':
                continue  # skip hidden/system files
            ext = os.path.splitext(fp)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
            content = None
            for enc in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    with open(fp, 'r', encoding=enc) as f:
                        content = f.read()
                    break
                except Exception:
                    continue
            if content is not None:
                yield (fp, content)
    finally:
        if temp_dir:
            cleanup_repository(temp_dir)


def modify_files_remove_pii(input_source: str, anonymized_results: list, create_backup=True, append=False) -> dict:
    results = {
        'modified': [],
        'backup': [],
        'errors': [],
        'skipped': []
    }
    try:
        files_with_content = list(get_data_with_paths(input_source))

        if not files_with_content:
            results['errors'].append("No text files found.")
            return results

        if len(anonymized_results) != len(files_with_content):
            results['errors'].append(f"Number of anonymized results ({len(anonymized_results)}) does not match number of files ({len(files_with_content)}).")
            return results

        # Always open temp files in write mode; we handle append manually by content concat
        mode = 'w'

        for i, (file_path, original_content) in enumerate(files_with_content):
            try:
                anonymized_content = anonymized_results[i]

                # If appending, combine old + new; else just new
                if append:
                    combined_content = original_content + "\n" + anonymized_content
                else:
                    combined_content = anonymized_content

                # Skip rewriting if no changes and not appending
                if not append and original_content.strip() == anonymized_content.strip():
                    results['skipped'].append(file_path)
                    continue

                with FileWriter(file_path, create_backup=create_backup, mode=mode) as f:
                    f.write(combined_content)

                results['modified'].append(file_path)

                if create_backup:
                    backup_path = None
                    backup_files = [f for f in os.listdir(os.path.dirname(file_path))
                                    if f.startswith(os.path.basename(file_path)) and 'backup' in f]
                    if backup_files:
                        backup_files.sort()
                        backup_path = os.path.join(os.path.dirname(file_path), backup_files[-1])
                        results['backup'].append(backup_path)

            except Exception as e:
                results['errors'].append(f"Failed modifying {file_path}: {e}")

    except Exception as e:
        results['errors'].append(f"Failed during file modification: {e}")

    return results
