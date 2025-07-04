import os, string, sys, tempfile
# Import OCR functions from ocr_utils.py
try:
    from ocr_utils import image_to_text, pdf_to_text
except ImportError:
    print("ERROR: Could not import OCR functions from 'ocr_utils.py'.")
    print(
        "Please ensure 'ocr_utils.py' is in the same directory and necessary libraries (Pillow, pytesseract, pdf2image, reportlab) are installed.")
    sys.exit(1)

# Import GitHub functions from github_handler.py
try:
    from gitHandler import clone_repository, cleanup_repository
except ImportError:
    print("ERROR: Could not import GitHub functions from 'gitHandler.py'.")
    print("Please ensure 'gitHandler.py' is in the same directory and Git is installed.")
    sys.exit(1)

# Define supported extensions globally for use in get_files
TEXT_EXTENSIONS = ('.txt', '.TXT', '.log', '.csv', '.json', '.xml', '.html', '.py', '.md', '.yml', '.ini', '')
IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp')
PDF_EXTENSIONS = ('.pdf',)
ALL_SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS + IMAGE_EXTENSIONS + PDF_EXTENSIONS


def get_files(input_path: str) -> list[str]:
    """
    Returns a list of paths to all non-empty files of supported types
    inside the given directory and its subdirectories.

    Args:
        input_path (str): The path to the directory to search.

    Returns:
        list[str]: A list of absolute file paths.
                   Exits with an error if the input path does not exist
                   or is not a directory.
    """
    filepaths = []

    if not os.path.exists(input_path):
        print(f"ERROR: Path does not exist: {input_path}")
        sys.exit(2)
    elif not os.path.isdir(input_path):
        print(f"Input must be a directory: {input_path}")
        sys.exit(2)

    for root, _, files in os.walk(input_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.lower().endswith(ALL_SUPPORTED_EXTENSIONS) and os.path.getsize(file_path) > 0:
                filepaths.append(file_path)
    return filepaths


def get_data(input_source: str) -> list[str]:
    """
    Reads all text files, extracts text from image files, and extracts text from PDF files
    from the specified input source (either a local directory path or a GitHub URL).
    Returns the full text content of each processed file.

    Args:
        input_source (str): The path to a local directory or a GitHub repository URL.

    Returns:
        list[str]: A list of strings, where each string is the full text content
                   of a readable file (text, image-extracted, or PDF-extracted).
                   Returns an empty list if the input source is invalid or
                   contains no readable files.
    """
    all_processed_contents = []

    is_github_url = input_source.startswith("http://") or input_source.startswith("https://")

    local_dir_to_scan = input_source
    temp_dir = None

    if is_github_url:
        print(f"Input is a GitHub URL: {input_source}")
        temp_dir = tempfile.mkdtemp(prefix="pii_repo_")
        print(f"Cloning repository to temporary directory: {temp_dir}")
        if not clone_repository(input_source, temp_dir):
            print(f"Error: Failed to clone repository from {input_source}. Cannot proceed with analysis.")
            if temp_dir:
                cleanup_repository(temp_dir)
            return []
        local_dir_to_scan = temp_dir
    else:
        print(f"Input is a local directory path: {input_source}")
        if not os.path.exists(input_source) or not os.path.isdir(input_source):
            print(f"Error: Local directory '{input_source}' does not exist or is not a directory.")
            return []

    try:
        paths = get_files(local_dir_to_scan)

        if not paths:
            print(f"No supported non-empty files found in {local_dir_to_scan}")
            return []

        for file_path in paths:
            file_extension = os.path.splitext(file_path)[1].lower()
            content = None

            if file_extension in TEXT_EXTENSIONS:
                print(f"  Attempting to read text file: {file_path}")
                encodings_to_try = ['utf-8', 'latin-1', 'cp1252']
                for encoding in encodings_to_try:
                    try:
                        with open(file_path, 'r', encoding=encoding) as f:
                            content = f.read()
                        print(f"    Successfully read with encoding: {encoding}")
                        break
                    except UnicodeDecodeError:
                        print(f"    Failed to decode with {encoding}. Trying next encoding...")
                    except Exception as e:
                        print(f"    An unexpected error occurred while reading {file_path} with {encoding}: {e}")
                        break

                if content is None:
                    print(
                        f"  Warning: Could not decode text file {file_path} with any of the tried encodings. Skipping.")

            elif file_extension in IMAGE_EXTENSIONS:
                print(f"  Attempting to extract text from image file: {file_path}")
                extracted_image_text = image_to_text(file_path)
                if extracted_image_text:
                    content = extracted_image_text
                    print(f"    Successfully extracted text from image.")
                else:
                    print(
                        f"  Warning: No text extracted from image file {file_path} or an OCR error occurred. Skipping.")

            elif file_extension in PDF_EXTENSIONS:
                print(f"  Attempting to extract text from PDF file: {file_path}")
                extracted_pdf_text = pdf_to_text(file_path)
                if extracted_pdf_text:
                    content = extracted_pdf_text
                    print(f"    Successfully extracted text from PDF.")
                else:
                    print(f"  Warning: No text extracted from PDF file {file_path} or an OCR error occurred. Skipping.")
            else:
                print(f"  Skipping unsupported file type: {file_path}")
                continue

            if content is not None:
                all_processed_contents.append(content)

        return all_processed_contents
    finally:
        if temp_dir:
            cleanup_repository(temp_dir)


if __name__ == "__main__":
    # Example Usage:
    test_dir = "test_data_combined"
    os.makedirs(test_dir, exist_ok=True)

    with open(os.path.join(test_dir, "file1.txt"), "w", encoding="utf-8") as f:
        f.write("This is a sample UTF-8 text with some PII like email@example.com and phone 123-456-7890. John Doe.")

    try:
        with open(os.path.join(test_dir, "file2_latin1.txt"), "w", encoding="latin-1") as f:
            f.write("This file has a special character: é and a name Jane Smith. The quick brown fox.")
    except Exception as e:
        print(f"Could not create latin-1 file (might not be supported on your system): {e}")

    with open(os.path.join(test_dir, "file3.log"), "w", encoding="utf-8") as f:
        f.write("Another text with a credit card number 1234-5678-9012-3456. And a password: MyStrongP@ssw0rd!")

    try:
        from PIL import Image, ImageDraw, ImageFont

        img_test_path = os.path.join(test_dir, "dummy_image_for_ocr.png")
        img_test = Image.new('RGB', (200, 50), color=(255, 255, 255))
        d = ImageDraw.Draw(img_test)
        try:
            fnt = ImageFont.truetype("arial.ttf", 20)
        except IOError:
            try:
                fnt = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 20)
            except IOError:
                fnt = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20)
            except IOError:
                fnt = ImageFont.load_default()

        d.text((10, 10), "Image Text 789", fill=(0, 0, 0), font=fnt)
        img_test.save(img_test_path)
        print(f"Created dummy image for OCR: {img_test_path}")
    except ImportError:
        print("Pillow not installed, skipping dummy image creation for OCR test.")
    except Exception as e:
        print(f"Error creating dummy image for OCR: {e}")

    dummy_pdf_path = os.path.join(test_dir, "dummy_document_for_ocr.pdf")
    try:
        from ocr_utils import create_dummy_pdf

        pdf_content = "This is PDF text. It has a social security number 999-88-7777."
        create_dummy_pdf(dummy_pdf_path, pdf_content, include_image=True, image_path=img_test_path)
        print(f"Created dummy PDF for OCR: {dummy_pdf_path}")
    except ImportError:
        print("Required libraries for PDF creation (reportlab, pdf2image) not installed, skipping dummy PDF creation.")
    except Exception as e:
        print(f"Error creating dummy PDF: {e}")

    print("\n--- Test get_data function with combined text, image, and PDF processing (local) ---")
    data = get_data(test_dir)
    print("\nFull Contents from local files:")
    for i, content in enumerate(data):
        print(f"--- File {i + 1} ---\n{content}\n-----------------")

    print("\n--- Test get_data function with GitHub URL (expected to clone git/git.git) ---")
    github_test_url = "https://github.com/git/git.git"
    github_data = get_data(github_test_url)
    print("\nFull Contents from GitHub repository (first 2 items):")
    if github_data:
        for i, content in enumerate(github_data[:2]):  # Print first 2 items to avoid spamming
            print(f"--- GitHub File {i + 1} ---\n{content}\n-----------------")
        if len(github_data) > 2:
            print(f"... and {len(github_data) - 2} more files.")
    else:
        print("No data extracted from GitHub repository.")

    import shutil

    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
        print(f"\nCleaned up {test_dir}")
