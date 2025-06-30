import os
import shutil
import tempfile
from git import Repo, InvalidGitRepositoryError, GitCommandError
from typing import List, Dict, Union, Tuple


# Assume these are available from your existing sensitive data finder
# from your_presidio_module import initialize_presidio_analyzer, find_sensitive_data_with_presidio, anonymize_text_with_presidio
# from your_breach_checker_module import check_email_with_xon, check_password_with_hibp

# Dummy functions for demonstration if you don't have Presidio/XON setup yet
class MockAnalyzer:
    def analyze(self, text, entities=None):
        results = []
        if "secret_key" in text:
            results.append({"entity_type": "API_KEY", "start": text.find("secret_key"),
                            "end": text.find("secret_key") + len("secret_key"), "score": 0.9, "text": "secret_key"})
        if "john.doe@example.com" in text:
            results.append({"entity_type": "EMAIL_ADDRESS", "start": text.find("john.doe@example.com"),
                            "end": text.find("john.doe@example.com") + len("john.doe@example.com"), "score": 0.8,
                            "text": "john.doe@example.com"})
        if "password123" in text:
            results.append({"entity_type": "PASSWORD", "start": text.find("password123"),
                            "end": text.find("password123") + len("password123"), "score": 0.7, "text": "password123"})
        return results


def initialize_presidio_analyzer():
    print("Initializing Mock Presidio Analyzer...")
    return MockAnalyzer()


def find_sensitive_data_with_presidio(text: str, analyzer: MockAnalyzer, entities: List[str] = None) -> Dict[
    str, List[Dict]]:
    """Simulates finding sensitive data with Presidio."""
    findings = analyzer.analyze(text, entities)
    categorized_findings = {}
    for f in findings:
        categorized_findings.setdefault(f['entity_type'], []).append(f)
    return categorized_findings


def check_email_with_xon(email_address: str) -> dict:
    """Simulates XposedOrNot check."""
    print(f"  (Simulating XposedOrNot check for {email_address})")
    if "breached@example.com" in email_address:
        return {"breached": True, "details": {"breaches_count": 5}}
    return {"breached": False}


def check_password_with_hibp(password: str) -> int:
    """Simulates HIBP Pwned Passwords check."""
    print(f"  (Simulating HIBP check for password hash prefix)")
    if "password123" in password:  # In real world, check hash prefix
        return 1000000  # Very pwned
    return 0


# End Dummy functions


def get_file_content_at_commit(commit, filepath: str) -> Union[str, None]:
    """
    Retrieves the content of a file at a specific commit.
    Returns None if the file does not exist at that commit.
    """
    try:
        blob = commit.tree / filepath
        # Only read text files, ignore binaries
        if blob.data_stream.read(100).isascii():  # Quick check if likely text
            return blob.data_stream.read().decode('utf-8', errors='ignore')
        else:
            print(f"    Skipping binary file: {filepath}")
            return None
    except KeyError:
        # File does not exist at this commit
        return None
    except Exception as e:
        print(f"    Error reading file {filepath} at commit {commit.hexsha}: {e}")
        return None


def scan_git_repository(
        repo_path_or_url: str,
        presidio_analyzer,
        scan_history: bool = True,
        temp_dir_prefix: str = "git_scan_temp_",
        excluded_file_patterns: List[str] = None,
        included_file_extensions: List[str] = None
) -> List[Dict]:
    """
    Scans a Git repository (cloned or local) for sensitive data.

    Args:
        repo_path_or_url: Local path to the repo or its remote URL.
        presidio_analyzer: An initialized Presidio Analyzer instance.
        scan_history: If True, scans all commits. If False, only the latest commit.
        temp_dir_prefix: Prefix for temporary directory if cloning.
        excluded_file_patterns: List of file/directory patterns to exclude (e.g., ['.git/', 'node_modules/']).
        included_file_extensions: List of extensions to include (e.g., ['.py', '.js', '.txt']).

    Returns:
        A list of dictionaries, each representing a sensitive data finding.
    """
    all_findings = []
    temp_repo_dir = None
    repo = None

    if excluded_file_patterns is None:
        excluded_file_patterns = ['.git/', '.DS_Store', '__pycache__/', '*.log', '*.lock', '*.min.js', '*.css.map',
                                  'node_modules/', '.venv/']
    if included_file_extensions is None:
        included_file_extensions = ['.py', '.js', '.ts', '.java', '.cs', '.php', '.html', '.css', '.json', '.yaml',
                                    '.yml', '.xml', '.txt', '.md', '.env', '.conf', '.config', '.sql']

    def should_scan_file(filepath: str) -> bool:
        """Determines if a file should be scanned based on include/exclude rules."""
        for pattern in excluded_file_patterns:
            if pattern.startswith('/') and filepath.startswith(pattern[1:]):  # Absolute path exclusion
                return False
            elif pattern.endswith('/') and pattern[:-1] in filepath:  # Directory exclusion
                if os.path.isdir(os.path.join(repo.working_dir, filepath)):  # check if it's a directory
                    return False
            elif pattern in filepath:  # Simple substring exclusion
                return False

        if included_file_extensions:
            _, ext = os.path.splitext(filepath)
            return ext.lower() in included_file_extensions
        return True  # If no includes, scan all non-excluded

    try:
        # Determine if it's a local path or a URL
        if os.path.isdir(repo_path_or_url) and os.path.exists(os.path.join(repo_path_or_url, '.git')):
            print(f"Opening local repository: {repo_path_or_url}")
            repo = Repo(repo_path_or_url)
            # Ensure it's not a bare repository
            if repo.bare:
                print(f"Warning: {repo_path_or_url} is a bare repository. Cannot scan working tree.")
                return []
        elif repo_path_or_url.startswith(('http://', 'https://', 'git@')):
            print(f"Cloning remote repository: {repo_path_or_url}")
            temp_repo_dir = tempfile.mkdtemp(prefix=temp_dir_prefix)
            repo = Repo.clone_from(repo_path_or_url, temp_repo_dir)
            print(f"Repository cloned to: {temp_repo_dir}")
        else:
            print(f"Error: '{repo_path_or_url}' is not a valid local Git repository path or remote URL.")
            return []

        if scan_history:
            print("Scanning full Git history...")
            for commit in repo.iter_commits():
                print(f"\nProcessing commit: {commit.hexsha} by {commit.author.name} on {commit.authored_datetime}")

                # Compare current commit with its parent to get diffs
                # For the very first commit, compare against an empty tree
                diff_index = commit.diff(commit.parents[0] if commit.parents else None)

                for diff in diff_index:
                    file_path = diff.b_path  # Path in the current commit
                    if not should_scan_file(file_path):
                        print(f"    Skipping (excluded/not included): {file_path}")
                        continue

                    # Process added/modified files
                    if diff.change_type in ('A', 'M'):  # 'A' for added, 'M' for modified
                        print(f"    Scanning modified/added file: {file_path}")
                        content = get_file_content_at_commit(commit, file_path)
                        if content:
                            findings = find_sensitive_data_with_presidio(content, presidio_analyzer)
                            if findings:
                                print(f"      Found sensitive data in {file_path}:")
                                for entity_type, entity_findings in findings.items():
                                    for f in entity_findings:
                                        finding_record = {
                                            "file_path": file_path,
                                            "commit_hash": commit.hexsha,
                                            "commit_author": commit.author.name,
                                            "commit_date": commit.authored_datetime.isoformat(),
                                            "entity_type": entity_type,
                                            "sensitive_text": f['text'],
                                            "confidence": f['score'],
                                            "location_start": f['start'],
                                            "location_end": f['end'],
                                            "context": content[max(0, f['start'] - 50):f['end'] + 50]
                                            # Snippet for context
                                        }
                                        # Add HIBP/XON checks if applicable
                                        if entity_type == "EMAIL_ADDRESS":
                                            xon_result = check_email_with_xon(f['text'])
                                            finding_record["breach_status_xon"] = xon_result.get("breached", False)
                                            if xon_result.get("breached"):
                                                finding_record["breach_details_xon"] = xon_result.get("details", {})
                                        elif entity_type == "PASSWORD":
                                            hibp_count = check_password_with_hibp(f['text'])
                                            finding_record["pwned_passwords_count"] = hibp_count

                                        all_findings.append(finding_record)
                                        print(
                                            f"        - Type: {entity_type}, Text: '{f['text']}', Confidence: {f['score']:.2f}")

                    # Process deleted files (check content *before* deletion if possible)
                    # This is more complex as you need the content from the *parent* commit.
                    # For simplicity, this example focuses on added/modified.
                    # A robust solution might check diff.a_blob.data_stream.read() for 'D' (deleted) files.

        else:  # Only scan the current working tree
            print("Scanning current working tree only...")
            for root, _, files in os.walk(repo.working_dir):
                for file_name in files:
                    file_path_abs = os.path.join(root, file_name)
                    # Get path relative to repo root
                    file_path_relative = os.path.relpath(file_path_abs, repo.working_dir)

                    if not should_scan_file(file_path_relative):
                        print(f"    Skipping (excluded/not included): {file_path_relative}")
                        continue

                    print(f"  Scanning file: {file_path_relative}")
                    try:
                        with open(file_path_abs, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            findings = find_sensitive_data_with_presidio(content, presidio_analyzer)
                            if findings:
                                print(f"    Found sensitive data in {file_path_relative}:")
                                for entity_type, entity_findings in findings.items():
                                    for f in entity_findings:
                                        finding_record = {
                                            "file_path": file_path_relative,
                                            "commit_hash": "HEAD",  # Indicate current state
                                            "commit_author": "N/A",
                                            "commit_date": "N/A",
                                            "entity_type": entity_type,
                                            "sensitive_text": f['text'],
                                            "confidence": f['score'],
                                            "location_start": f['start'],
                                            "location_end": f['end'],
                                            "context": content[max(0, f['start'] - 50):f['end'] + 50]
                                        }
                                        # Add HIBP/XON checks if applicable
                                        if entity_type == "EMAIL_ADDRESS":
                                            xon_result = check_email_with_xon(f['text'])
                                            finding_record["breach_status_xon"] = xon_result.get("breached", False)
                                            if xon_result.get("breached"):
                                                finding_record["breach_details_xon"] = xon_result.get("details", {})
                                        elif entity_type == "PASSWORD":
                                            hibp_count = check_password_with_hibp(f['text'])
                                            finding_record["pwned_passwords_count"] = hibp_count

                                        all_findings.append(finding_record)
                                        print(
                                            f"      - Type: {entity_type}, Text: '{f['text']}', Confidence: {f['score']:.2f}")

                    except Exception as e:
                        print(f"    Error reading file {file_path_abs}: {e}")

    except InvalidGitRepositoryError:
        print(f"Error: '{repo_path_or_url}' is not a valid Git repository.")
    except GitCommandError as e:
        print(f"Error executing Git command: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if temp_repo_dir and os.path.exists(temp_repo_dir):
            print(f"Cleaning up temporary directory: {temp_repo_dir}")
            shutil.rmtree(temp_repo_dir)

    return all_findings


if __name__ == "__main__":
    analyzer = initialize_presidio_analyzer()

    # --- Example Usage ---
    # 1. Scan a local repository (make sure you have one for testing)
    #    e.g., create a dummy repo:
    #    mkdir my_test_repo
    #    cd my_test_repo
    #    git init
    #    echo "This file has a secret_key_123 and test@example.com." > test_file.txt
    #    git add .
    #    git commit -m "Add sensitive data"
    #    echo "Another line with no sensitive data." >> test_file.txt
    #    git commit -m "Modify file"
    #    echo "My password is password123." >> credentials.py
    #    git add .
    #    git commit -m "Add password file"
    #    rm credentials.py # Delete the file
    #    git commit -m "Remove password file"
    #    echo "Final content." > test_file.txt
    #    git commit -m "Final changes"

    # Replace with an actual path to a local Git repo for testing
    local_repo_path = "./my_test_repo"

    # Create the dummy repo if it doesn't exist for testing this script
    if not os.path.exists(local_repo_path):
        print(f"Creating a dummy Git repository at {local_repo_path} for testing...")
        os.makedirs(local_repo_path)
        os.chdir(local_repo_path)
        os.system("git init")
        os.system('echo "This file has a secret_key_123 and john.doe@example.com." > test_file.txt')
        os.system("git add .")
        os.system('git commit -m "Add sensitive data to test_file.txt"')
        os.system('echo "Another file with a breached@example.com and password123." > credentials.py')
        os.system("git add .")
        os.system('git commit -m "Add credentials.py with email and password"')
        os.system("rm credentials.py")
        os.system('git commit -m "Remove credentials.py - but data is still in history"')
        os.chdir("..")
        print("Dummy repository created.")

    print("\n--- Scanning Local Git Repository (Full History) ---")
    findings_local_history = scan_git_repository(
        local_repo_path,
        analyzer,
        scan_history=True,
        excluded_file_patterns=['.git/', 'temp_files/', '*.log'],
        included_file_extensions=['.txt', '.py', '.js']
    )

    print("\n--- Summary of Findings from Local Repo History ---")
    if findings_local_history:
        for f in findings_local_history:
            print(f"  - File: {f['file_path']}, Type: {f['entity_type']}, Text: '{f['sensitive_text']}'")
            print(f"    Commit: {f['commit_hash']} by {f['commit_author']} on {f['commit_date']}")
            if f['entity_type'] == "EMAIL_ADDRESS":
                print(f"    Breached (XON): {f['breach_status_xon']}")
            elif f['entity_type'] == "PASSWORD":
                print(f"    Pwned Count (HIBP): {f['pwned_passwords_count']}")
            print(f"    Context: {f['context']}")
    else:
        print("  No sensitive data found in local repository history.")

    # 2. Scan a remote public repository (e.g., a simple demo repo)
    #    Be cautious when scanning large public repositories as it involves cloning
    #    and can be resource-intensive and might violate their terms of service if abused.
    #    Use a small, simple public repo for testing if you must.
    # remote_repo_url = "https://github.com/gitleaks/testing" # Example repo with intentional secrets
    # print("\n--- Scanning Remote Git Repository (Current State Only) ---")
    # findings_remote_current = scan_git_repository(
    #     remote_repo_url,
    #     analyzer,
    #     scan_history=False, # Just scan the current HEAD
    #     excluded_file_patterns=['.git/', 'node_modules/']
    # )

    # print("\n--- Summary of Findings from Remote Repo (Current State) ---")
    # if findings_remote_current:
    #     for f in findings_remote_current:
    #         print(f"  - File: {f['file_path']}, Type: {f['entity_type']}, Text: '{f['sensitive_text']}'")
    # else:
    #     print("  No sensitive data found in the current state of the remote repository.")