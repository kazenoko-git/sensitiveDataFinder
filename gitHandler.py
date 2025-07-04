import os
import shutil
import subprocess

def clone_repository(repo_url: str, local_path: str) -> bool:
    """
    Clones a GitHub repository to a specified local path.

    Args:
        repo_url (str): The URL of the GitHub repository (e.g., "https://github.com/user/repo.git").
        local_path (str): The local directory path where the repository should be cloned.

    Returns:
        bool: True if cloning was successful, False otherwise.
    """
    if os.path.exists(local_path):
        print(f"Warning: Local path '{local_path}' already exists. Attempting to remove it.")
        try:
            shutil.rmtree(local_path)
            print(f"Successfully removed existing directory: {local_path}")
        except Exception as e:
            print(f"Error removing existing directory '{local_path}': {e}")
            return False

    print(f"Cloning '{repo_url}' to '{local_path}'...")
    try:
        # Use subprocess to run the git clone command
        # check=True will raise CalledProcessError if the command fails
        subprocess.run(['git', 'clone', repo_url, local_path], check=True, capture_output=True, text=True)
        print(f"Successfully cloned repository to '{local_path}'.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print("Error: 'git' command not found. Please ensure Git is installed and in your system's PATH.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during cloning: {e}")
        return False

def cleanup_repository(local_path: str) -> bool:
    """
    Removes the specified local repository directory.

    Args:
        local_path (str): The path to the local repository directory to remove.

    Returns:
        bool: True if cleanup was successful, False otherwise.
    """
    if os.path.exists(local_path):
        print(f"Cleaning up local repository at '{local_path}'...")
        try:
            shutil.rmtree(local_path)
            print(f"Successfully removed '{local_path}'.")
            return True
        except Exception as e:
            print(f"Error cleaning up repository at '{local_path}': {e}")
            return False
    else:
        print(f"No repository found at '{local_path}' to clean up.")
        return True # Considered successful if nothing to remove

if __name__ == "__main__":
    # Example Usage:
    test_repo_url = "https://github.com/git/git.git" # A public, small repository for testing
    test_local_path = "temp_github_repo"

    print("\n--- Testing clone_repository ---")
    if clone_repository(test_repo_url, test_local_path):
        print("Cloning test successful!")
        # You can now inspect the 'temp_github_repo' directory
    else:
        print("Cloning test failed.")

    print("\n--- Testing cleanup_repository ---")
    if cleanup_repository(test_local_path):
        print("Cleanup test successful!")
    else:
        print("Cleanup test failed.")

    # Test with a non-existent URL (expected to fail)
    print("\n--- Testing clone_repository with invalid URL ---")
    if not clone_repository("https://github.com/nonexistent/repo.git", "invalid_repo"):
        print("Cloning invalid URL test successful (expected failure).")
    else:
        print("Cloning invalid URL test failed (unexpected success).")
    cleanup_repository("invalid_repo") # Clean up if it somehow got created
