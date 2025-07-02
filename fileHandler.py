import os, string, sys

# Define common words and special characters as provided by the user
COMMON_WORDS = {
    "a", "an", "the", "and", "or", "but", "is", "are", "was", "were",
    "be", "been", "being", "to", "of", "in", "on", "at", "for", "with",
    "as", "by", "from", "up", "out", "down", "about", "into", "over",
    "under", "through", "above", "below", "between", "among", "before",
    "after", "since", "until", "while", "if", "then", "else", "when",
    "where", "why", "how", "all", "any", "both", "each", "few", "more",
    "most", "other", "some", "such", "no", "nor", "not", "only", "own",
    "same", "so", "than", "too", "very", "s", "t", "can", "will", "just",
    "don", "should", "now", "it", "its", "he", "him", "his", "she", "her",
    "hers", "we", "us", "our", "ours", "you", "your", "yours", "they",
    "them", "their", "theirs", "this", "that", "these", "those", "i", "me",
    "my", "mine"
}

SPECIAL_CHARS = set(string.punctuation)


def get_files(inputDir: str) -> list[str]:
    """
    Returns a list of paths to all non-empty files of supported types
    inside the given directory and its subdirectories.

    Args:
        inputDir (str): The path to the directory to search.

    Returns:
        list[str]: A list of absolute file paths.
                   Exits with an error if the input path does not exist
                   or is not a directory.
    """
    filepaths = []
    # Supported extensions for text analysis
    SUPPORTED_EXTENSIONS = ['.txt', '.TXT', '.log', '.csv', '.json', '.xml', '.html', '.py', '.md', '.yml', '.ini', '']

    if not os.path.exists(inputDir):  # Check if the path even exists
        print(f"ERROR: Path does not exist: {inputDir}")
        sys.exit(2)  # Using sys.exit for critical errors as per original user code intent
    elif not os.path.isdir(inputDir):  # Check if the path is to a dir and not a file
        print(f"Input must be a directory: {inputDir}")
        sys.exit(2)  # Using sys.exit for critical errors

    # Walk through the directory to find all files
    for root, _, files in os.walk(inputDir):
        for file in files:
            file_path = os.path.join(root, file)
            # Check if the file has a supported extension and is not empty
            if file.endswith(tuple(SUPPORTED_EXTENSIONS)) and os.path.getsize(file_path) > 0:
                filepaths.append(file_path)
    return filepaths


def get_data(inputDir: str) -> list[str]:
    """
    Reads all text files from the specified directory and its subdirectories,
    decodes them using common encodings, and returns a list of filtered tokens.

    Args:
        inputDir (str): The path to the directory containing text files.

    Returns:
        list[str]: A list of strings, where each string is a filtered token
                   from the combined content of all readable files.
                   Returns an empty list if the directory does not exist or
                   contains no readable files, or if no tokens pass the filter.
    """
    all_file_contents = []
    # Get all supported file paths
    paths = get_files(inputDir)

    if not paths:
        print(f"No supported non-empty files found in {inputDir}")
        return []

    # Read content from each file with encoding fallback
    for file_path in paths:
        print(f"  Attempting to read file: {file_path}")
        content = None
        encodings_to_try = ['utf-8', 'latin-1', 'cp1252']  # Common encodings

        for encoding in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                print(f"    Successfully read with encoding: {encoding}")
                break  # Break if successful
            except UnicodeDecodeError:
                print(f"    Failed to decode with {encoding}. Trying next encoding...")
            except Exception as e:
                print(f"    An unexpected error occurred while reading {file_path} with {encoding}: {e}")
                break  # Stop trying if a non-decoding error occurs

        if content is not None:
            all_file_contents.append(content)
        else:
            print(f"  Warning: Could not decode file {file_path} with any of the tried encodings. Skipping.")

    sample_text = []
    for text_content in all_file_contents:
        # Replace newlines and spaces with commas, then split into tokens
        corpus_unclean = text_content.replace("\n", ",").replace(" ", ",")
        tokens = corpus_unclean.split(",")

        for token in tokens:
            # Filter out empty strings that result from multiple commas
            if not token:
                continue

            # Check if token is a special character
            if token in SPECIAL_CHARS:
                continue

            # Check if token is a common word (case-insensitive)
            is_common_word = False
            for common_word in COMMON_WORDS:
                if token.lower() == common_word.lower():  # Exact match for common words
                    is_common_word = True
                    break

            if not is_common_word:
                sample_text.append(token)

    return sample_text


"""if __name__ == "__main__":
    # Example Usage:
    # Create a dummy directory and files for testing
    test_dir = "test_data_filtered"
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

    print("--- Test get_data function with filtering ---")
    data = get_data(test_dir)
    print("Filtered Tokens:")
    for token in data:
        print(f"-> {token}")"""

    # Clean up dummy directory
    # import shutil
    # shutil.rmtree(test_dir)
    # print(f"\nCleaned up {test_dir}")
