import os, string

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

def get_files(inputDir):
    """Return list of paths to all non empty files of supported type inside given directory"""
    filepaths = []

    SUPPORTED_EXTENSIONS = ['.txt', '.TXT', '.log', '.csv', '.json', '.xml', '.html', '.py', '.md', '.yml', '.ini', '']

    if not os.path.exists(inputDir):  # check if the path even exists
        print("ERROR: Path does not exist.")
        exit(2)
    elif not os.path.isdir(inputDir):  # check if the path is to a dir and not a file
        print("Input must be a directory.")
        exit(2)

    for root, _, files in os.walk(inputDir):  # search in the directory
        for file in files:
            if file.endswith(tuple(SUPPORTED_EXTENSIONS)) and os.path.getsize(os.path.join(root, file)) > 0:
                filepaths.append(os.path.join(root, file))
    return filepaths


def get_data(inputDir):
    """Returns data"""
    paths = get_files(inputDir)
    sample_text = []
    for file in paths:
        with open(file, "r+") as f:
            corpusUnclean = str(str(f.read()).replace("\n", ",")).replace(" ", ",")
            tokens = corpusUnclean.split(",")
            for token in tokens:
                if token not in SPECIAL_CHARS:
                    for i in COMMON_WORDS:
                        if token.lower() in i.lower():
                            tkn = None
                            break
                        else: tkn = token
                    if tkn is not None: sample_text.append(tkn)
                else: continue
    return sample_text
