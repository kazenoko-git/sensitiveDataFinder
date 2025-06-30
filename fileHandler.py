import sys
import os

def getFile(inputDir):
    if not os.path.exists(inputDir):  # check if the path even exists
        print("ERROR: Path does not exist.")
        exit(2)
    elif not os.path.isdir(inputDir):  # check if the path is to a dir and not a file
        print("Input must be a directory.")
        exit(2)
    """Return list of paths to all files inside given directory"""
    filepaths = []
    for root, _, files in os.walk(inputDir):
        for file in files:
            filepaths.append(os.path.join(root, file))
    return filepaths