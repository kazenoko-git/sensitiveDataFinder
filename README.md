# sensitiveDataFinder
### An easy way to scan multiple directories and get sensitive data.

## Requirements
* Install the primary requiremnts
  `pip install -r requirements.txt`

### Tesseract OCR
**Windows Installation:**
* Download *https://tesseract-ocr.github.io/tessdoc/Downloads.html*

**MacOS Installation:**
* Install Tesseract-OCR
`brew install tesseract`

**Linux Installation:**
* Install Tesseract-OCR
`sudo apt-get install tesseract-ocr`

* Make sure Tesseract-OCR is in PATH.
* If you are still facing issues, try the below.
> Replace path in settings.txt from *tesseract_dir* to the new path.
> Remove the comment from line 26-27.

### Poppler
**Windows Installation:**
* Download https://github.com/oschwartz10612/poppler-windows/releases

**MacOS Installation:**
* Install Poppler
`brew install poppler`

**Linux Installation:**
* Install Poppler
`sudo apt-get install poppler-utils`

* Make sure Poppler is in PATH.
If you are still facing issues, try the below.
> Replace path in settings.txt from *tesseract_dir* to the new path.
> Remove the comment in line 28.

**Note that you will need a Groq API Key to run this program.**
> Get one from *https://console.groq.com/keys*
> Replace groq_api_key with your API Key.

## What does it do?
The program scans data over any directory given, identifying the sensitive data and also redacting it.
Note that there can be many False Positives when not using Groq Rechecker.

**Supported File-types**
.txt, .log, .csv, .json, .xml, .html, .py, .md, .yml, .ini, .png, .jpg, .jpeg, .gif, .bmp, .tiff, .webp, .pdf


