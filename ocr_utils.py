# First, ensure you have the necessary libraries installed:
# pip install Pillow pytesseract pdf2image reportlab

# You also need to install the Tesseract OCR engine itself.
# For Windows: Download from https://tesseract-ocr.github.io/tessdoc/Downloads.html
# For macOS: brew install tesseract
# For Linux (Debian/Ubuntu): sudo apt-get install tesseract-ocr

# Additionally, for pdf2image to work, you need Poppler.
# For Windows: Download poppler for Windows from https://github.com/oschwartz10612/poppler-windows/releases
#              and add its 'bin' directory to your system's PATH.
# For macOS: brew install poppler
# For Linux (Debian/Ubuntu): sudo apt-get install poppler-utils

# Set the path to the Tesseract executable if it's not in your system's PATH.
# Replace 'C:/Program Files/Tesseract-OCR/tesseract.exe' with your actual path.
# For macOS/Linux, if you installed via brew/apt-get, it might be automatically found.
# If you get a 'pytesseract.TesseractNotFoundError', uncomment and adjust this line.
# pytesseract.pytesseract.tesseract_cmd = r''

# Set the path to the Poppler 'bin' directory if it's not in your system's PATH.
# This is required by pdf2image.
# Replace 'C:/Program Files/poppler-XX/bin' with your actual path.
# If you get a 'pdf2image.exceptions.PopplerNotInstalledError', uncomment and adjust this line.

from PIL import Image, ImageDraw, ImageFont
import pytesseract, os
from pdf2image import convert_from_path, exceptions as pdf2image_exceptions
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas as reportlab_canvas
from reportlab.lib.utils import ImageReader

with open("settings.txt", "r") as f: dt = str(f.read()).split(';')
pytesseract.pytesseract.tesseract_cmd = rf'{dt[0].split("=")[1]}' # replace in settings.txt or here with the raw dir
poppler_path = rf'{dt[1].split("=")[1]}' # replace in settings.txt or here with the raw dir
# Default to None to rely on system PATH

def image_to_text(image_path: str) -> str:
    """
    Converts an image file to text using Tesseract OCR.

    Args:
        image_path (str): The path to the input image file.

    Returns:
        str: The extracted text from the image.
    """
    if not os.path.exists(image_path):
        print(f"Error: Image file not found at '{image_path}'")
        return ""

    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)

        return text
    except pytesseract.TesseractNotFoundError:
        print("Error: Tesseract OCR engine not found.")
        print("Please install Tesseract from https://tesseract-ocr.github.io/tessdoc/Downloads.html")
        print("And ensure it's in your system's PATH or set 'pytesseract.pytesseract.tesseract_cmd' in the script.")
        return ""
    except Exception as e:
        print(f"An error occurred during image to text conversion: {e}")
        return ""

def pdf_to_text(pdf_path: str) -> str:
    """
    Converts a PDF file to text by processing each page as an image using Tesseract OCR.
    If the PDF contains images, they will be OCR'd as part of their respective pages.

    Args:
        pdf_path (str): The path to the input PDF file.

    Returns:
        str: The extracted text from the PDF.
    """
    if not os.path.exists(pdf_path):
        print(f"Error: PDF file not found at '{pdf_path}'")
        return ""

    full_text = []
    temp_image_files = []

    try:
        print(f"Converting PDF '{pdf_path}' to images...")
        pages = convert_from_path(pdf_path, dpi=300, poppler_path=poppler_path)
        print(f"Successfully converted {len(pages)} pages to images.")

        for i, page_image in enumerate(pages):
            temp_image_path = f"temp_page_{i+1}.png"
            page_image.save(temp_image_path, 'PNG')
            temp_image_files.append(temp_image_path)
            print(f"Processing page {i+1}...")
            page_text = image_to_text(temp_image_path)
            if page_text:
                full_text.append(f"\n--- Page {i+1} ---\n")
                full_text.append(page_text)
            else:
                full_text.append(f"\n--- Page {i+1} (No text extracted or error) ---\n")

    except pdf2image_exceptions.PopplerNotInstalledError:
        print("Error: Poppler is not installed or its path is not configured correctly.")
        print("Please install Poppler and ensure its 'bin' directory is in your system's PATH,")
        print("or uncomment and provide the 'poppler_path' variable in ocr_utils.py.")
        return ""
    except Exception as e:
        print(f"An error occurred during PDF to text conversion: {e}")
        return ""
    finally:
        for temp_file in temp_image_files:
            if os.path.exists(temp_file): os.remove(temp_file)
                # print(f"Cleaned up temporary image: {temp_file}")

    return "".join(full_text)

# --- Helper function to create a dummy PDF for demonstration ---
def create_dummy_pdf(pdf_path: str, text_content: str, include_image: bool = False, image_path: str = None):
    """
    Creates a simple PDF file with text and optionally an image for demonstration.

    Args:
        pdf_path (str): The path where the dummy PDF will be saved.
        text_content (str): The text to include in the PDF.
        include_image (bool): Whether to include a dummy image in the PDF.
        image_path (str, optional): Path to an image file to embed if include_image is True.
                                    If None, a simple placeholder will be used.
    """
    c = reportlab_canvas.Canvas(pdf_path, pagesize=letter)
    textobject = c.beginText()
    textobject.setTextOrigin(50, 750) # Start position (x, y)
    textobject.setFont("Helvetica", 12)

    for line in text_content.split('\n'):
        textobject.textLine(line)

    c.drawText(textobject)

    if include_image and image_path and os.path.exists(image_path):
        try:
            img_reader = ImageReader(image_path)
            c.drawImage(img_reader, 50, 500, width=200, height=100)
            print(f"Embedded image '{image_path}' into PDF.")
        except Exception as e:
            print(f"Could not embed image '{image_path}' into PDF: {e}")
    elif include_image:
        print("Warning: Could not include image in PDF as image_path was not provided or file not found.")

    c.save()
    print(f"Dummy PDF '{pdf_path}' created for testing.")

# Test

"""
if __name__ == "__main__":
    dummy_image_path = "sample_image_with_text.png"
    try:
        img_width, img_height = 800, 400
        dummy_img = Image.new('RGB', (img_width, img_height), color = (255, 255, 255))
        d = ImageDraw.Draw(dummy_img)
        try:
            font = ImageFont.truetype("arial.ttf", 40)
        except IOError:
            font = ImageFont.load_default()
            print("Could not load 'arial.ttf', using default font. Text rendering might be basic.")
        text_to_write_img = "Hello, this is a sample text for OCR!"
        text_to_write_img += "\nLine 2 with numbers 12345"
        text_to_write_img += "\nAnother line with special characters: !@#$%^&*()"
        bbox = d.textbbox((0,0), text_to_write_img, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (img_width - text_width) / 2
        y = (img_height - text_height) / 2
        d.text((x, y), text_to_write_img, fill=(0, 0, 0), font=font)
        dummy_img.save(dummy_image_path)
        print(f"Dummy image '{dummy_image_path}' created for testing.")

        print("\n--- Running Image to Text Conversion ---")
        extracted_text_img = image_to_text(dummy_image_path)
        if extracted_text_img:
            print("\n--- Extracted Text from Image ---")
            print(extracted_text_img)
            print("---------------------------------")
        else:
            print("\nNo text could be extracted from image or an error occurred.")

    finally:
        if os.path.exists(dummy_image_path):
            os.remove(dummy_image_path)
            print(f"Cleaned up dummy image '{dummy_image_path}'.")

    print("\n" + "="*50 + "\n") # Separator

    # --- PDF to Text Example ---
    dummy_pdf_path = "sample_document.pdf"
    try:
        pdf_content = "This is the first line of text in the PDF.\n" \
                      "It also contains some numbers: 12345.\n" \
                      "And a third line to test the OCR on a PDF document.\n" \
                      "This is a test document for the PDF to text conversion."

        # Create the dummy PDF, optionally including the dummy image created earlier
        create_dummy_pdf(dummy_pdf_path, pdf_content, include_image=True, image_path=dummy_image_path)

        print("\n--- Running PDF to Text Conversion ---")
        # IMPORTANT: If Poppler is not in your system's PATH, you MUST provide poppler_path here.
        # Example: extracted_text_pdf = pdf_to_text(dummy_pdf_path, poppler_path=r'C:/Program Files/poppler-24.02.0/Library/bin')
        extracted_text_pdf = pdf_to_text("/Users/ivansamuel/Downloads/AISC Ambassador Code of Conduct.pdf")

        if extracted_text_pdf:
            print("\n--- Extracted Text from PDF ---")
            print(extracted_text_pdf)
            print("-------------------------------")
        else:
            print("\nNo text could be extracted from PDF or an error occurred.")

    finally:
        # Clean up the dummy PDF file
        if os.path.exists(dummy_pdf_path):
            os.remove(dummy_pdf_path)
            print(f"Cleaned up dummy PDF '{dummy_pdf_path}'.")
        # Ensure dummy_image_path is cleaned up if it was used for embedding
        if os.path.exists(dummy_image_path):
            os.remove(dummy_image_path)
            print(f"Cleaned up dummy image '{dummy_image_path}'.")
"""
