# First, ensure you have the necessary libraries installed:
# pip install Pillow pytesseract

# You also need to install the Tesseract OCR engine itself.
# For Windows: Download from https://tesseract-ocr.github.io/tessdoc/Downloads.html
# For macOS: brew install tesseract
# For Linux (Debian/Ubuntu): sudo apt-get install tesseract-ocr

# Import the necessary libraries
from PIL import Image
import pytesseract
import os

# --- Configuration ---
# Set the path to the Tesseract executable if it's not in your system's PATH.
# Replace 'C:/Program Files/Tesseract-OCR/tesseract.exe' with your actual path.
# For macOS/Linux, if you installed via brew/apt-get, it might be automatically found.
# If you get a 'pytesseract.TesseractNotFoundError', uncomment and adjust this line.
# pytesseract.pytesseract.tesseract_cmd = r'C:/Program Files/Tesseract-OCR/tesseract.exe'

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
        # Open the image using Pillow
        img = Image.open(image_path)

        # Use pytesseract to perform OCR on the image
        # You can specify the language using the 'lang' parameter, e.g., lang='eng' for English.
        # For multiple languages, use '+', e.g., lang='eng+fra'
        text = pytesseract.image_to_string(img)

        return text
    except pytesseract.TesseractNotFoundError:
        print("Error: Tesseract OCR engine not found.")
        print("Please install Tesseract from https://tesseract-ocr.github.io/tessdoc/Downloads.html")
        print("And ensure it's in your system's PATH or set 'pytesseract.pytesseract.tesseract_cmd' in the script.")
        return ""
    except Exception as e:
        print(f"An error occurred: {e}")
        return ""

# --- Example Usage ---
if __name__ == "__main__":
    # Create a dummy image file for demonstration purposes
    # In a real scenario, you would use an actual image file.
    # For this example, we'll simulate an image with text.
    # You can replace 'sample_image.png' with the path to your own image.

    dummy_image_path = "sample_image_with_text.png"

    try:
        # This part is just to create a *very simple* image for testing if you don't have one.
        # For actual OCR, you'd use a real image with printed/typed text.
        from PIL import ImageDraw, ImageFont
        img_width, img_height = 800, 400
        dummy_img = Image.new('RGB', (img_width, img_height), color = (255, 255, 255))
        d = ImageDraw.Draw(dummy_img)

        try:
            # Try to load a default font, or use a generic one if not found
            font = ImageFont.truetype("arial.ttf", 40)
        except IOError:
            font = ImageFont.load_default()
            print("Could not load 'arial.ttf', using default font. Text rendering might be basic.")

        text_to_write = "Hello, this is a sample text for OCR!"
        text_to_write += "\nLine 2 with numbers 12345"
        text_to_write += "\nAnother line with special characters: !@#$%^&*()"

        # Calculate text size to center it
        bbox = d.textbbox((0,0), text_to_write, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        x = (img_width - text_width) / 2
        y = (img_height - text_height) / 2

        d.text((x, y), text_to_write, fill=(0, 0, 0), font=font)
        dummy_img.save(dummy_image_path)
        print(f"Dummy image '{dummy_image_path}' created for testing.")

        # Perform OCR on the dummy image
        extracted_text = image_to_text(dummy_image_path)

        if extracted_text:
            print("\n--- Extracted Text ---")
            print(extracted_text)
            print("----------------------")
        else:
            print("\nNo text could be extracted or an error occurred.")

    finally:
        # Clean up the dummy image file
        if os.path.exists(dummy_image_path):
            os.remove(dummy_image_path)
            print(f"Cleaned up dummy image '{dummy_image_path}'.")

