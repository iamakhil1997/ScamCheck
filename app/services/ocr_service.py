import io
from PIL import Image
import pytesseract
from typing import Dict, Any

def extract_text_from_image_bytes(image_bytes: bytes) -> Dict[str, Any]:
    """
    In-memory OCR extraction using Pillow and pytesseract.
    Ensures image bytes are never written to disk or stored persistently.
    """
    try:
        if not image_bytes or len(image_bytes) == 0:
            return {"success": False, "error": "Uploaded image file is empty."}

        image = Image.open(io.BytesIO(image_bytes))
        
        # Convert image to RGB if necessary
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")

        # Perform OCR
        extracted_text = pytesseract.image_to_string(image)
        cleaned_text = extracted_text.strip()

        if not cleaned_text:
            return {
                "success": False,
                "error": "No readable text could be extracted from the screenshot. Please make sure the image is clear or copy-paste the text manually."
            }

        return {
            "success": True,
            "extracted_text": cleaned_text
        }

    except (pytesseract.TesseractNotFoundError, FileNotFoundError):
        return {
            "success": False,
            "error": "OCR Engine (Tesseract) is not installed on the server environment. Please copy and paste the message text directly into the 'Paste Message' tab."
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to process screenshot: {str(e)}"
        }
