import pymupdf
import pytesseract
from PIL import Image, ImageDraw
import io

class HybridRedactor:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    def redact_page_as_image(self, page, pii_entities=["PERSON", "LOCATION", "EMAIL_ADDRESS"]):
        """
        Converts a PDF page to an image, finds PII via OCR, 
        redacts the pixels, and returns a new PDF page.
        """
        # 1. Rasterize page to image (300 DPI for high-quality OCR)
        pix = page.get_pixmap(matrix=pymupdf.Matrix(300/72, 300/72))
        img = Image.open(io.BytesIO(pix.tobytes("png")))
        draw = ImageDraw.Draw(img)

        # 2. Get OCR data (includes text, coordinates, and confidence)
        ocr_data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        
        # Combine all words into one string for the PII Analyzer
        full_text = " ".join(ocr_data['text'])
        
        # 3. Analyze text for PII
        results = self.analyzer.analyze(text=full_text, language='en', entities=pii_entities)

        # 4. Map PII character offsets back to OCR bounding boxes
        # This is a simplified mapper; in production, use a more robust offset-to-word aligner
        for res in results:
            target_pii = full_text[res.start:res.end]
            
            # Find which OCR words match this PII string
            for i, word in enumerate(ocr_data['text']):
                if word and word in target_pii:
                    # Get coordinates
                    l, t, w, h = ocr_data['left'][i], ocr_data['top'][i], ocr_data['width'][i], ocr_data['height'][i]
                    # Draw a black box over the pixels
                    draw.rectangle([l, t, l + w, t + h], fill="black")

        # 5. Convert back to a PDF page
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        
        # Create a new blank PDF doc and insert the sanitized image
        new_pdf = pymupdf.open()
        rect = page.rect  # Get original page dimensions
        new_page = new_pdf.new_page(width=rect.width, height=rect.height)
        new_page.insert_image(rect, stream=img_byte_arr.getvalue())
        
        return new_pdf[0] # Return the sanitized page as a PDF object