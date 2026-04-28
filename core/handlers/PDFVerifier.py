import pymupdf
import pytesseract
from PIL import Image
import io, os, sys
from rapidfuzz import fuzz

class PDFVerifier:
    def __init__(self, tesseract_path=None):
        if tesseract_path:
            pytesseract.pytesseract.tesseract_cmd = tesseract_path
            
    def get_ocr_text(self, page):
        """Renders page to image and runs OCR."""
        # Increase DPI for better OCR accuracy (300 is standard for text)
        pix = page.get_pixmap(matrix=pymupdf.Matrix(300/72, 300/72))
        img_data = pix.tobytes("png")
        img = Image.open(io.BytesIO(img_data))
        
        return pytesseract.image_to_string(img)

    def verify_document(self, pdf_path):
        doc = pymupdf.open(pdf_path)
        report = []

        for page_num in range(len(doc)):
            page = doc[page_num]
            
            # 1. Get Embedded Text
            embedded_text = page.get_text("text").strip()
            
            # 2. Get OCR Text
            ocr_text = self.get_ocr_text(page).strip()
            
            # 3. Compare
            # ratio() returns a score from 0-100 (100 is a perfect match)
            similarity = fuzz.ratio(embedded_text.lower(), ocr_text.lower())
            
            discrepancy_found = similarity < 90  # Threshold for "significant" difference
            
            page_report = {
                "page": page_num + 1,
                "similarity_score": round(similarity, 2),
                "discrepancy_detected": discrepancy_found,
                "embedded_sample": embedded_text[:100] + "...",
                "ocr_sample": ocr_text[:100] + "..."
            }
            report.append(page_report)
            
            if discrepancy_found:
                print(f"⚠️ Discrepancy on Page {page_num + 1}! Score: {similarity}%")
                # Logic: If OCR finds text but Embedded is empty, it's a scanned image.
                if not embedded_text and ocr_text:
                    print("   Reason: Page appears to be a scanned image (No embedded text).")
                elif len(embedded_text) != len(ocr_text):
                    print(f"   Reason: Text length mismatch (Emb: {len(embedded_text)}, OCR: {len(ocr_text)})")

        doc.close()
        return report

# --- Execution ---
if __name__ == "__main__":
    # Check if a filename was provided as an argument
    if len(sys.argv) < 2:
        print("Usage: python PDFVerifier.py <path_to_pdf>")
        sys.exit(1)

    # Take the filename from the first command line parameter
    input_filename = sys.argv[1]

    # Verify the file exists before proceeding
    if not os.path.exists(input_filename):
        print(f"❌ Error: The file '{input_filename}' does not exist.")
        sys.exit(1)

    # Initialize and run the verifier
    verifier = PDFVerifier()
    
    try:
        print(f"--- Starting Optical Integrity Validation for: {input_filename} ---")
        results = verifier.verify_document(input_filename)
        
        print("\n--- Final Verification Report ---")
        for r in results:
            status = "❌ FAIL" if r['discrepancy_detected'] else "✅ PASS"
            print(f"Page {r['page']}: {status} (Match: {r['similarity_score']}%)")
            
            if r['discrepancy_detected']:
                print(f"   [!] Large discrepancy detected on page {r['page']}. Review manually.")
                
    except Exception as e:
        print(f"❌ An error occurred during processing: {e}")