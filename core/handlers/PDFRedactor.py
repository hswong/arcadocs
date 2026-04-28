import fitz  # PyMuPDF
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

class PDFRedactor:
    def __init__(self):
        # Initialize the engine with the spaCy model
        self.analyzer = AnalyzerEngine(default_score_threshold=0.4)
        
    def redact_pdf(self, input_path, output_path):
        doc = fitz.open(input_path)
        
        for page in doc:
            # 1. Extract text from the page
            text = page.get_text("text")
            
            # 2. Analyze text for PII (Names, Phones, Emails, IDs, etc.)
            # You can add specific entities like "LOCATION" or "IT_ASSET"
            analysis_results = self.analyzer.analyze(
                text=text, 
                language='en', 
                entities=["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "LOCATION", "US_ITIN"]
            )
            
            # 3. Map PII results to PDF coordinates and apply redaction
            for result in analysis_results:
                # Find the actual string in the text based on character offsets
                pii_text = text[result.start:result.end]
                
                # Search for this text on the page to get its bounding box (coordinates)
                areas = page.search_for(pii_text)
                
                for rect in areas:
                    # Add a redaction annotation (the black box)
                    page.add_redact_annot(rect, fill=(0, 0, 0))
            
            # 4. Apply the redactions (this physically deletes the text/images underneath)
            page.apply_redactions()
            
        # Save the sanitized file
        doc.save(output_path, garbage=4, deflate=True)
        doc.close()
        print(f"Successfully redacted: {output_path}")

# --- Execution ---
if __name__ == "__main__":
    redactor = PDFRedactor()
    
    # Example Usage
    input_file = "private_document.pdf"
    output_file = "sanitized_document.pdf"
    
    try:
        redactor.redact_pdf(input_file, output_file)
    except Exception as e:
        print(f"Error processing PDF: {e}")