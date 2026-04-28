import fitz  # PyMuPDF
from presidio_analyzer import AnalyzerEngine
import uuid

class PseudonymizedRedactor:
    def __init__(self):
        self.analyzer = AnalyzerEngine(default_score_threshold=0.4)
        # Stores { "Original Name": "PERSON_1" }
        self.entity_map = {} 
        # Reverse map for your traceback: { "PERSON_1": "Original Name" }
        self.traceback_map = {} 
        self.counters = {"PERSON": 0, "LOCATION": 0, "EMAIL_ADDRESS": 0, "ID": 0}

    def get_pseudonym(self, original_text, entity_type):
        """Returns a consistent pseudonym for a given piece of text."""
        if original_text not in self.entity_map:
            self.counters[entity_type] = self.counters.get(entity_type, 0) + 1
            pseudonym = f"[{entity_type}_{self.counters[entity_type]}]"
            self.entity_map[original_text] = pseudonym
            self.traceback_map[pseudonym] = original_text
        return self.entity_map[original_text]

    def process_pdf(self, input_path, output_path):
        doc = fitz.open(input_path)
        
        for page in doc:
            text = page.get_text("text")
            results = self.analyzer.analyze(
                text=text, 
                language='en', 
                entities=["PERSON", "LOCATION", "EMAIL_ADDRESS"]
            )

            # Sort results in reverse to avoid offset shifts if modifying text directly
            # However, for PDF drawing, we just need the coordinates
            for res in results:
                original_val = text[res.start:res.end]
                pseudo_val = self.get_pseudonym(original_val, res.entity_type)
                
                # Find coordinates of the sensitive text
                areas = page.search_for(original_val)
                
                for rect in areas:
                    # 1. Clean the area (remove original text)
                    page.add_redact_annot(rect, fill=(1, 1, 1)) # White fill
                    page.apply_redactions()
                    
                    # 2. Insert the pseudonym in the same spot
                    # We use a slightly smaller font to ensure it fits the box
                    page.insert_text(rect.tl, pseudo_val, fontsize=9, color=(1, 0, 0))

        doc.save(output_path)
        doc.close()
        return self.traceback_map

# --- Execution ---
if __name__ == "__main__":
    engine = PseudonymizedRedactor()
    
    # Process the file
    mapping = engine.process_pdf("input.pdf", "pseudonymized_output.pdf")
    
    print("--- Traceback Mapping ---")
    for pseudo, real in mapping.items():
        print(f"{pseudo} -> {real}")