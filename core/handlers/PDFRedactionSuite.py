import pymupdf
import pytesseract
from PIL import Image, ImageDraw
import io
import json
import sqlite3
import uuid
import datetime
import subprocess
import os
import argparse
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from rapidfuzz import fuzz

APP_VERSION = "3.0.0"

class PDFRedactionSuite:
    def __init__(self, db_path="redaction_audit.db"):
        # 1. Create a recognizer for your specific name
        my_name_recognizer = PatternRecognizer(
            supported_entity="PERSON", 
            name="my_name_recognizer",
            deny_list=["Wong Hoong Shen", "HS Wong", "Hswong"] # Direct match list
        )

        # 2. Create a recognizer for your specific address using a Regex pattern
        my_address_pattern = Pattern(
            name="my_home_address",
            regex=r"\d{1,3}\s+Lorong\s+\d{1}\s+Toa\s+Payoh", # Replace with your actual address regex
            score=1.0
        )

        # Define the pattern for SG Unit Numbers
        unit_number_pattern = Pattern(
            name="sg_unit_number",
            regex=r"#\d{2,3}-\d{2,5}",
            score=1.0
        )

        my_address_recognizer = PatternRecognizer(
            supported_entity="LOCATION",
            patterns=[my_address_pattern, unit_number_pattern]
        )
        self.db_path = db_path
        self.analyzer = AnalyzerEngine(default_score_threshold=0.4)
        # 3. Add these to your existing AnalyzerEngine
        # (Assuming 'self.analyzer' in your PDFRedactionSuite)
        self.analyzer.registry.add_recognizer(my_name_recognizer)
        self.analyzer.registry.add_recognizer(my_address_recognizer)
        self.git_hash = self._get_git_hash()
        self._init_db()

    def _get_git_hash(self):
        try:
            return subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).decode('ascii').strip()
        except:
            return "no-git"

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    exec_id TEXT PRIMARY KEY,
                    filename TEXT,
                    version TEXT,
                    git_hash TEXT,
                    status TEXT,
                    traceback_map TEXT,
                    validation_results TEXT,
                    updated_at TEXT
                )
            """)

    # --- THE REDACTION ENGINES ---

    def standard_redaction(self, page, traceback_manager):
        # ... your detection logic ...
        for rect in page.search_for(original_val):
            page.add_redact_annot(rect, text=label, fill=(1,1,1))
        
        # CRITICAL: This is the 'Scrubbing' step
        page.apply_redactions(
            images=pymupdf.PDF_REDACT_IMAGE_NONE, # Don't touch images
            graphics=pymupdf.PDF_REDACT_GRAPHICS_REMOVE # Remove vector paths
        )
        
        # This final step removes the 'hidden' text layer for the redacted areas
        page.clean_contents()

    def hybrid_redaction(self, doc, page, traceback_manager):
        pno = page.number
        rect = page.rect
        
        # 1. Rasterize
        pix = page.get_pixmap(matrix=pymupdf.Matrix(2, 2))
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        draw = ImageDraw.Draw(img)
        
        # 2. OCR and Detection (standard logic)
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        full_text = " ".join([w for w in data['text'] if w.strip()])
        results = self.analyzer.analyze(text=full_text, language='en', entities=["PERSON", "LOCATION"])

        # 3. Draw Redactions
        for res in results:
            target = full_text[res.start:res.end]
            label = traceback_manager.get_pseudo(target, res.entity_type)
            for i, word in enumerate(data['text']):
                if word and word in target:
                    l, t, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                    draw.rectangle([l, t, l+w, t+h], fill="white")
                    draw.text((l, t), label, fill="red")

        # 4. Prepare the New Page
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='JPEG', quality=75, optimize=True)
        
        # 5. THE SWAP
        # Insert the new sanitized page at the same position
        new_page = doc.new_page(pno=pno + 1, width=rect.width, height=rect.height)
        new_page.insert_image(rect, stream=img_byte_arr.getvalue())
        
        # Delete the old page ONLY after the new one is safely inserted
        doc.delete_page(pno)
        
        return True # Signal success

    # def hybrid_redaction(self, page, traceback_manager):
    #     # 1. Rasterize to high-res image
    #     pix = page.get_pixmap(matrix=pymupdf.Matrix(300/72, 300/72))
    #     img = Image.open(io.BytesIO(pix.tobytes("png")))
    #     draw = ImageDraw.Draw(img)
        
    #     # 2. OCR and PII Detection
    #     ocr_data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    #     full_ocr_text = " ".join(ocr_data['text'])
    #     results = self.analyzer.analyze(text=full_ocr_text, language='en', 
    #                                     entities=["PERSON", "LOCATION", "EMAIL_ADDRESS"])

    #     # 3. Paint over the pixels on the 'img' object
    #     for res in results:
    #         target = full_ocr_text[res.start:res.end]
    #         label = traceback_manager.get_pseudo(target, res.entity_type)
            
    #         for i, word in enumerate(ocr_data['text']):
    #             if word and word in target:
    #                 l, t, w, h = ocr_data['left'][i], ocr_data['top'][i], ocr_data['width'][i], ocr_data['height'][i]
    #                 draw.rectangle([l, t, l+w, t+h], fill="white")
    #                 draw.text((l, t), label, fill="red")

    #     # --- CRITICAL: THE SANITIZATION STEP ---
        
    #     # This removes all selectable text, vector graphics, and existing paths
    #     page.clean_contents() 
        
    #     # This removes any existing links or annotations (like your previous attempts)
    #     for annot in page.annots():
    #         page.delete_annot(annot)

    #     # ---------------------------------------

    #     # 4. Re-insert the flattened, redacted image
    #     img_byte_arr = io.BytesIO()
    #     # Save as JPEG to keep file size low (resolves your 50MB issue)
    #     img.convert("RGB").save(img_byte_arr, format='JPEG', quality=75, optimize=True)
        
    #     page.insert_image(page.rect, stream=img_byte_arr.getvalue())

    # --- THE PIPELINE LOGIC ---
    def run_pipeline(self, input_pdf):
        exec_id = str(uuid.uuid4())
        doc = pymupdf.open(input_pdf)
        tm = TracebackManager()
        validation_summary = []

        # Iterate BACKWARDS
        for pno in reversed(range(len(doc))):
            page = doc[pno]
            
            # Score calculation
            emb_text = page.get_text("text").strip()
            pix = page.get_pixmap(matrix=pymupdf.Matrix(1, 1))
            ocr_text = pytesseract.image_to_string(Image.open(io.BytesIO(pix.tobytes("png")))).strip()
            score = fuzz.ratio(emb_text.lower(), ocr_text.lower())

            if score < 95:
                # After this call, 'page' is deleted from 'doc'
                self.hybrid_redaction(doc, page, tm)
                method = "Hybrid"
            else:
                self.standard_redaction(page, tm)
                method = "Standard"

            validation_summary.append({"page": pno + 1, "score": score, "method": method})

        # Finalize
        output_path = input_pdf.replace(".pdf", "_sanitized.pdf")
        doc.save(output_path, garbage=4, deflate=True, clean=True)
        
        self._log_to_db(exec_id, input_pdf, tm.mapping, validation_summary)

    def _log_to_db(self, eid, fname, mapping, valid_res):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO audit_logs VALUES (?,?,?,?,?,?,?,?)",
                (eid, fname, APP_VERSION, self.git_hash, "completed", 
                 json.dumps(mapping), json.dumps(valid_res), datetime.datetime.now().isoformat()))

class TracebackManager:
    def __init__(self):
        self.mapping = {}
        self.counters = {}

    def get_pseudo(self, val, ent):
        if val not in self.mapping:
            self.counters[ent] = self.counters.get(ent, 0) + 1
            self.mapping[val] = f"[{ent}_{self.counters[ent]}]"
        return self.mapping[val]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    args = parser.parse_args()
    
    suite = PDFRedactionSuite()
    suite.run_pipeline(args.filename)