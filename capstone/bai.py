import cv2
import pytesseract
import pandas as pd
import random
import string
import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RecordManagementSystemAI:
    def __init__(self):
        self.records = []
        self.programs = {
            "children": [
                {"name": "Supplementary Feeding Program", "description": "Provides supplementary food to malnourished children."},
                {"name": "Micronutrient Supplementation", "description": "Provides vitamins and minerals to address micronutrient deficiencies."},
            ],
            "pregnant_women": [
                {"name": "Prenatal Nutrition Program", "description": "Ensures proper nutrition for pregnant women."},
                {"name": "Maternal Micronutrient Supplementation", "description": "Provides essential vitamins and minerals to pregnant women."},
            ]
        }

    def scan_and_extract_data(self, image_path):
        """Scan an image of a hardcopy form and extract data using OCR."""
        try:
            image = cv2.imread(image_path)
            gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            extracted_text = pytesseract.image_to_string(gray_image)
            extracted_data = self.process_extracted_text(extracted_text)
            logging.info(f"Data extracted from image: {extracted_data}")
            return extracted_data
        except Exception as e:
            logging.error(f"Error while scanning image: {e}")
            return []

    def process_extracted_text(self, extracted_text):
        """Convert the raw extracted text into a structured format."""
        rows = extracted_text.strip().split('\n')
        structured_records = []
        for row in rows:
            columns = row.split()
            if len(columns) >= 4:
                try:
                    record = {
                        'id': ''.join(random.choices(string.ascii_uppercase + string.digits, k=6)),
                        'name': columns[0],
                        'age_or_weeks': columns[1],
                        'weight': float(columns[2]),
                        'additional_info': ' '.join(columns[3:])
                    }
                    record['malnutrition_status'], record['recommended_program'], record['food_recommendation'] = self.detect_malnutrition_and_recommend_program(record)
                    structured_records.append(record)
                except ValueError as ve:
                    logging.error(f"Error processing row: {row} - {ve}")
            else:
                logging.warning(f"Skipping incomplete row: {row}")
        return structured_records

    def detect_malnutrition_and_recommend_program(self, record):
        """Detect malnutrition and recommend appropriate programs and foods."""
        age_or_weeks = record['age_or_weeks']
        weight = record['weight']
        
        if "weeks" in age_or_weeks.lower():
            if weight < 50:
                return "Malnourished", random.choice(self.programs['pregnant_women']), None
        else:
            age_in_years = int(age_or_weeks) if age_or_weeks.isdigit() else None
            if age_in_years is not None:
                if (age_in_years <= 5 and weight < 15) or (age_in_years > 5 and weight < 20):
                    recommended_program = random.choice(self.programs['children'])
                    food_recommendation = self.generate_food_recommendation()
                    return "Malnourished", recommended_program, food_recommendation
        
        return "Normal", None, None

    def generate_food_recommendation(self):
        """Return a simple 'go, grow, glow' food recommendation."""
        return "go, grow, glow"

    def add_record(self, record):
        """Add a new record to the system."""
        self.records.append(record)
        logging.info(f"Record {record['id']} added successfully!")
        return f"Record {record['id']} added successfully!"

    def save_records_to_excel(self, file_path='records.xlsx'):
        """Save all records to an Excel file."""
        try:
            df = pd.DataFrame(self.records)
            df.to_excel(file_path, index=False)
            logging.info(f"Records saved to {file_path}")
            return f"Records saved to {file_path}"
        except Exception as e:
            logging.error(f"Error saving records to Excel: {e}")
            return "Error saving records to Excel."

    def update_record(self, record_id, updated_fields):
        """Update specific fields of a record."""
        for record in self.records:
            if record['id'] == record_id:
                record.update(updated_fields)
                logging.info(f"Record {record_id} updated successfully!")
                return f"Record {record_id} updated successfully!"
        logging.warning(f"Record {record_id} not found.")
        return "Record not found."

    def delete_record(self, record_id):
        """Delete a record from the system."""
        initial_len = len(self.records)
        self.records = [record for record in self.records if record['id'] != record_id]
        if len(self.records) < initial_len:
            logging.info(f"Record {record_id} deleted successfully!")
            return f"Record {record_id} deleted successfully!"
        logging.warning(f"Record {record_id} not found.")
        return "Record not found."

    def list_records(self):
        """List all records in the system."""
        logging.info(f"Listing all records: {self.records}")
        return self.records
