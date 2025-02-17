import spacy
import re
import os
from Functions.URLcheeker import URL_Cheeker
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# nlp1 = spacy.load("bahraini_phone_number_model")
nlp=spacy.load("en_core_web_lg")

def PIICheck(text_data, filename):
    ENCRYPTED_DIR = "ProcessedFiles/encrypted"
    KEYS_DIR = "ProcessedFiles/keys"
    CLEANED_DIR = "ProcessedFiles/cleanedFile"
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(CLEANED_DIR, exist_ok=True)

    # Define regex patterns
    URL_PATTERN = r"https?://(?:www\.)?[\w.-]+\.[a-zA-Z]{2,}(?:/[\w./?=#%-]*)?"
    PHONE_PATTERN = r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}|\+\d{1,3}\s\d{4}\s\d{4}|\b\d{4}\s\d{4}\b"
    CPR_PATTERN = r"\b\d{9}\b"  # Bahraini CPR numbers are exactly 9 digits
    EMAIL_PATTERN = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    IP_ADDRESS_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    

    doc = nlp(text_data)
    sensitive_data = []

    # Detect and validate URLs
    for match in re.finditer(URL_PATTERN, text_data):
        url = match.group()
        print(f"Checking URL: {url}")
        is_safe = URL_Cheeker(url)
        print(f"URL: {url}, Status: {is_safe}")
        if is_safe == "Malicious":
            text_data = text_data.replace(url, f"{url} (Malicious)")
        elif is_safe == "Suspicious":
            text_data = text_data.replace(url, f"{url} (Suspicious)")
        else:
            text_data = text_data.replace(url, f"{url} (Safe)")

    # Detect sensitive data
    for pattern, label in [
        (PHONE_PATTERN, "PHONE_NUMBER"),
        (EMAIL_PATTERN, "EMAIL"),
        (CPR_PATTERN, "CPR"),
        (IP_ADDRESS_PATTERN, "IP_ADDRESS"),
        (URL_PATTERN, "URL")
    ]:
        for match in re.finditer(pattern, text_data):
            sensitive_data.append((match.group(), label))

    # Detect named entities using spaCy
    for ent in doc.ents:
        if ent.label_ in ["PERSON", "EMAIL", "GPE"]:
            sensitive_data.append((ent.text, ent.label_))

    # Mask sensitive data
    masked_text = text_data
    for data, label in sensitive_data:
        masked_text = masked_text.replace(data, f"[{label}]")
        
    # Generate filenames
    base_name, ext = os.path.splitext(filename)

    # Check if the file is PDF or TXT and set corresponding cleaned/encrypted file paths
    if ext.lower() == ".pdf":
        cleaned_filename = f"{base_name}_cleaned.pdf"
        encrypted_filename = f"{base_name}_encrypted.pdf"
        cleaned_file_path = os.path.join(CLEANED_DIR, cleaned_filename)
        encrypted_file_path = os.path.join(ENCRYPTED_DIR, encrypted_filename)
        
        # Create a PDF for the cleaned file
        pdf = canvas.Canvas(cleaned_file_path, pagesize=letter)
        pdf.setFont("Helvetica", 12)
        
        sentences = masked_text.split(". ")  # Split text at period + space
        y_position = 750  # Start position
        max_width = 500  # Maximum line width
        line_height = 25  # Increased line spacing for readability

        for sentence in sentences:
            words = sentence.split()
            line = ""

            for word in words:
                if pdf.stringWidth(line + word, "Helvetica", 12) < max_width:
                    line += word + " "
                else:
                    pdf.drawString(50, y_position, line.strip())  
                    y_position -= line_height
                    line = word + " "

                    if y_position < 50:  
                        pdf.showPage()
                        pdf.setFont("Helvetica", 12)
                        y_position = 750

            if line:
                pdf.drawString(50, y_position, line.strip())
                y_position -= line_height  # Add extra spacing between lines

        pdf.save()

    elif ext.lower() == ".txt":
        cleaned_filename = f"{base_name}_cleaned.txt"
        encrypted_filename = f"{base_name}_encrypted.txt"
        cleaned_file_path = os.path.join(CLEANED_DIR, cleaned_filename)
        encrypted_file_path = os.path.join(ENCRYPTED_DIR, encrypted_filename)

        # Write the masked text to the cleaned .txt file
        with open(cleaned_file_path, "w") as cleaned_file:
            cleaned_file.write(masked_text)

    return cleaned_file_path, encrypted_file_path
