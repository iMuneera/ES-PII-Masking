from flask import Flask, render_template, request, jsonify, send_from_directory,url_for, redirect

import os
from Functions.PII import PIICheck
from PyPDF2 import PdfReader
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from Functions.automate import delete_encrypted_files


load_dotenv()

# Define directories
ENCRYPTED_DIR = "ProcessedFiles/encrypted"
KEYS_DIR = "ProcessedFiles/keys"
CLEANED_DIR = "ProcessedFiles/cleanedFile"

# Ensure directories exist
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(CLEANED_DIR, exist_ok=True)

app = Flask(__name__)

CLERK_PUBLISHABLE_KEY = os.getenv("CLERK_PUBLISHABLE_KEY")
print(f"CLERK_PUBLISHABLE_KEY Loaded: {bool(CLERK_PUBLISHABLE_KEY)}")

@app.route('/')
def home():
    delete_encrypted_files()
    return render_template('Home.html', clerk_publishable_key=CLERK_PUBLISHABLE_KEY)

MAX_FILE_SIZE = 500 * 1024  # 500KB in bytes
def generate_key():
    """Generate and return an AES encryption key."""
    return Fernet.generate_key()

def save_key(key, file_name):
    """Save encryption key."""
    key_path = os.path.join(KEYS_DIR, file_name + ".key")
    with open(key_path, "wb") as kf:
        kf.write(key)

def encrypt_data(data, key):
    """Encrypt data using AES-256."""
    cipher = Fernet(key)
    return cipher.encrypt(data)

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-256."""
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data)



@app.route('/Chatpdf')
def Chatpdf():

    return render_template('Chatpdf.html', clerk_publishable_key=CLERK_PUBLISHABLE_KEY)
    
@app.route('/MaskPDF', methods=['GET','POST'])
def Chat():
    return render_template('MaskPDF.html', clerk_publishable_key=CLERK_PUBLISHABLE_KEY)



@app.route('/process', methods=['POST'])
def submit():
    text_data = ""
    response_text = ""
    file_url = ""  
    isitpdf = False

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']

    if not file.filename:
        return jsonify({"error": "No valid file selected"}), 400

    # Check file size
    file.seek(0, os.SEEK_END)  # Move cursor to end of file
    file_size = file.tell()  # Get file size
    file.seek(0)  # Reset cursor position

    if file_size > MAX_FILE_SIZE:
        return jsonify({"error": "File size exceeds 500KB limit"}), 400

    # Validate file type
    allowed_extensions = {'.pdf', '.txt', '.doc'}
    file_ext = os.path.splitext(file.filename)[1].lower()

    if file_ext not in allowed_extensions:
        return jsonify({"error": "Invalid file type. Only PDF, TXT files are allowed."}), 400

    # Read and extract text data
    if file_ext == '.pdf':
        pdf_reader = PdfReader(file)
        text_data = "".join([page.extract_text() or "" for page in pdf_reader.pages])
    else:
        text_data = file.read().decode('utf-8')

    # Encrypt the file before processing
    key = generate_key()
    encrypted_data = encrypt_data(text_data.encode('utf-8'), key)

    # Save encrypted file
    encrypted_filename = f"{os.path.splitext(file.filename)[0]}_encrypted{file_ext}"
    encrypted_file_path = os.path.join(ENCRYPTED_DIR, encrypted_filename)
    with open(encrypted_file_path, "wb") as ef:
        ef.write(encrypted_data)

    # Save the encryption key
    save_key(key, file.filename)

    # Decrypt the file for processing
    decrypted_data = decrypt_data(encrypted_data, key).decode("utf-8")

    # Process PII Masking and save with the correct extension
    output_filename = f"processed_{os.path.splitext(file.filename)[0]}{file_ext}"
    cleaned_file_path, _ = PIICheck(decrypted_data, output_filename)

    if cleaned_file_path:
        file_url = f"/download/{os.path.basename(cleaned_file_path)}"
        response_text = f"File '{file.filename}' uploaded, encrypted, and processed successfully."
    else:
        response_text = "Processing failed."

    return jsonify({"response": response_text, "file_url": file_url})

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(CLEANED_DIR, filename)

if __name__ == '__main__':
    app.run(debug=True)
