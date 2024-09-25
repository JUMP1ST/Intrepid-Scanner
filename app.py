import os
import json
import subprocess
import logging
import magic  
import tarfile
import shutil
import tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from werkzeug.utils import secure_filename  # Added secure_filename import

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI()

# Serve templates using Jinja2
templates = Jinja2Templates(directory="templates")

# Configurable folders via environment variables with fallbacks to default temporary directories
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', tempfile.mkdtemp())
SCAN_RESULTS_FOLDER = os.getenv('SCAN_RESULTS_FOLDER', tempfile.mkdtemp())
YARA_RULES_PATH = os.getenv('YARA_RULES_PATH', '/opt/yara/malware_index.yar')

# Ensure necessary directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)

# Path for storing review data
REVIEW_FILE_PATH = os.path.join(SCAN_RESULTS_FOLDER, 'review.json')

# Ensure the review file exists
if not os.path.exists(REVIEW_FILE_PATH):
    with open(REVIEW_FILE_PATH, 'w') as file:
        json.dump([], file)  # Initialize as an empty list

# Initialize file type detector
try:
    mime = magic.Magic(mime=True)  # This assumes libmagic is properly installed
except Exception as e:
    logger.error(f"Failed to initialize magic: {e}")
    mime = None

# Utility functions
def sanitize_input(input_value):
    """Sanitize user inputs to prevent command injection and path traversal attacks."""
    if '..' in input_value or '/' in input_value or '\\' in input_value:
        logger.error(f"Invalid input detected: {input_value}")
        raise HTTPException(status_code=400, detail="Invalid input detected.")
    return input_value

def extract_files(filepath, dest):
    """Extract .tar, .tgz, .tar.gz files."""
    try:
        if tarfile.is_tarfile(filepath):
            with tarfile.open(filepath, 'r:*') as tar:
                tar.extractall(path=dest)
                logger.info(f"Extracted {filepath} to {dest}")
        else:
            logger.warning(f"{filepath} is not a valid tar archive.")
    except Exception as e:
        logger.error(f"Failed to extract {filepath}: {e}")

def handle_virus_detection(scan_type, path):
    """Log virus detection for manual review."""
    logger.error(f"Potential virus detected in {scan_type} on: {path}. Requires manual review.")
    review_entry = {
        'scan_type': scan_type,
        'path': path,
        'status': 'Pending Review'
    }

    # Append the review entry to the JSON file
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)  # Load existing data
            data.append(review_entry)  # Append new entry
            file.seek(0)  # Move to the beginning of the file
            json.dump(data, file, indent=4)  # Write updated data
        logger.info(f"Review entry added for {path}.")
    except Exception as e:
        logger.error(f"Failed to update review log: {e}")

def get_review_data():
    """Retrieve the list of scan results marked for review."""
    try:
        with open(REVIEW_FILE_PATH, 'r') as file:
            return json.load(file)
    except Exception as e:
        logger.error(f"Failed to load review data: {e}")
        return []

# Review-related routes
@app.get("/review")
def review(request: Request):
    """Display flagged scan results for manual review."""
    review_data = get_review_data()
    return templates.TemplateResponse('review.html', {"request": request, "review_data": review_data})

@app.post("/mark_reviewed/{index}")
def mark_reviewed(index: int):
    """Mark a review item as reviewed."""
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)
            data[index]['status'] = 'Reviewed'
            file.seek(0)
            json.dump(data, file, indent=4)
        return JSONResponse({'message': 'Marked as reviewed'}, status_code=200)
    except Exception as e:
        logger.error(f"Failed to mark as reviewed: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)

@app.post("/delete_review/{index}")
def delete_review(index: int):
    """Delete a review item."""
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)
            data.pop(index)
            file.seek(0)
            file.truncate()  # Remove remaining old data
            json.dump(data, file, indent=4)
        return JSONResponse({'message': 'Entry deleted'}, status_code=200)
    except Exception as e:
        logger.error(f"Failed to delete review: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)

# Scan functions (YARA, Trivy, ClamAV, etc.)
def run_yara_scan(target_dir):
    """Run YARA scan on the target directory."""
    try:
        result = subprocess.run(['yara', '-r', YARA_RULES_PATH, target_dir], capture_output=True, text=True, check=True)
        logger.info(f"YARA Scan Results: {result.stdout}")
        if "matches" in result.stdout:
            handle_virus_detection('YARA', target_dir)
        return {'path': target_dir, 'scan_type': 'YARA', 'severity': 'info', 'details': result.stdout}
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running YARA: {e.stderr}")
        return {'path': target_dir, 'scan_type': 'YARA', 'severity': 'error', 'details': f"Error running YARA: {e.stderr}"}

# Handle file upload and scanning
@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    try:
        # Save the uploaded file
        file_location = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)

        # Perform file type detection
        file_type = detect_file_type(file_location)

        # Run scans (YARA, ClamAV, etc.)
        scan_results = [run_yara_scan(file_location)]
        scan_results.append(run_clamav_scan(file_location))

        # Additional scans (e.g., Trivy, Grype) can be added here
        return {"filename": file.filename, "scan_results": scan_results}
    except Exception as e:
        logger.error(f"Failed to process file: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process file: {e}")

# File download and list routes
@app.get("/download/{filename}")
def download_file(filename: str):
    """Serve files for download from the output folder."""
    sanitized_filename = sanitize_input(filename)
    file_path = Path(UPLOAD_FOLDER) / sanitized_filename
    if file_path.exists():
        return file_path.read_bytes()
    else:
        raise HTTPException(status_code=404, detail="File not found.")

@app.get("/download/")
def list_files():
    """List available files for download."""
    files = os.listdir(UPLOAD_FOLDER)
    return {"files": files}

# Entry point for running the application
if __name__ == "__main__":
    import uvicorn
    logger.info("Starting FastAPI application on http://0.0.0.0:5000")
    uvicorn.run(app, host="0.0.0.0", port=5000)

