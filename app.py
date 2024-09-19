import os
import json
import subprocess
import logging
import magic
import tarfile
import shutil
import zipfile
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurations
UPLOAD_FOLDER = '/app/uploads'
SCAN_RESULTS_FOLDER = '/app/scan-results'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SCAN_RESULTS_FOLDER'] = SCAN_RESULTS_FOLDER

# Initialize file type detector
try:
    mime = magic.Magic(mime=True)
except Exception as e:
    logger.error(f"Failed to initialize magic: {e}")
    mime = None

def detect_file_type(file_path):
    """Detect the type of a file using libmagic."""
    if mime:
        try:
            file_type = mime.from_file(file_path)
            logger.info(f"Detected file type: {file_type}")
            return file_type
        except Exception as e:
            logger.error(f"Failed to detect file type: {e}")
            return "Unknown file type"
    else:
        logger.error("libmagic not initialized.")
        return "libmagic not available"

def extract_files(filepath, dest):
    """Extract .tar, .tgz, .tar.gz, and .zip files."""
    try:
        if tarfile.is_tarfile(filepath):
            with tarfile.open(filepath, 'r:*') as tar:
                tar.extractall(path=dest)
                logger.info(f"Extracted {filepath} to {dest}")
            return True
        elif zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(dest)
                logger.info(f"Extracted {filepath} to {dest}")
            return True
        else:
            logger.warning(f"{filepath} is not a valid archive.")
            return False
    except Exception as e:
        logger.error(f"Failed to extract {filepath}: {e}")
        return False

def zip_directory(src_dir, zip_file_path):
    """Zip the contents of the source directory."""
    logger.info(f"Zipping the directory {src_dir} to {zip_file_path}")
    try:
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(src_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=src_dir)
                    zip_file.write(file_path, arcname)
        logger.info(f"Zipping completed: {zip_file_path}")
    except Exception as e:
        logger.error(f"Failed to zip directory {src_dir}: {e}")

def run_trivy_fs_scan(target_path):
    """Run Trivy filesystem scan."""
    scan_output_path = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'trivy_fs_scan.log')
    logger.info(f"Running Trivy filesystem scan on: {target_path}")
    command = ['trivy', 'fs', target_path, '--format', 'table']

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if result.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(result.stdout)
            logger.info("Trivy filesystem scan completed successfully.")
            return {'path': target_path, 'scan_type': 'Trivy FS', 'severity': 'info', 'details': result.stdout}
        else:
            logger.error(f"Trivy filesystem scan failed: {result.stderr}")
            return {'error': f"Trivy scan failed: {result.stderr}"}
    except Exception as e:
        logger.error(f"Exception during Trivy scan: {e}")
        return {'error': f"Exception during Trivy scan: {e}"}

def run_trivy_image_scan(image_name):
    """Run Trivy image scan."""
    scan_output_path = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'trivy_image_scan.log')
    logger.info(f"Running Trivy image scan on: {image_name}")
    command = ['trivy', 'image', image_name, '--format', 'table']

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if result.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(result.stdout)
            logger.info("Trivy image scan completed successfully.")
            return {'path': image_name, 'scan_type': 'Trivy Image', 'severity': 'info', 'details': result.stdout}
        else:
            logger.error(f"Trivy image scan failed: {result.stderr}")
            return {'error': f"Trivy image scan failed: {result.stderr}"}
    except Exception as e:
        logger.error(f"Exception during Trivy image scan: {e}")
        return {'error': f"Exception during Trivy image scan: {e}"}

def run_trivy_repo_scan(repo_url):
    """Run Trivy repo scan."""
    scan_output_path = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'trivy_repo_scan.log')
    logger.info(f"Running Trivy repo scan on: {repo_url}")
    command = ['trivy', 'repo', repo_url, '--format', 'table']

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if result.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(result.stdout)
            logger.info("Trivy repo scan completed successfully.")
            return {'path': repo_url, 'scan_type': 'Trivy Repo', 'severity': 'info', 'details': result.stdout}
        else:
            logger.error(f"Trivy repo scan failed: {result.stderr}")
            return {'error': f"Trivy repo scan failed: {result.stderr}"}
    except Exception as e:
        logger.error(f"Exception during Trivy repo scan: {e}")
        return {'error': f"Exception during Trivy repo scan: {e}"}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        scan_results = []

        if scan_type == 'filesystem':
            files = request.files.getlist('file')
            for file in files:
                filename = secure_filename(file.filename)
                if not filename:
                    logger.error("No filename provided for file upload.")
                    scan_results.append({"error": "No valid filename provided."})
                    continue

                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(file_path)
                    logger.info(f"File saved to {file_path}")
                except Exception as e:
                    logger.error(f"Failed to save file: {e}")
                    scan_results.append({"error": f"Error saving file {filename}: {e}"})
                    continue

                try:
                    file_type = detect_file_type(file_path)
                except Exception as e:
                    logger.error(f"Error detecting file type: {e}")
                    scan_results.append({"error": f"Error detecting file type: {e}"})
                    continue

                # Extract if it's an archive
                extract_path = os.path.join(app.config['UPLOAD_FOLDER'], 'extracted')
                os.makedirs(extract_path, exist_ok=True)
                if file_type in ['application/gzip', 'application/x-tar', 'application/zip']:
                    if extract_files(file_path, extract_path):
                        full_scan_result = run_trivy_fs_scan(extract_path)
                        scan_results.append(full_scan_result)
                        
                        # Re-zip and mark as good/bad after scanning
                        zip_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_scanned.zip")
                        zip_directory(extract_path, zip_file_path)
                        scan_results.append({"path": zip_file_path, "scan_type": "Zip", "severity": "info", "details": "Files re-zipped after scanning."})
                        
                        shutil.rmtree(extract_path)  # Clean up extracted files
                    else:
                        scan_results.append({"error": f"Failed to extract {filename}"})
                else:
                    full_scan_result = run_trivy_fs_scan(file_path)
                    scan_results.append(full_scan_result)

        elif scan_type == 'image':
            image_name = request.form.get('image_name')
            if image_name:
                full_scan_result = run_trivy_image_scan(image_name)
                scan_results.append(full_scan_result)

        elif scan_type == 'git':
            git_repo_url = request.form.get('git_repo_url')
            if git_repo_url:
                full_scan_result = run_trivy_repo_scan(git_repo_url)
                scan_results.append(full_scan_result)

        # Format scan results consistently
        formatted_results = format_scan_results(scan_results)

        # Ensure scan results are passed to the template
        return render_template('index.html', scan_results=formatted_results)

    return render_template('index.html')

def format_scan_results(results):
    """Formats the scan results into a readable format for the UI."""
    formatted_results = []
    for result in results:
        if isinstance(result, dict):
            formatted_result = {
                'path': result.get('path', 'Unknown path'),
                'scan_type': result.get('scan_type', 'Unknown scan type'),
                'severity': result.get('severity', 'unknown'),
                'details': result.get('details', 'No details available')
            }
            formatted_results.append(formatted_result)
        elif isinstance(result, list):
            formatted_results.extend(format_scan_results(result))
        else:
            formatted_results.append({
                'path': 'Unknown path',
                'scan_type': 'Unknown scan type',
                'severity': 'error',
                'details': str(result)
            })
    return formatted_results

if __name__ == "__main__":
    logger.info("Starting Flask application on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000)
