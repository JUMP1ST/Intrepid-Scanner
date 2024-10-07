import os
import logging
from flask import Flask, request, render_template, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import shutil

# Import scanning and review functions
from scanners.file_scanner import scan_file_system
from scanners.image_scanner import scan_docker_image
from scanners.git_scanner import scan_git_repository
from review_manager.review_manager import get_review_data, mark_review_item_reviewed, delete_review_item

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', '/tmp/uploads')
app.config['SCAN_RESULTS_FOLDER'] = os.getenv('SCAN_RESULTS_FOLDER', '/tmp/scan-results')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024  # 5GB max file size
app.secret_key = 'supersecretkey'  # Set a secure key for sessions
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SCAN_RESULTS_FOLDER'], exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    file_scan_results = []
    image_scan_results = []
    git_scan_results = []

    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        image_name = request.form.get('image_name')
        git_repo_url = request.form.get('git_url')
        files = request.files.getlist('file')

        # Process filesystem scan
        if scan_type == 'filesystem':
            for file in files:
                try:
                    file_path = save_file_to_upload_folder(file)
                    logger.info(f"File saved to {file_path}")

                    # Perform the filesystem scan
                    full_scan_result = scan_file_system(file_path)
                    file_scan_results.append(format_scan_result(full_scan_result, 'filesystem'))

                except Exception as e:
                    logger.error(f"Failed to process file: {e}")
                    file_scan_results.append(f"Error processing file {file.filename}: {e}")

        # Process Git repository scan
        elif scan_type == 'git' and git_repo_url:
            try:
                git_scan_results.append(scan_git_repository(git_repo_url))
            except Exception as e:
                git_scan_results.append({'error': f"Error running Git scan: {e}"})

        # Process image scan
        elif scan_type == 'image' and image_name:
            try:
                image_scan_results.append(scan_docker_image(image_name))
            except Exception as e:
                image_scan_results.append({'error': f"Error scanning Docker image: {e}"})

        # Pass scan results to the template
        return render_template(
            'index.html',
            file_scan_results=file_scan_results,
            image_scan_results=image_scan_results,
            git_scan_results=git_scan_results
        )

    # Render default template for GET request
    return render_template('index.html')


def save_file_to_upload_folder(file):
    """Save an uploaded file to the upload directory."""
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    logger.info(f"File saved to {file_path}")
    return file_path


@app.route('/review')
def review():
    """Display flagged scan results for manual review."""
    review_data = get_review_data()
    return render_template('review.html', review_data=review_data)

@app.route('/mark_reviewed/<int:index>', methods=['POST'])
def mark_reviewed(index):
    """Mark a review item as reviewed."""
    success, message = mark_review_item_reviewed(index)
    if success:
        return jsonify({'message': 'Marked as reviewed'}), 200
    else:
        return jsonify({'error': message}), 500

@app.route('/delete_review/<int:index>', methods=['POST'])
def delete_review(index):
    """Delete a review item."""
    success, message = delete_review_item(index)
    if success:
        return jsonify({'message': 'Entry deleted'}), 200
    else:
        return jsonify({'error': message}), 500

if __name__ == "__main__":
    logger.info("Starting Flask application on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000)
