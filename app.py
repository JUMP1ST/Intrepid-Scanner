import os
import shutil
import logging
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename


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

scan_completed = False  # Track scan status
scan_results = None  # Hold the scan results for status endpoint

@app.route('/', methods=['GET', 'POST'])
def index():
    global scan_completed, scan_results  # Use the global variables to track status and results
    file_scan_results = []
    image_scan_results = []
    git_scan_results = []

    if request.method == 'POST':
        # Get form data
        scan_type = request.form.get('scan_type')
        image_name = request.form.get('image_name')
        git_repo_url = request.form.get('git_repo_url')
        files = request.files.getlist('file')

        if not scan_type:
            logger.error("No scan type provided.")
            return render_template('index.html', error="Error: No scan type provided.")

        try:
            # Process filesystem scan
            if scan_type == 'filesystem':
                for file in files:
                    filename = secure_filename(file.filename)
                    if not filename:
                        logger.error("No filename provided for file upload.")
                        file_scan_results.append("Error: No valid filename provided.")
                        continue

                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    try:
                        file.save(file_path)
                        logger.info(f"File saved to {file_path}")
                    except Exception as e:
                        logger.error(f"Failed to save file: {e}")
                        file_scan_results.append(f"Error saving file {filename}: {e}")
                        continue

                    # Perform the filesystem scan
                    full_scan_result = scan_file_system(file_path)
                    file_scan_results.append(full_scan_result)

            # Process Git repository scan
            elif scan_type == 'git' and git_repo_url:
                clone_path = "/tmp/cloned_repo"

                # Clean up the clone directory if it exists
                if os.path.exists(clone_path):
                    logger.info(f"Cleaning up existing directory: {clone_path}")
                    shutil.rmtree(clone_path)

                try:
                    # Clone the repository
                    logger.info(f"Cloning Git repository: {git_repo_url}")
                    result = subprocess.run(['git', 'clone', git_repo_url, clone_path], capture_output=True, text=True)
                    if result.returncode != 0:
                        logger.error(f"Git clone failed: {result.stderr}")
                        git_scan_results.append({'error': f"Git clone failed: {result.stderr}"})
                    else:
                        logger.info(f"Git repository cloned successfully: {clone_path}")
                        # Pass the cloned path to scan function (ensure that scan_git_repository can handle it)
                        trivy_repo_result = scan_git_repository(clone_path)
                        git_scan_results.append(trivy_repo_result)
                        logger.info(f"Git repository scan completed for: {git_repo_url}")

                except Exception as e:
                    git_scan_results.append({'error': f"Error running Git scan: {e}"})
                    logger.error(f"Git scan failed: {e}")

            # Process image scan
            elif scan_type == 'image' and image_name:
                try:
                    logger.info(f"Running Image scan on: {image_name}")
                    image_scan_result = scan_docker_image(image_name)
                    image_scan_results.append(image_scan_result)
                    logger.info(f"Image scan completed for: {image_name}")
                except Exception as e:
                    image_scan_results.append({'error': f"Error running Image scan: {e}"})
                    logger.error(f"Image scan failed: {e}")

            else:
                logger.error("Invalid scan type or missing parameters.")
                return render_template('index.html', error="Error: Invalid scan type or missing parameters.")

            # Set the scan as completed and store results
            scan_completed = True
            scan_results = {
                "file_scan_results": file_scan_results,
                "image_scan_results": image_scan_results,
                "git_scan_results": git_scan_results
            }

        except Exception as e:
            logger.error(f"Unexpected error occurred during scan: {e}")
            return render_template('index.html', error=f"Unexpected error occurred: {e}")

        # Format and pass scan results to template
        return render_template(
            'index.html',
            file_scan_results=file_scan_results,
            image_scan_results=image_scan_results,
            git_scan_results=git_scan_results,
            scan_completed=True
        )

    # If not POST, render the default template
    return render_template('index.html', scan_completed=scan_completed)


@app.route('/scan-status')
def scan_status():
    """Provide the status and results of the latest scan."""
    if scan_completed:
        return jsonify({
            "scan_completed": scan_completed,
            "scan_results": scan_results
        }), 200
    return jsonify({"scan_completed": False, "scan_results": None}), 200


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
