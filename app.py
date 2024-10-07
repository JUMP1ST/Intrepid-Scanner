import os
import logging
from flask import Flask, request, render_template, redirect, url_for, jsonify
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

@app.route('/', methods=['GET', 'POST'])
def index():
    global scan_completed  # Use the global scan_completed to track status
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

                try:
                    file_type = detect_file_type(file_path)
                except Exception as e:
                    file_scan_results.append(f"Error detecting file type: {e}")
                    continue

                # Perform the filesystem scan
                full_scan_result = run_trivy_fs_scan(file_path)
                file_scan_results.append(format_scan_result(full_scan_result, 'filesystem'))

        # Process Git repository scan
        elif scan_type == 'git' and git_repo_url:
            try:
                logger.info(f"Running Trivy remote Git scan on: {git_repo_url}")
                trivy_repo_result = run_trivy_repo_scan(git_repo_url)
                git_scan_results.append(format_scan_result(trivy_repo_result, 'git'))
                logger.info(f"Git repository scan completed for: {git_repo_url}")
            except Exception as e:
                git_scan_results.append({'error': f"Error running Trivy Git scan: {e}"})

            # Clone the repo and run further scans
            clone_path = os.path.join(app.config['UPLOAD_FOLDER'], 'cloned_repo')
            if clone_git_repo(git_repo_url, clone_path):
                git_scan_results.extend(run_clamav_scan(clone_path))
                git_scan_results.append(run_yara_scan(clone_path))
                trivy_scan_result = run_trivy_scan(
                    ['trivy', 'fs', clone_path, '--format', 'json'],
                    os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'trivy_fs_scan.json')
                )
                git_scan_results.append(format_scan_result(trivy_scan_result, 'filesystem'))
                shutil.rmtree(clone_path)

        # Process image scan
        elif scan_type == 'image' and image_name:
            scan_tasks = [
                lambda: run_trivy_image_scan(image_name),
                lambda: run_grype_image_scan(image_name),
                lambda: run_clamav_docker_image_scan(image_name)
            ]

            clamav_path = f'/var/lib/docker/images/{image_name}'
            if os.path.exists(clamav_path):
                scan_tasks.append(lambda: run_clamav_scan(clamav_path))

            # Execute scan tasks and collect results
            image_scan_results.extend(perform_scan_tasks(scan_tasks))

        # Format and pass scan results to template
        formatted_file_results = [format_scan_result(result, 'filesystem') for result in file_scan_results]
        formatted_image_results = [format_scan_result(result, 'image') for result in image_scan_results]
        formatted_git_results = [format_scan_result(result, 'git') for result in git_scan_results]

        # Pass all results to the index template
        return render_template(
            'index.html',
            file_scan_results=formatted_file_results,
            image_scan_results=formatted_image_results,
            git_scan_results=formatted_git_results
        )

    # If not POST, render the default template
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
