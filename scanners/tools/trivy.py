import os
import subprocess
import json
import logging
from review_manager.review_manager import add_review_entry  # Correct import


logger = logging.getLogger(__name__)

def run_trivy_scan(command, output_path):
    """Run a Trivy scan command and handle output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        with open(output_path, 'w') as f:
            f.write(result.stdout)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"Trivy scan failed: {e.stderr}")
        return {'error': f"Error running Trivy scan: {e.stderr}"}

def run_trivy_fs_scan(target_path):
    """Run Trivy filesystem scan."""
    output_path = f"/tmp/trivy_fs_scan_{os.path.basename(target_path)}.json"
    command = ['trivy', 'fs', target_path, '--format', 'json']
    return run_trivy_scan(command, output_path)

def run_trivy_image_scan(image_name):
    """Run Trivy image scan."""
    output_path = f"/tmp/trivy_image_scan_{image_name.replace('/', '_')}.json"
    command = ['trivy', 'image', image_name, '--format', 'json']
    return run_trivy_scan(command, output_path)

def run_trivy_repo_scan(git_repo_url):
    """Run Trivy scan on a Git repository."""
    output_path = f"/tmp/trivy_repo_scan_{os.path.basename(git_repo_url)}.json"
    command = ['trivy', 'repo', git_repo_url, '--format', 'json']
    return run_trivy_scan(command, output_path)

def handle_virus_detection(scan_type, path):
    """Log virus detection for manual review."""
    logger.error(f"Potential virus detected in {scan_type} on: {path}. Requires manual review.")
    add_review_entry(scan_type, path)

def sanitize_input(input_value):
    """Sanitize user inputs to prevent command injection and path traversal attacks."""
    if '..' in input_value or '/' in input_value or '\\' in input_value:
        logger.error(f"Invalid input detected: {input_value}")
        raise ValueError("Invalid input detected.")
    return input_value