import subprocess
import logging
from review_manager.review_manager import add_review_entry

logger = logging.getLogger(__name__)

def sanitize_input(input_value):
    """Sanitize user inputs to prevent command injection and path traversal attacks."""
    if '..' in input_value or '/' in input_value or '\\' in input_value:
        logger.error(f"Invalid input detected: {input_value}")
        raise ValueError("Invalid input detected.")
    return input_value

def handle_virus_detection(scan_type, path):
    """Log virus detection for manual review."""
    logger.error(f"Potential virus detected in {scan_type} on: {path}. Requires manual review.")
    add_review_entry(scan_type, path)

def run_clamav_scan(path):
    """Run ClamAV scan on a file or directory."""
    try:
        result = subprocess.run(['clamscan', '-r', path], capture_output=True, text=True, check=True)
        return {'path': path, 'scan_type': 'ClamAV', 'details': result.stdout}
    except subprocess.CalledProcessError as e:
        logger.error(f"ClamAV scan failed: {e.stderr}")
        return {'error': f"Error running ClamAV scan: {e.stderr}"}

def run_clamav_docker_image_scan(image_name):
    """Run ClamAV scan on a Docker image by extracting the image contents."""
    try:
        # Save Docker image as a tarball
        image_tar_path = f"/tmp/{image_name.replace('/', '_')}.tar"
        extract_path = f"/tmp/extracted_{image_name.replace('/', '_')}"
        subprocess.run(['docker', 'save', image_name, '-o', image_tar_path], check=True)

        # Extract tarball contents
        subprocess.run(['mkdir', '-p', extract_path], check=True)
        subprocess.run(['tar', '-xf', image_tar_path, '-C', extract_path], check=True)

        # Run ClamAV scan on the extracted contents
        clamav_result = run_clamav_scan(extract_path)

        # Clean up temporary files
        subprocess.run(['rm', '-rf', image_tar_path, extract_path], check=True)

        return clamav_result
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to scan Docker image {image_name} with ClamAV: {e.stderr}")
        return {'error': f"Error running ClamAV scan on Docker image: {e.stderr}"}

