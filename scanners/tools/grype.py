import subprocess
import json
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

def run_grype_image_scan(image_name):
    """Run Grype scan on a Docker image."""
    try:
        output_path = f"/tmp/grype_image_scan_{image_name.replace('/', '_')}.json"
        result = subprocess.run(
            ['grype', f'docker:{image_name}', '--output', 'json'],
            capture_output=True, text=True, check=True
        )
        # Save scan results
        with open(output_path, 'w') as f:
            f.write(result.stdout)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"Grype image scan failed: {e.stderr}")
        return {'error': f"Error running Grype image scan: {e.stderr}"}

