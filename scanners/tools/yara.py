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

YARA_RULES_PATH = '/opt/yara/malware_index.yar'

def run_yara_scan(target_dir):
    """Run YARA scan on the target directory."""
    try:
        result = subprocess.run(['yara', '-r', YARA_RULES_PATH, target_dir], capture_output=True, text=True, check=True)
        return {'path': target_dir, 'scan_type': 'YARA', 'details': result.stdout}
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running YARA: {e.stderr}")
        return {'error': f"Error running YARA: {e.stderr}"}
