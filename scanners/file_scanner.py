import os
import shutil
from scanners.tools.trivy import run_trivy_fs_scan
from scanners.tools.yara import run_yara_scan
from scanners.tools.clamav import run_clamav_scan

def scan_file_system(file_path):
    """Perform scans on a file system path using different tools."""
    results = []

    # Ensure the path exists
    if not os.path.exists(file_path):
        return [{"error": "File Path does not exisit." }]

    # Run the Trivy scan
    trivy_result = run_trivy_fs_scan(file_path)
    results.append(trivy_result)

    # Run the YARA scan
    yara_result = run_yara_scan(file_path)
    results.append(yara_result)

    # Run the ClamAV scan
    clamav_result = run_clamav_scan(file_path)
    results.append(clamav_result)

    # Clean up the file path if necessary
    shutil.rmtree(file_path, ignore_errors=True)
    
    return results
