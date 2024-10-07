import os
import shutil
from scanners.tools.trivy import run_trivy_repo_scan
from scanners.tools.yara import run_yara_scan
from scanners.tools.clamav import run_clamav_scan

def scan_git_repository(git_repo_url):
    """Perform scans on a Git repository using different tools."""
    results = []

    # Clone the repo and set path for scanning
    clone_path = clone_git_repository(git_repo_url)
    if not clone_path:
        return [{'error': 'Failed to clone repository'}]

    # Run the Trivy scan on the cloned repo
    trivy_result = run_trivy_repo_scan(git_repo_url)
    results.append(trivy_result)

    # Run the YARA scan on the cloned repo
    yara_result = run_yara_scan(clone_path)
    results.append(yara_result)

    # Run the ClamAV scan on the cloned repo
    clamav_result = run_clamav_scan(clone_path)
    results.append(clamav_result)

    # Cleanup cloned repo
    shutil.rmtree(clone_path, ignore_errors=True)
    
    return results

def clone_git_repository(git_repo_url):
    """Clone a Git repository to a temporary directory."""
    clone_path = f"/tmp/{os.path.basename(git_repo_url)}"
    try:
        os.system(f"git clone {git_repo_url} {clone_path}")
        return clone_path
    except Exception as e:
        return None
