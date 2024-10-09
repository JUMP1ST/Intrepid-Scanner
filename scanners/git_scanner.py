import os
from shutil import rmtree
from git import Repo
import subprocess
from .tools.trivy import run_trivy_repo_scan
from .tools.clamav import run_clamav_scan

def scan_git_repository(repo_url):
    # Clone a Git repository and run file system scans.
    repo_name = os.path.basename(repo_url).replace('.git', '')
    repo_path = os.path.join('/tmp/uploads', repo_name)
    
    # Step 1: Run remote Trivy scan on the repo URL
    scan_results = [run_trivy_repo_scan(repo_url)]

    # Clone the repository
    if os.path.exists(repo_path):
        rmtree(repo_path)
    Repo.clone_from(repo_url, repo_path)

    # Step 2: Run local Trivy and ClamAV scans on the cloned repo
    scan_results.append(run_trivy_repo_scan(repo_path))
    scan_results.append(run_clamav_scan(repo_path))

    # Clean up
    rmtree(repo_path, ignore_errors=True)

    return scan_results
