import subprocess

def run_trivy_fs_scan(file_path):
    # Run Trivy scan on the filesystem.
    result = subprocess.run(['trivy', 'fs', file_path], capture_output=True, text=True)
    return result.stdout

def run_trivy_repo_scan(repo_url):
    # Run Trivy scan on the Git repository.
    result = subprocess.run(['trivy', 'repo', repo_url], capture_output=True, text=True)
    return result.stdout

def run_trivy_image_scan(image_name):
    # Run Trivy scan on the Docker image.
    result = subprocess.run(['trivy', 'image', image_name], capture_output=True, text=True)
    return result.stdout
