import subprocess

def run_grype_image_scan(image_name):
    # Run Grype scan on the Docker image.
    result = subprocess.run(['grype', image_name], capture_output=True, text=True)
    return result.stdout

