from .tools.trivy import run_trivy_image_scan
from .tools.grype import run_grype_image_scan

def scan_docker_image(image_name):
    # Perform Docker image scans using Trivy and Grype.
    scan_results = []
    scan_results.append(run_trivy_image_scan(image_name))
    scan_results.append(run_grype_image_scan(image_name))
    return scan_results
