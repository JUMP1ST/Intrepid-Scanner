import os
from scanners.tools.trivy import run_trivy_image_scan
from scanners.tools.grype import run_grype_image_scan
from scanners.tools.clamav import run_clamav_docker_image_scan

def scan_docker_image(image_name):
    """Perform scans on a Docker image using different tools."""
    results = []

    # Run the Trivy scan
    trivy_result = run_trivy_image_scan(image_name)
    results.append(trivy_result)

    # Run the Grype scan
    grype_result = run_grype_image_scan(image_name)
    results.append(grype_result)

    # Run the ClamAV scan
    clamav_result = run_clamav_docker_image_scan(image_name)
    results.append(clamav_result)
    
    return results
