![image](https://github.com/user-attachments/assets/8d2da204-e568-4bc0-90f8-7776582152be)








Overview
The Security-Scanner is a versatile application that scans files, Docker images, and Git repositories for potential vulnerabilities, malware, and viruses. It leverages several industry-standard tools, including:

Trivy: Vulnerability scanner for container images and filesystems.
YARA: Malware detection based on predefined rules.
Grype: Vulnerability scanner for Docker images.
ClamAV: Antivirus engine for scanning files and directories.
The application is built with Flask as the web interface and designed to run in a containerized environment using Docker.

Features
File Upload Scan: Scan uploaded files for vulnerabilities and malware.
Docker Image Scan: Scan Docker images for vulnerabilities using multiple scanners.
Git Repository Scan: Clone and scan Git repositories for vulnerabilities and malware.
Review Mechanism: Flag potentially harmful files for manual review.
Parallel Scanning: Executes scans in parallel for efficiency.
Prerequisites
Docker installed on the system.
Python 3.6+ (for running without Docker).
Docker and Docker Compose (Best).

Installation
Clone the Repository
Clone the repository to your local machine:

git clone git@github.com:JUMP1ST/Sec-Scanner-ubuntu.git
cd <your-repository-folder>

Build Docker Image
To build the Docker image for the Security-Scanner application, use the following command:

bash
Copy code
docker build -t security-scanner .
Run the Docker Container
Run the container and expose it on port 5000:

docker run -d -p 5000:5000 security-scanner
This will start the Flask application, and you can access it in your browser at http://localhost:5000.

Environment Variables
You can customize the application's behavior by passing environment variables during deployment. The following environment variables can be used:

UPLOAD_FOLDER: Directory to store uploaded files. Default is a temporary directory.
Example: /app/uploads
SCAN_RESULTS_FOLDER: Directory to store scan results. Default is a temporary directory.
Example: /app/output/scan-results
YARA_RULES_PATH: Path to the YARA rules file. Default is /opt/yara/malware_index.yar.
Example: /opt/yara/custom_rules.yar
You can pass these variables to Docker using the -e flag:

docker run -d -p 5000:5000 -e UPLOAD_FOLDER=/app/uploads -e SCAN_RESULTS_FOLDER=/app/output/scan-results security-scanner 

Example Usage
File Upload: Upload a file through the web interface to trigger a filesystem scan using Trivy, YARA, and ClamAV.
Docker Image Scan: Enter a Docker image name in the web interface to scan it with Trivy, Grype, and ClamAV.
Git Repository Scan: Provide a Git repository URL to clone and scan it using Trivy and YARA.
Custom Configuration
Configurable Environment Variables
UPLOAD_FOLDER: Defines the folder where uploaded files will be saved.

Default: A temporary directory
Example: /path/to/uploads
SCAN_RESULTS_FOLDER: Defines the folder where scan results will be saved.

Default: A temporary directory
Example: /path/to/scan-results
YARA_RULES_PATH: Points to the YARA rules file used to scan for malware patterns.

Default: /opt/yara/malware_index.yar
Example: /path/to/yara_rules.yar
MAX_CONTENT_LENGTH: Sets the maximum allowed payload size for file uploads.

Default: 5GB
Example: MAX_CONTENT_LENGTH=3GB
SECRET_KEY: This is Flask’s secret key used for sessions.

Default: supersecretkey
API Endpoints
The application has the following API endpoints:

File Upload Endpoint (/):

Method: POST
Description: Uploads a file or triggers Docker/Git repository scan.
Parameters:
scan_type: Type of scan to perform (e.g., filesystem, image, git).
file[]: Files for upload (for filesystem scan).
image_name: Docker image name (for image scan).
git_url: Git repository URL (for git scan).
Review Endpoint (/review):

Method: GET
Description: Displays flagged scan results for manual review.
Mark Reviewed Endpoint (/mark_reviewed/<index>):

Method: POST
Description: Marks a review item as reviewed.
Delete Review Endpoint (/delete_review/<index>):

Method: POST
Description: Deletes a review item from the review log.
Download Files Endpoint (/download/<filename>):

Method: GET
Description: Downloads a file from the upload directory.
Functions and Scan Types
File Scan (scan_type=filesystem):

Upload files to be scanned for vulnerabilities and malware.
The application runs Trivy, YARA, and ClamAV scans on the uploaded files.
Docker Image Scan (scan_type=image):

Provide the name of a Docker image (e.g., ubuntu:latest) to scan it for vulnerabilities.
The application runs Trivy, Grype, and ClamAV scans on the image.
Git Repository Scan (scan_type=git):

Provide a Git repository URL to clone the repository and scan its contents.
The application runs Trivy, YARA, and ClamAV scans on the cloned repository.
Logging
The application provides detailed logging to help troubleshoot or audit the scans. Logs are displayed in the console output and include information about:

Successful and failed scans.
Detection of vulnerabilities or malware.
Review entries that require manual intervention.

Future Improvements
Integration with Security APIs: Extend functionality by integrating with third-party security APIs.
Automated Remediation: Automatically remediate vulnerabilities in scanned files, images, or repositories.
Performance Enhancements: Optimize the scanning process to handle larger datasets.
Dashboard Reporting: Provide visual reporting of scan results and trends over time.

Conclusion
The Security-Scanner provides a flexible and comprehensive way to scan files, Docker images, and Git repositories for vulnerabilities and malware. The integration of multiple scanning tools makes it a powerful solution for security teams to quickly identify and address threats. Contributions and feedback are always welcome!



