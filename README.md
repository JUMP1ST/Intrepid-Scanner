# Intrepid Security Scanner

## Overview
Intrepid Security Scanner is a web-based security tool that allows users to scan files, Git repositories, and Docker container images for potential threats. It provides an easy-to-use interface to perform multiple types of scans and view the results in a user-friendly way. Users can also review flagged findings for manual investigation and track the status of scans in real time.

## Features
- **File System Scanning**: Upload files or provide paths to scan for malware or vulnerabilities.
- **Git Repository Scanning**: Provide a Git repository URL to analyze its contents for threats.
- **Container Image Scanning**: Scan Docker container images for vulnerabilities.
- **Real-Time Alerts**: Get notified when scans are complete or findings are detected.
- **Review Findings**: A dedicated review page allows for easy access and management of scan results.
- **Light/Dark Mode**: Toggle between light and dark mode for an improved user experience.

## Prerequisites
- **Docker**: The application uses Docker for easy setup and deployment.
  - [Docker Installation Guide](https://docs.docker.com/get-docker/)
- **Python 3**: For local development and testing (optional if using Docker).
  - [Python Installation Guide](https://www.python.org/downloads/)

## Building and Running the Application

### Building the Docker Image
1. **Clone the Repository**: Start by cloning the repository to your local machine.
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2. **Build the Docker Image**: Use the following command to build the Docker image.
    ```bash
    docker build -t intrepid-scanner .
    ```

### Running the Docker Container
3. **Run the Docker Container**: Execute the command below to start the application.
    ```bash
    docker run -p 5000:5000 intrepid-scanner
    ```

4. **Access the Application**: Once the container is running, open a web browser and navigate to:
    ```
    http://localhost:5000
    ```

## Project Structure

The application's file and folder structure is as follows:

```plaintext
Sec-scanner/
│
├── app.py                          # Main Flask application file
│
├── Dockerfile                      # Docker configuration for building the image
│
├── requirements.txt                # Python dependencies
│
├── templates/                      # HTML templates for Flask
│   ├── index.html                  # Main HTML file with the form and scan results
│   ├── review.html                 # HTML for the review page
│   ├── about.html                  # About page content (if separated)
│   └── how_to.html                 # How-To page content (if separated)
│
├── static/                         # Static files like CSS, JavaScript, images
│   ├── style.css                   # Custom styles for the application
│   ├── script.js                   # Custom JavaScript for client-side logic
│   ├── bootstrap-icons.css         # Bootstrap Icons CSS file
│   ├── bootstrap.bundle.min.js     # Bootstrap JS bundle (minified)
│   ├── bootstrap.min.css           # Bootstrap CSS (minified)
│   ├── fonts/                      # Fonts used in the application
│   │   ├── bootstrap-icons.woff
│   │   └── bootstrap-icons.woff2
│   └── images/                     # Images used in the application (if any)
│       ├── tool-icon.png
│       └── tool-logo.png
│
├── uploads/                        # Directory for uploaded files
│   └── ...                         # Files uploaded by users
│
└── scan-results/                   # Directory for storing scan results
    ├── clamav_scan.log             # Example scan result file for ClamAV
    ├── trivy_fs_scan.json          # Example scan result for Trivy filesystem scan
    ├── trivy_image_scan.json       # Example scan result for Trivy image scan
    └── review.json                 # JSON file storing review data

## Usage Instructions

### 1. Performing a Scan
- **File System Scan**: Upload files from your system to analyze them for potential threats.
- **Git Repository Scan**: Enter a valid Git URL (e.g., `https://github.com/user/repo.git`) to scan the repository's contents.
- **Container Image Scan**: Provide the name of a Docker image to run a security scan for vulnerabilities.

### 2. Reviewing Scan Results
- After a scan is initiated, the application automatically redirects to a review page where the scan results are displayed.
- Users can revisit the review page by clicking the "View Scan Results" button on the main page if the scan has already been completed.

### 3. Real-Time Alerts
- An alert icon is present at the top of the page to notify users when scans are completed or if findings require attention.
- The icon will change color and animate when a new alert is available, ensuring users are aware of any important updates.

## Contributing

To contribute to this project:

1. Fork the repository.
2. Create a new feature branch (`git checkout -b feature/new-feature`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push the branch to your fork (`git push origin feature/new-feature`).
5. Submit a pull request.

