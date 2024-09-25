# Use a minimal Python base image to reduce size
FROM python:3.11-alpine

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    YARA_RULES_PATH="/opt/yara/malware_index.yar" \
    PYTHONUNBUFFERED=1

# Create app directory
WORKDIR /app

# Install necessary tools and dependencies for offline use
RUN apk add --no-cache \
    gcc \
    libffi-dev \
    musl-dev \
    openssl-dev \
    yara \
    clamav \
    file \
    git \
    bash \
    curl \
    docker-cli

# Install Python dependencies in a virtual environment
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip

# Copy requirements.txt and install Python dependencies
COPY requirements.txt ./
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py ./
COPY templates/ ./templates/
COPY static/ ./static/

# Install YARA rules locally
COPY yara-rules /opt/yara/

# Ensure output and upload directories exist
RUN mkdir -p /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Expose the application port
EXPOSE 5000

# Run the FastAPI application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]

