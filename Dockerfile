# -----------------------------
# Stage 1: Builder Stage
# -----------------------------
FROM python:3.11-slim AS builder

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1 \
    GIT_PYTHON_REFRESH=quiet

# Create the application directory
WORKDIR /app

# Install necessary system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    build-essential \
    git \
    libmagic1 \
    libmagic-dev \
    yara \
    clamav clamav-daemon \
    docker.io \
    libssl-dev openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    freshclam

# Install Trivy, Grype, and Syft
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Clone YARA rules repository
RUN mkdir -p /opt/yara && \
    git clone https://github.com/Yara-Rules/rules.git /opt/yara

# Install Python dependencies in a virtual environment
COPY requirements.txt .
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Set permissions for application directories
RUN mkdir -p /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Copy application code
COPY . /app
COPY static /app/static
COPY templates /app/templates

# -----------------------------
# Stage 2: Production Stage
# -----------------------------
FROM python:3.11-slim

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1 \
    YARA_RULES_PATH="/opt/yara" \
    GIT_PYTHON_REFRESH=quiet

# Create necessary directories and set permissions
RUN mkdir -p /app/output /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Install runtime dependencies including git
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libmagic1 \
    clamav clamav-daemon && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    freshclam

# Configure ClamAV
RUN mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 755 /var/run/clamav && \
    echo "LocalSocket /var/run/clamav/clamd.ctl" >> /etc/clamav/clamd.conf

# Copy necessary files from builder stage
COPY --from=builder /app /app
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /opt/yara /opt/yara

# Verify installations
RUN git --version && trivy --version && grype version && syft version

# Set working directory
WORKDIR /app

# Expose the application port
EXPOSE 8000

# Define volumes for persistence
VOLUME ["/app/uploads", "/app/output/scan-results"]

# Add health check for FastAPI and ClamAV
HEALTHCHECK --interval=30s --timeout=10s \
    CMD curl -f http://localhost:8000/ || exit 1

# Start ClamAV daemon and FastAPI app using Uvicorn
CMD ["sh", "-c", "clamd & uvicorn app:app --host 0.0.0.0 --port 8000"]
