FROM python:3.12-slim

WORKDIR /app

# Install git for repo cloning
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY server.py config.py advanced_auditor.py \
    repo_scanner.py source_analyzer.py scanner_scheduler.py \
    report_generator.py \
     ./

# Create directories for scanner workspace and results
RUN mkdir -p scanner_workspace scan_results data

# Default environment
ENV AUDIT_ENV=production \
    AUDIT_DEBUG=false \
    AUDIT_HOST=0.0.0.0 \
    AUDIT_PORT=8080 \
    SCANNER_WORKSPACE=/app/scanner_workspace \
    SCANNER_DB=/app/data/scan_history.db \
    SCANNER_RESULTS=/app/scan_results \
    LOG_LEVEL=INFO

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python", "server.py"]
