FROM python:3.12-slim

# Security: run as non-root
RUN groupadd -r cloudops && useradd -r -g cloudops cloudops

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Ensure DB directory is writable
RUN mkdir -p /data && chown cloudops:cloudops /data

USER cloudops

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
