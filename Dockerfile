# =============================================
# Temp Mail + OpenAI Auto-Register Proxy
# =============================================

FROM python:3.11-slim

LABEL maintainer="gaojilingjuli"
LABEL description="Temp Mail Admin Panel + OpenAI Auto-Register Proxy"

# Install system dependencies (curl for healthcheck, ca-certificates for HTTPS)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (for caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY proxy_server.py .
COPY index.html .
COPY back_gao.py .

# Create output directories
RUN mkdir -p /app/tokens /app/logs

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=5000
ENV HOST=0.0.0.0

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/status || exit 1

# Run the server
CMD ["python", "-u", "proxy_server.py", "--host", "0.0.0.0", "--port", "5000"]
