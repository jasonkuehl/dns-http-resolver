FROM python:3.12-slim

ARG APP_VERSION

# Set labels for container metadata
LABEL maintainer="jason@jasonkuehl.com"
LABEL description="DNS Resolver - Multi-server DNS lookup with web UI and API"
LABEL version="${APP_VERSION}"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install minimal system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN useradd --create-home --shell /bin/bash --uid 1000 appuser

# Copy and install requirements first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY VERSION .
COPY templates ./templates
COPY static ./static
COPY .env.sample .env

# Set proper ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:60200/health || exit 1

EXPOSE 60200

# Use exec form for proper signal handling
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:60200", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "app:app"]


