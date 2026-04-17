# 4 Messenger Bot Runtime - Docker Image
# ----------------------------------------
# This image provides a secure, isolated environment for running user bots.

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install required Python packages
RUN pip install requests

# Create non-root user for security
RUN groupadd -r botuser && useradd -r -g botuser botuser

# Create app directory
WORKDIR /app

# Copy the runner script
COPY docker_runner.py /app/runner.py

# Set ownership
RUN chown -R botuser:botuser /app

# Switch to non-root user
USER botuser

# Entry point - reads script from stdin
ENTRYPOINT ["python", "/app/runner.py"]
