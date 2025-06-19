FROM python:3.12-slim

# Environment setup
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Create venv FIRST, then use it
RUN python -m venv /opt/.venv

# Update PATH at Docker-level
ENV PATH="/opt/.venv/bin:$PATH"

# Upgrade pip and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Uncomment for Bootdev CLI install
# COPY bootdev-install.sh ./
# RUN chmod +x bootdev-install.sh && ./bootdev-install.sh && rm bootdev-install.sh

# Default command
CMD [ "bash" ]
