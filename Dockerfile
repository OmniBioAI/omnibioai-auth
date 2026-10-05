# OmniBioAI — Authentication
# Purpose: Build the authentication API container.
# Author: Manish Kumar <manish@omnibioai.org>

# Base image
FROM python:3.11.16-slim-trixie@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e

# Prevent .pyc files + unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

# Expose FastAPI port
EXPOSE 8001

# Run app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
