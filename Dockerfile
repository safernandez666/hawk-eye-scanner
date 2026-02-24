# Dockerfile corregido
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencias del sistema
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    curl \
    git \
    netcat-openbsd \
    build-essential \
    libgl1 \
    libglx-mesa0 \
    libglib2.0-0 \
 && rm -rf /var/lib/apt/lists/*

# Instalar dependencias Python
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copiar todo el directorio del scanner
COPY hawk-scanner /app/

# Install OneDrive connector into hawk_scanner package
COPY hawk-eye-contrib /tmp/hawk-eye-contrib
RUN python /tmp/hawk-eye-contrib/install_onedrive.py \
 && rm -rf /tmp/hawk-eye-contrib

# Crear carpetas necesarias
RUN mkdir -p /app/alerts /app/data \
 && chmod -R a+rX /app

# WORKDIR ya es /app (donde están los archivos yml)
CMD ["python", "run_hawk_scanner.py"]