# Dashboard DSPM - Tabler via CDN
FROM nginx:alpine

# Instalar Python, dependencias y docker-cli para scan trigger
RUN apk add --no-cache python3 py3-pip docker-cli

# Crear entorno virtual
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copiar frontend (Tabler se carga via CDN)
COPY frontend/ /usr/share/nginx/html/

# Configurar nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Configurar la API
WORKDIR /app
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/ .

# Script de inicio
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80 5000

CMD ["/start.sh"]
