# ============================================
# Stage 1: Build Next.js frontend
# ============================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app

# Copiar package files e instalar dependencias
COPY frontend-next/package*.json ./
RUN npm install

# Copiar source y buildear como export estatico
COPY frontend-next/ ./
ENV NEXT_OUTPUT=export
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build
# Output: /app/out/

# ============================================
# Stage 2: nginx + Flask API
# ============================================
FROM nginx:alpine

# Instalar Python, dependencias y docker-cli para scan trigger
RUN apk add --no-cache python3 py3-pip docker-cli

# Crear entorno virtual
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copiar frontend buildeado desde Stage 1
COPY --from=frontend-builder /app/out/ /usr/share/nginx/html/

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
