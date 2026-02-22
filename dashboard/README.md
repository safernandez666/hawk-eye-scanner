# 🦅 Hawk-Eye DSPM Dashboard

Dashboard web para visualización y gestión de datos sensibles detectados por Hawk-Eye Scanner.

## 🏗️ Arquitectura

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Nginx     │────►│   Flask API │────►│   SQLite    │
│   :80       │     │   :5000     │     │   alerts.db │
└─────────────┘     └─────────────┘     └─────────────┘
       │
       ▼
┌─────────────┐
│  AdminKit   │
│  (CDN)      │
└─────────────┘
```

## 📁 Estructura

```
dashboard/
├── Dockerfile              # Imagen Docker multi-servicio
├── nginx.conf              # Configuración de Nginx (reverse proxy)
├── start.sh                # Script de inicio
├── README.md               # Este archivo
├── frontend/               # HTML/CSS/JS
│   ├── index.html          # Dashboard principal
│   ├── alerts.html         # Lista de alertas
│   ├── patterns.html       # Patrones detectados
│   ├── timeline.html       # Timeline de detecciones
│   └── sources.html        # Fuentes de datos
└── api/                    # Backend Flask
    ├── api.py              # API REST
    └── requirements.txt    # Dependencias Python
```

## 🚀 Endpoints API

| Endpoint | Descripción |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/stats` | Estadísticas generales |
| `GET /api/alerts` | Lista de alertas (con filtros) |
| `GET /api/alerts/<hash>` | Detalle de alerta |
| `GET /api/patterns` | Resumen de patrones |
| `GET /api/timeline` | Timeline de detecciones |

## 🐳 Uso con Docker Compose

El dashboard se integra automáticamente al `docker-compose.yml` principal:

```bash
# Levantar todos los servicios
docker-compose up -d

# Ver logs del dashboard
docker-compose logs -f dashboard

# Acceder al dashboard
open http://localhost:8080
```

## 📊 Páginas

- **Dashboard** (`/`): Vista general con estadísticas y gráficos
- **Alertas** (`/alerts.html`): Gestión de hallazgos con filtros
- **Patrones** (`/patterns.html`): Tipos de datos detectados
- **Timeline** (`/timeline.html`): Histórico de detecciones
- **Fuentes** (`/sources.html`): Estado de conexiones

## 🌙 Dark Mode

El dashboard incluye un toggle de **Dark Mode** en la navbar:

- 🌞 **Icono sol**: Cambia a modo claro  
- 🌙 **Icono luna**: Cambia a modo oscuro

La preferencia se guarda en `localStorage` y persiste entre sesiones.

## 🔧 Tecnologías

- **Frontend**: AdminKit (Bootstrap 5), Chart.js
- **Backend**: Flask, Flask-CORS
- **Web Server**: Nginx (reverse proxy)
- **Container**: Docker + Alpine Linux
- **Features**: 🌙 Dark Mode Toggle (persistente en localStorage)
