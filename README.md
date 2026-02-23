# Hawk-Eye Scanner

**Sistema automatizado de deteccion y gestion de datos sensibles (PII/PCI) con dashboard DSPM e integracion SOAR**

[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-compose-blue.svg)](https://www.docker.com/)
[![TheHive](https://img.shields.io/badge/TheHive-5.0-orange.svg)](https://thehive-project.org/)
[![Flask](https://img.shields.io/badge/Flask-API-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Blog: [La Batalla Perdida de la Clasificacion de la Informacion](https://blog.santiagoagustinfernandez.com/la-batalla-perdida-de-la-clasificacion-de-la-informacion)

---

## Que es Hawk-Eye Scanner?

Hawk-Eye Scanner detecta, clasifica y gestiona **datos sensibles** en bases de datos MySQL y almacenamiento S3. Combina un motor de escaneo basado en regex con un dashboard web (**Poirot DSPM**) y crea casos automaticamente en **TheHive** para respuesta ante incidentes.

### Pipeline

![Arquitectura Hawk-Eye Scanner](screenshots/arquitectura.png)

**MySQL / S3** &rarr; **Hawk-Eye** (escaneo regex) &rarr; **Clasificacion de severidad** &rarr; **Deduplicacion** (hash SQLite) &rarr; **TheHive** (caso automatico)

### Funcionalidades clave

- Escaneo automatizado de MySQL y S3 con 19 patrones regex integrados
- Clasificacion por severidad (CRITICAL, HIGH, MEDIUM, LOW)
- Deduplicacion inteligente por hash de ubicacion
- Deteccion de re-ocurrencias (datos resueltos que reaparecen)
- Dashboard web con KPIs, graficos, exportacion CSV/JSON
- CRUD de patrones y fuentes de datos desde la UI
- Creacion automatica de casos en TheHive para hallazgos criticos
- Semaforo de conectividad para cada fuente de datos

---

## Tabla de Contenidos

- [Stack Tecnologico](#stack-tecnologico)
- [Instalacion Rapida](#instalacion-rapida)
- [Configuracion de TheHive](#configuracion-de-thehive)
- [Dashboard Poirot](#dashboard-poirot)
- [API Endpoints](#api-endpoints)
- [Desarrollo Local](#desarrollo-local)
- [Patrones Detectados](#patrones-detectados)
- [Configuracion Avanzada](#configuracion-avanzada)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

---

## Stack Tecnologico

| Componente | Tecnologia | Puerto |
|------------|-----------|--------|
| Scanner Engine | Python 3.11 + [hawk_scanner](https://github.com/rohitcoder/hawk-eye) | - |
| Dashboard (Poirot) | Flask + Tabler UI + Nginx | `:8080` |
| Base de datos objetivo | MySQL 8.0 | `:3306` |
| Storage objetivo | LocalStack 2.2 (S3) | `:4566` |
| SOAR Platform | TheHive 5.0 | `:9000` |
| Search Engine | Elasticsearch 7.17 | Interno |
| Database (TheHive) | Cassandra 4.1 | Interno |
| Tracking DB | SQLite | `alerts.db` |

---

## Instalacion Rapida

### Prerrequisitos

- Docker Engine 20.10+
- Docker Compose 2.0+
- Python 3.11+ (para datos de prueba)
- 6 GB RAM minimo
- 10 GB espacio en disco

### Paso a paso

```bash
# 1. Clonar el repositorio
git clone https://github.com/safernandez666/poirot.git
cd poirot

# 2. Levantar todos los servicios (primera vez tarda ~5 minutos)
docker compose up -d

# 3. Verificar que todos los servicios estan healthy
docker compose ps

# 4. Generar datos de prueba en MySQL y S3
pip3 install pymysql boto3
python3 generar_datos.py

# 5. Ejecutar el primer scan
docker exec hawk-scanner python3 run_hawk_scanner.py
```

Despues del scan:
- **Dashboard Poirot**: http://localhost:8080
- **TheHive**: http://localhost:9000

---

## Configuracion de TheHive

El scanner necesita una API key de TheHive con permisos `manageCase` para crear casos automaticamente. **La key default no funciona** — hay que generarla.

### Opcion A: Setup automatizado (recomendado)

Ejecutar despues de que TheHive este healthy (`docker compose ps` muestra `healthy`):

```bash
# 1. Login con credenciales default
SESSION=$(curl -s -D /dev/stderr http://localhost:9000/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin@thehive.local","password":"secret"}' 2>&1 \
  | grep -i 'thehive-session' \
  | sed 's/.*THEHIVE-SESSION=\([^;]*\).*/\1/' | tr -d '\r')

# 2. Crear organizacion "poirot"
curl -s -X POST "http://localhost:9000/api/v1/organisation" \
  -H "Cookie: THEHIVE-SESSION=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name":"poirot","description":"Poirot DSPM Organisation"}'

# 3. Crear usuario con permisos manageCase
curl -s -X POST "http://localhost:9000/api/v1/user" \
  -H "Cookie: THEHIVE-SESSION=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"login":"poirot@thehive.local","name":"Poirot Scanner","profile":"org-admin","organisation":"poirot"}'

# 4. Obtener el ID del usuario poirot
POIROT_ID=$(curl -s "http://localhost:9000/api/v1/user" \
  -H "Cookie: THEHIVE-SESSION=$SESSION" | python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    if u.get('login') == 'poirot@thehive.local':
        print(u['_id'])
        break
")

# 5. Generar API key
API_KEY=$(curl -s -X POST "http://localhost:9000/api/v1/user/${POIROT_ID}/key/renew" \
  -H "Cookie: THEHIVE-SESSION=$SESSION")

echo ""
echo "==================================="
echo "  API Key generada: $API_KEY"
echo "==================================="

# 6. Actualizar en los archivos de configuracion
# macOS:
sed -i '' "s/THEHIVE_API_KEY=.*/THEHIVE_API_KEY=$API_KEY/" docker-compose.yml
sed -i '' "s/api_key or \".*\"/api_key or \"$API_KEY\"/" hawk-scanner/thehive_integration.py

# Linux:
# sed -i "s/THEHIVE_API_KEY=.*/THEHIVE_API_KEY=$API_KEY/" docker-compose.yml
# sed -i "s/api_key or \".*\"/api_key or \"$API_KEY\"/" hawk-scanner/thehive_integration.py

# 7. Rebuild con la nueva key
docker compose build hawk-scanner dashboard
docker compose up -d hawk-scanner dashboard
```

### Opcion B: Manual via UI

1. Abrir http://localhost:9000
2. Login: `admin@thehive.local` / `secret`
3. Ir a **Organisation** > crear "poirot"
4. Crear usuario `poirot@thehive.local` con perfil **org-admin** en la org "poirot"
5. Generar API Key para ese usuario
6. Actualizar la key en `docker-compose.yml` (variable `THEHIVE_API_KEY`) y en `hawk-scanner/thehive_integration.py`
7. `docker compose build hawk-scanner dashboard && docker compose up -d`

### Verificar conexion

```bash
curl -s http://localhost:8080/api/thehive/status
# Esperado: {"status":"connected","code":200}
```

### Sincronizar alertas existentes con TheHive

Si ya corriste scans antes de configurar la API key:

```bash
curl -s -X POST http://localhost:8080/api/thehive/sync
```

O usa el boton **"Sincronizar Alertas"** en la pagina de Casos del dashboard.

---

## Dashboard Poirot

El dashboard web esta disponible en **http://localhost:8080** con 6 secciones:

| Pagina | Ruta | Descripcion |
|--------|------|-------------|
| **Dashboard** | `/` | KPIs, graficos de severidad/fuentes, alertas recientes, boton "Escanear Ahora" |
| **Alertas** | `/alerts.html` | Tabla filtrable con exportacion CSV/JSON |
| **Patrones** | `/patterns.html` | CRUD de patrones regex (crear, editar, eliminar) |
| **Timeline** | `/timeline.html` | Grafico de detecciones por dia (ultimos 30 dias) |
| **Fuentes** | `/sources.html` | CRUD de fuentes, semaforo de conectividad (verde/rojo) |
| **Casos** | `/cases.html` | Lista de casos TheHive, detalle con modal, sincronizacion |

### Funcionalidades principales

- **Escaneo manual**: Boton "Escanear Ahora" ejecuta el scanner desde el dashboard
- **Exportar alertas**: Descarga CSV o JSON respetando filtros activos
- **Editar patrones**: Edicion inline de regex desde la UI
- **Semaforo de fuentes**: Badge verde (conectado) o rojo (error) por fuente
- **Badges en sidebar**: Conteo de alertas criticas y casos abiertos en todas las paginas

---

## API Endpoints

| Endpoint | Metodo | Descripcion |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/stats` | GET | Estadisticas generales (KPIs) |
| `/api/alerts` | GET | Listar alertas (filtros: `severity`, `status`, `source`) |
| `/api/alerts/<hash>` | GET | Detalle de alerta |
| `/api/alerts/export` | GET | Exportar alertas (`format=csv\|json`) |
| `/api/patterns` | GET | Resumen de detecciones por patron |
| `/api/timeline` | GET | Timeline de detecciones |
| `/api/config/patterns` | GET / POST | Listar / agregar patrones |
| `/api/config/patterns/<name>` | PUT / DELETE | Editar / eliminar patron |
| `/api/config/sources` | GET / POST | Listar / agregar fuentes |
| `/api/config/sources/<type>/<name>` | DELETE | Eliminar fuente |
| `/api/config/sources/health` | GET | Health check de cada fuente |
| `/api/thehive/status` | GET | Verificar conexion con TheHive |
| `/api/thehive/cases` | GET | Listar casos de TheHive |
| `/api/thehive/cases/<id>` | GET | Detalle de caso |
| `/api/thehive/sync` | POST | Enviar alertas pendientes a TheHive |
| `/api/scanner/run` | POST | Ejecutar scan manual |
| `/api/scanner/status` | GET | Estado del container scanner |

---

## Desarrollo Local

Para iterar rapido en el dashboard sin rebuild de Docker:

```bash
# 1. Mantener servicios Docker corriendo
docker compose up -d hawk-mysql localstack thehive hawk-scanner

# 2. Instalar dependencias (una vez)
pip3 install flask flask-cors pyyaml requests

# 3. Ejecutar servidor de desarrollo
python3 dashboard/dev.py
```

Dashboard local en **http://localhost:5001** — Flask auto-recarga cambios Python, para HTML solo refrescar el browser.

### Variables de entorno opcionales

```bash
THEHIVE_URL=http://localhost:9000 \
THEHIVE_API_KEY=tu_api_key \
ALERTS_DB_PATH=./hawk-scanner/data/alerts.db \
python3 dashboard/dev.py
```

---

## Patrones Detectados

### Datos Financieros (PCI DSS)

| Patron | Severidad |
|--------|-----------|
| Credit Card - Visa | `CRITICAL` |
| Credit Card - Mastercard | `CRITICAL` |
| Credit Card - American Express | `CRITICAL` |
| Credit Card - Discover | `CRITICAL` |
| IBAN | `MEDIUM` |
| Bitcoin Address | `LOW` |

### Informacion Personal (PII)

| Patron | Severidad |
|--------|-----------|
| Social Security Number (SSN) | `HIGH` |
| Email Address | `MEDIUM` |
| Phone Number - US | `MEDIUM` |
| Phone Number - International | `MEDIUM` |

### Credenciales y Secretos

| Patron | Severidad |
|--------|-----------|
| AWS Access Key | `HIGH` |
| AWS Secret Key | `CRITICAL` |
| Private Key (SSH/PGP) | `CRITICAL` |
| Generic Password | `HIGH` |
| API Key | `HIGH` |
| JWT Token | `HIGH` |
| URL with Credentials | `HIGH` |

### Infraestructura

| Patron | Severidad |
|--------|-----------|
| IP Address - Private | `MEDIUM` |

---

## Configuracion Avanzada

### Agregar fuentes

Editar `hawk-scanner/connection.yml` o usar el dashboard (Fuentes > Nueva Fuente):

```yaml
sources:
  mysql:
    production_db:
      host: prod-mysql.company.com
      port: 3306
      database: customers
      user: scanner_user
      password: secure_password
      limit_start: 0
      limit_end: 10000

  s3:
    production_bucket:
      access_key: AKIAIOSFODNN7EXAMPLE
      secret_key: wJalrXUtnFEMI/K7MDENG
      bucket_name: company-prod-data
      endpoint_url: https://s3.amazonaws.com
```

### Agregar patrones

Editar `hawk-scanner/fingerprint.yml` o usar el dashboard (Patrones > Nuevo Patron):

```yaml
"DNI Argentina": '\b\d{2}\.\d{3}\.\d{3}\b'
"Custom API Key": '\b[Aa][Pp][Ii]_[Kk][Ee][Yy]:[a-zA-Z0-9]{32}\b'
```

---

## Estructura del Proyecto

```
.
├── docker-compose.yml           # Orquestacion de servicios
├── Dockerfile                   # Build del scanner
├── generar_datos.py             # Generador de datos de prueba
├── fingerprint.yml              # Patrones de deteccion (host)
├── requirements.txt             # Dependencias Python del scanner
│
├── hawk-scanner/                # Motor de escaneo
│   ├── run_hawk_scanner.py      # Script principal del scanner
│   ├── alert_manager.py         # Gestion de alertas (SQLite)
│   ├── severity_classifier.py   # Clasificador de severidad
│   ├── thehive_integration.py   # Integracion con TheHive
│   ├── fingerprint.yml          # Patrones de deteccion
│   ├── connection.yml           # Fuentes de datos
│   └── data/
│       └── alerts.db            # Base de datos de alertas
│
├── dashboard/                   # Dashboard web (Poirot)
│   ├── Dockerfile               # Build multi-stage (Node + Nginx + Flask)
│   ├── nginx.conf               # Config Nginx (produccion)
│   ├── dev.py                   # Servidor de desarrollo local
│   ├── start.sh                 # Script de inicio (produccion)
│   ├── api/
│   │   ├── api.py               # API Flask (25+ endpoints)
│   │   └── requirements.txt     # Dependencias Python
│   └── frontend/
│       ├── index.html           # Dashboard principal
│       ├── alerts.html          # Pagina de alertas
│       ├── patterns.html        # Gestion de patrones
│       ├── timeline.html        # Timeline de detecciones
│       ├── sources.html         # Gestion de fuentes
│       └── cases.html           # Casos TheHive
│
├── thehive-config/
│   └── application.conf         # Configuracion de TheHive
│
└── screenshots/
    └── arquitectura.png         # Diagrama de arquitectura
```

---

## Contribuir

1. Fork el proyecto
2. Crear rama: `git checkout -b feature/nueva-funcionalidad`
3. Commit: `git commit -m 'Add: nueva funcionalidad'`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Abrir Pull Request

---

## Disclaimer

Este proyecto es para **fines educativos y de investigacion en seguridad**.

- NO utilizar en sistemas de produccion sin autorizacion explicita
- Los datos de prueba incluidos son completamente ficticios
- Siempre obtener permisos antes de escanear sistemas

---

## Licencia

[MIT License](LICENSE) - Copyright (c) 2025 Santiago Fernandez

---

## Autor

**Santiago Fernandez**

- Web: [santiagoagustinfernandez.com](https://blog.santiagoagustinfernandez.com)
- LinkedIn: [Santiago Fernandez](https://linkedin.com/in/safernandez666)
- GitHub: [@safernandez666](https://github.com/safernandez666)
