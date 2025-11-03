# 🦅 Hawk-Eye Scanner

**Sistema automatizado de detección y gestión de datos sensibles (PII/PCI) con integración SOAR**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)
[![TheHive](https://img.shields.io/badge/TheHive-5.0-orange.svg)](https://thehive-project.org/)

> 📖 **Lee el artículo completo:** [La Batalla Perdida de la Clasificación de la Información](https://blog.santiagoagustinfernandez.com/la-batalla-perdida-de-la-clasificacion-de-la-informacion)

---

## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Patrones Detectados](#-patrones-detectados)
- [Sistema de Tracking](#-sistema-de-tracking)
- [Integración con TheHive](#-integración-con-thehive)
- [Configuración Avanzada](#%EF%B8%8F-configuración-avanzada)
- [Roadmap](#-roadmap)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)
- [Autor](#-autor)

---

## 🎯 Descripción

Hawk-Eye Scanner es una plataforma automatizada de seguridad diseñada para detectar, clasificar y gestionar datos sensibles en bases de datos y almacenamiento en la nube. El proyecto nace de la problemática real de la **falta de clasificación de información** en las organizaciones, donde los datos sensibles se encuentran dispersos y sin controles adecuados.

### El Problema

Como se detalla en el [artículo del blog](https://blog.santiagoagustinfernandez.com/la-batalla-perdida-de-la-clasificacion-de-la-informacion), las organizaciones enfrentan desafíos constantes:

- ✗ Datos sensibles sin clasificar ni proteger
- ✗ PII/PCI dispersos en múltiples sistemas
- ✗ Falta de visibilidad sobre qué información existe
- ✗ Respuesta manual y lenta ante incidentes
- ✗ Cumplimiento normativo comprometido

### La Solución

Hawk-Eye Scanner automatiza la detección, clasifica por severidad y orquesta la respuesta a través de TheHive:

- ✓ **Detección automática** de 17+ tipos de datos sensibles
- ✓ **Clasificación inteligente** de severidad (CRITICAL → HIGH → MEDIUM → LOW)
- ✓ **Deduplicación** automática para evitar alertas repetidas
- ✓ **Integración SOAR** con TheHive para gestión de casos
- ✓ **Workflow automatizado** de respuesta a incidentes

---

## ✨ Características

### 🔍 Detección

- **17+ patrones de datos sensibles**: Tarjetas de crédito, SSN, emails, AWS keys, claves privadas, etc.
- **Múltiples fuentes**: MySQL, S3, PostgreSQL (próximamente)
- **Escaneo incremental** con tracking de cambios

### 🎯 Clasificación

- **Sistema de severidad de 4 niveles**:
  - 🔴 **CRITICAL**: Requiere acción inmediata (tarjetas, AWS Secret Keys)
  - 🟠 **HIGH**: Remediar < 24h (SSN, passwords, API keys)
  - 🟡 **MEDIUM**: Revisar < 7 días (emails, teléfonos, IPs)
  - 🟢 **LOW**: Monitorear (direcciones Bitcoin)

### 🔄 Tracking y Deduplicación

- **Base de datos SQLite** con historial completo de hallazgos
- **Hash-based uniqueness**: Evita alertas duplicadas
- **Contadores de detección**: Cuántas veces se detectó cada hallazgo
- **Estados de alertas**: NEW → ACKNOWLEDGED → FALSE_POSITIVE

### 🎯 Integración SOAR

- **Auto-creación de casos** en TheHive para CRITICAL y HIGH
- **Enrichment automático** con observables (IOCs)
- **Tags inteligentes** por fuente, patrón y severidad
- **Descripción detallada** con contexto y acciones recomendadas

---

## 🏗️ Arquitectura
```
┌─────────────────────────────────────────────────────────────────────┐
│                     HAWK-EYE SECURITY PLATFORM                      │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                         CAPA DE DATOS                                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌──────────────┐            │
│  │   MySQL     │    │ LocalStack  │    │ Cassandra    │            │
│  │  Database   │    │     S3      │    │  (TheHive)   │            │
│  │             │    │             │    │              │            │
│  │ • payments  │    │ • HR docs   │    │ • Cases      │            │
│  │ • customers │    │ • Contacts  │    │ • Alerts     │            │
│  └──────┬──────┘    └──────┬──────┘    └──────┬───────┘            │
│         │                  │                   │                     │
└─────────┼──────────────────┼───────────────────┼─────────────────────┘
          │                  │                   │
          ▼                  ▼                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    CAPA DE PROCESAMIENTO                             │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌───────────────────────────────────────────────────────────┐      │
│  │           🦅 HAWK-EYE SCANNER ENGINE                      │      │
│  ├───────────────────────────────────────────────────────────┤      │
│  │                                                            │      │
│  │  1. Scan → 2. Classify → 3. Deduplicate → 4. Route       │      │
│  │                                                            │      │
│  │  ├─► hawk_scanner (regex patterns)                        │      │
│  │  ├─► severity_classifier (CRITICAL/HIGH/MEDIUM/LOW)       │      │
│  │  ├─► alert_manager (SQLite tracking)                      │      │
│  │  └─► thehive_integration (only CRITICAL/HIGH)             │      │
│  │                                                            │      │
│  └────────────────────────┬───────────────────────────────────┘      │
│                           │                                          │
└───────────────────────────┼──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    CAPA DE PRESENTACIÓN                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │              🎯 TheHive SOAR Platform                   │        │
│  │                  (Port 9000)                            │        │
│  ├─────────────────────────────────────────────────────────┤        │
│  │                                                          │        │
│  │  📋 Cases Dashboard                                     │        │
│  │     • Auto-created from CRITICAL/HIGH findings          │        │
│  │     • Enriched with observables (IOCs)                  │        │
│  │     • Tagged and categorized                            │        │
│  │                                                          │        │
│  │  📊 Workflow Management                                 │        │
│  │     • New → In Progress → Resolved                      │        │
│  │     • Assignee tracking                                 │        │
│  │     • Comments and timeline                             │        │
│  │                                                          │        │
│  └──────────────────────────────────────────────────────────┘        │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### Stack Tecnológico

| Componente | Tecnología | Puerto/Path |
|------------|-----------|-------------|
| Scanner Engine | Python 3.11 | Container: hawk-scanner |
| MySQL | MySQL 8.0 | localhost:3306 |
| S3 Mock | LocalStack 2.2 | localhost:4566 |
| SOAR Platform | TheHive 5.0 | http://localhost:9000 |
| Search Engine | Elasticsearch 7.17 | Internal |
| Database (TheHive) | Cassandra 4.1 | Internal |
| Tracking DB | SQLite | /app/data/alerts.db |

---

## 🚀 Instalación

### Prerrequisitos

- Docker Engine 20.10+
- Docker Compose 2.0+
- Python 3.11+ (para generar datos de prueba)
- 6GB RAM mínimo
- 10GB espacio en disco

### Setup Rápido
```bash
# 1. Clonar el repositorio
git clone https://github.com/safernandez666/hawk-eye-scanner.git
cd hawk-eye-scanner

# 2. Levantar todos los servicios
docker-compose up -d

# 3. Esperar a que todos los servicios estén listos (2-3 minutos)
docker-compose logs -f

# 4. Generar datos de prueba (opcional)
pip3 install pymysql boto3 --break-system-packages
python3 generar_datos.py

# 5. Ejecutar primer scan
docker exec -it hawk-scanner python run_hawk_scanner.py

# 6. Acceder a TheHive
open http://localhost:9000
# Usuario: admin@thehive.local
# Password: secret
```

### Configuración de TheHive

Una vez dentro de TheHive:

1. **Cambiar password de admin** (primer login)
2. **Crear API Key:**
   - Click en usuario (arriba derecha)
   - "API Keys" → "Create API Key"
   - Name: `hawk-scanner`
   - Copiar la key generada

3. **Actualizar la API Key en el código:**
```bash
   # Editar hawk-scanner/thehive_integration.py
   nano hawk-scanner/thehive_integration.py
   # Cambiar la línea:
   self.api_key = api_key or "TU_API_KEY_AQUI"
```

4. **Reconstruir el contenedor:**
```bash
   docker-compose build --no-cache hawk-scanner
   docker-compose up -d hawk-scanner
```

---

## 📖 Uso

### Escaneo Manual
```bash
# Ejecutar scan completo
docker exec -it hawk-scanner python run_hawk_scanner.py
```

**Salida esperada:**
```
======================================================================
🦅 HAWK-EYE SCANNER - Automated Security Scan
======================================================================
🔍 Escaneando mysql...
✅ mysql completado: /app/alerts/mysql_20251103_120000.json
🔍 Escaneando s3...
✅ s3 completado: /app/alerts/s3_20251103_120000.json
📊 Resultados consolidados: 15 hallazgos

======================================================================
🔄 Procesando con sistema de tracking...
======================================================================
✅ Base de datos inicializada: data/alerts.db

📊 Resultados del tracking:
   • Total de hallazgos: 15
   • Alertas NUEVAS: 5
   • Ya vistos: 10

   ⚠️  5 alertas CRÍTICAS pendientes

======================================================================
🎯 Enviando alertas críticas a TheHive...
======================================================================
   ✅ Caso creado en TheHive: ~28720
   ✅ Caso creado en TheHive: ~28721
   ✅ Caso creado en TheHive: ~28722
   ✅ Caso creado en TheHive: ~28723
   ✅ Caso creado en TheHive: ~28724

📋 Casos creados en TheHive: 5
🌐 Accede al dashboard: http://localhost:9000
```

### Ver Casos en TheHive

1. Abrir http://localhost:9000
2. Ir a **"Cases"**
3. Verás los casos auto-creados con:
   - Título descriptivo: `[MYSQL] Credit Card - Visa`
   - Severidad correcta
   - Tags: `mysql`, `credit-card-visa`, `hawk-scanner`, `automated`
   - Observables: Los datos enmascarados como IOCs
   - Descripción completa con acciones recomendadas

### Generar Nuevos Datos de Prueba
```bash
# Ejecutar generador
python3 generar_datos.py

# Scan nuevamente
docker exec -it hawk-scanner python run_hawk_scanner.py
```

---

## 🔍 Patrones Detectados

### 💳 Datos Financieros (PCI DSS)

| Patrón | Severidad | Ejemplo |
|--------|-----------|---------|
| Visa | 🔴 CRITICAL | 4532-1234-5678-9010 |
| Mastercard | 🔴 CRITICAL | 5425-2334-3010-9903 |
| American Express | 🔴 CRITICAL | 3782-822463-10005 |
| Discover | 🔴 CRITICAL | 6011-1111-1111-1117 |
| IBAN | 🟠 HIGH | ES91 2100 0418 4502 0005 1332 |
| Bitcoin Address | 🟢 LOW | 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa |

### 👤 Información Personal (PII)

| Patrón | Severidad | Ejemplo |
|--------|-----------|---------|
| SSN (Social Security) | 🟠 HIGH | 123-45-6789 |
| Email | 🟡 MEDIUM | user@example.com |
| Phone (US) | 🟡 MEDIUM | 555-123-4567 |
| Phone (International) | 🟡 MEDIUM | +1-555-123-4567 |

### 🔐 Credenciales y Secretos

| Patrón | Severidad | Ejemplo |
|--------|-----------|---------|
| AWS Access Key | 🟡 MEDIUM | AKIAIOSFODNN7EXAMPLE |
| AWS Secret Key | 🔴 CRITICAL | wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY |
| Private Key (SSH/PGP) | 🟠 HIGH | -----BEGIN RSA PRIVATE KEY----- |
| API Key | 🟠 HIGH | sk_live_abc123def456... |
| JWT Token | 🟠 HIGH | eyJhbGciOiJIUzI1NiIs... |
| Password in Code | 🟠 HIGH | password="P@ssw0rd123" |

### 🌐 Infraestructura

| Patrón | Severidad | Ejemplo |
|--------|-----------|---------|
| IP Privada | 🟡 MEDIUM | 192.168.1.1, 10.0.0.1 |
| URL con credenciales | 🟠 HIGH | http://user:pass@example.com |

---

## 🗄️ Sistema de Tracking

### Base de Datos SQLite

Todas las alertas se guardan en `/app/data/alerts.db` con:
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    alert_hash TEXT UNIQUE,        -- Hash único del hallazgo
    pattern_name TEXT,              -- Tipo de patrón detectado
    data_source TEXT,               -- mysql, s3, etc.
    location TEXT,                  -- db.table.column o bucket/file
    severity TEXT,                  -- CRITICAL, HIGH, MEDIUM, LOW
    status TEXT DEFAULT 'NEW',      -- NEW, ACKNOWLEDGED, FALSE_POSITIVE
    first_seen TIMESTAMP,           -- Primera detección
    last_seen TIMESTAMP,            -- Última detección
    count INTEGER DEFAULT 1,        -- Veces detectado
    notes TEXT                      -- Notas del analista
);
```

### Lógica de Deduplicación
```python
hash = SHA256(data_source + pattern_name + location)

if hash in database:
    count++
    last_seen = now
    is_new = False
else:
    insert new record
    is_new = True
```

### Estados de Alertas

- **NEW**: Primera vez detectado, requiere revisión
- **ACKNOWLEDGED**: Revisado por el equipo, en proceso
- **FALSE_POSITIVE**: Descartado como falso positivo

---

## 🎯 Integración con TheHive

### Workflow Automático
```
Scan → Detect → Classify → Deduplicate → Route → Manage
 │       │         │            │           │         │
 │       │         │            │           │         │
 ▼       ▼         ▼            ▼           ▼         ▼
[15]  [Valid]  [Severity]   [New: 5]  [TheHive]  [Cases]
             [CRITICAL: 4]  [Dup: 10]  [5 cases]  [Resolved]
             [HIGH: 1]
```

### Criterios de Routing

- ✅ **CRITICAL y HIGH** → TheHive (auto-create case)
- ⚪ **MEDIUM y LOW** → Solo SQLite (tracking local)

### Enriquecimiento de Casos

Cada caso en TheHive incluye:

1. **Título descriptivo**: `[MYSQL] Credit Card - Mastercard`
2. **Severidad y TLP** automáticos según el tipo de dato
3. **Tags inteligentes**:
   - Fuente: `mysql`, `s3`
   - Patrón: `credit-card-mastercard`
   - Origen: `hawk-scanner`, `automated`
   - Hash: `hash-abc123def456`
4. **Descripción completa** con:
   - Contexto del hallazgo
   - Ubicación exacta (base/tabla/columna o bucket/archivo)
   - Matches detectados (enmascarados)
   - Acciones recomendadas por severidad
5. **Observables (IOCs)**:
   - Hasta 5 matches como observables
   - Tipo correcto (mail para emails, other para tarjetas, etc.)
   - Tags por patrón

---

## ⚙️ Configuración Avanzada

### Agregar Nuevas Fuentes

Editar `hawk-scanner/connection.yml`:
```yaml
sources:
  mysql:
    production_db:
      host: prod-mysql.company.com
      database: customers
      user: scanner_user
      password: ${MYSQL_PASSWORD}  # Usar variables de entorno
  
  s3:
    production_bucket:
      access_key: ${AWS_ACCESS_KEY}
      secret_key: ${AWS_SECRET_KEY}
      bucket_name: company-prod-data
      region: us-east-1
```

### Agregar Nuevos Patrones

Editar `hawk-scanner/fingerprint.yml`:
```yaml
"Custom API Key": '\b[Aa][Pp][Ii]_[Kk][Ee][Yy]:[a-zA-Z0-9]{32}\b'
"Internal Employee ID": '\bEMP-[0-9]{6}\b'
"Custom Secret": '\bCUST_SECRET_[A-Z0-9]{20}\b'
```

### Ajustar Clasificación de Severidad

Editar `hawk-scanner/severity_classifier.py`:
```python
CRITICAL_PATTERNS = [
    'Credit Card',
    'AWS Secret Key',
    'Private Key',
    'Custom Secret'  # Agregar tu patrón
]
```

### Variables de Entorno
```bash
# Crear .env
cat > .env << EOF
MYSQL_PASSWORD=your_secure_password
AWS_ACCESS_KEY=your_aws_key
AWS_SECRET_KEY=your_aws_secret
THEHIVE_API_KEY=your_thehive_api_key
EOF

# Agregar a docker-compose.yml
services:
  hawk-scanner:
    env_file:
      - .env
```

---

## 🛣️ Roadmap

### Versión Actual (v1.0)

- [x] Detección de 17+ patrones PII/PCI
- [x] Clasificación de severidad en 4 niveles
- [x] Sistema de tracking con SQLite
- [x] Deduplicación basada en hash
- [x] Integración con TheHive
- [x] Soporte para MySQL y S3

### Próximas Versiones

#### v1.1 - Mejoras de Usabilidad
- [ ] CLI interactivo con `rich`
- [ ] Dashboard web con métricas en tiempo real
- [ ] Notificaciones vía Slack/Email/Teams
- [ ] Sistema de whitelisting para falsos positivos

#### v1.2 - Más Fuentes
- [ ] PostgreSQL
- [ ] MongoDB
- [ ] Azure Blob Storage
- [ ] Google Cloud Storage

#### v1.3 - Análisis Avanzado
- [ ] Validación de tarjetas con algoritmo de Luhn
- [ ] Detección de patrones customizados con ML
- [ ] Análisis de contexto (detectar credenciales hardcodeadas)
- [ ] Scoring de riesgo por contexto

#### v1.4 - Integraciones
- [ ] Cortex Analyzer para enrichment automático
- [ ] MISP para IOC sharing
- [ ] Splunk/ELK para logs
- [ ] Jira para ticketing

#### v2.0 - Enterprise Features
- [ ] Multi-tenancy
- [ ] RBAC (Role-Based Access Control)
- [ ] Auditoría completa
- [ ] Reportes ejecutivos (PDF/Excel)
- [ ] Scheduler con cron jobs
- [ ] API REST para integraciones

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Si querés mejorar el proyecto:

### Cómo Contribuir

1. **Fork** el proyecto
2. Crear una rama: `git checkout -b feature/nueva-funcionalidad`
3. Commit: `git commit -m 'Add: nueva funcionalidad'`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Abrir un **Pull Request**

### Guidelines

- Código en español (comentarios y variables)
- Tests unitarios para nuevas funcionalidades
- Actualizar README si agregás features
- Seguir PEP 8 para Python
- Commits descriptivos siguiendo [Conventional Commits](https://www.conventionalcommits.org/)

### Issues

Si encontrás un bug o tenés una sugerencia:

1. Revisar [Issues existentes](https://github.com/safernandez666/hawk-eye-scanner/issues)
2. Crear un nuevo Issue con:
   - Descripción clara del problema/sugerencia
   - Pasos para reproducir (si es un bug)
   - Logs relevantes
   - Entorno (OS, Docker version, etc.)

---

## ⚠️ Disclaimer

Este proyecto es para **fines educativos y de investigación en seguridad**. 

- **NO** utilizar en sistemas de producción sin autorización explícita
- Los datos de prueba incluidos son completamente ficticios
- El autor no se responsabiliza por el uso indebido de esta herramienta
- Siempre obtener permisos antes de escanear sistemas

---

## 📄 Licencia

Este proyecto está licenciado bajo la [MIT License](LICENSE).
```
MIT License

Copyright (c) 2025 Santiago Fernández

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 👤 Autor

**Santiago Fernández**

- 🌐 Website: [santiagoagustinfernandez.com](https://blog.santiagoagustinfernandez.com)
- 📝 Blog: [La Batalla Perdida de la Clasificación de la Información](https://blog.santiagoagustinfernandez.com/la-batalla-perdida-de-la-clasificacion-de-la-informacion)
- 💼 LinkedIn: [Santiago Fernández](https://linkedin.com/in/safernandez666)
- 🐙 GitHub: [@safernandez666](https://github.com/safernandez666)

---

## 🙏 Agradecimientos

- [Hawk-Scanner](https://github.com/hawk-scanner/hawk-scanner) - Motor de escaneo de código abierto
- [TheHive Project](https://thehive-project.org/) - Plataforma SOAR de código abierto
- [LocalStack](https://github.com/localstack/localstack) - Emulación de servicios AWS
- Comunidad de ciberseguridad por el feedback y contribuciones

---

## 📚 Referencias

- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)
- [GDPR - Reglamento General de Protección de Datos](https://gdpr.eu/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

<div align="center">

**⭐ Si te resultó útil, dale una estrella al repo ⭐**

**🦅 Hawk-Eye Scanner - Automatizando la seguridad de datos sensibles**

</div>
EOF

# Crear archivo de licencia
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2025 Santiago Fernández

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
