# 🦅 Hawk-Eye Scanner

Sistema automatizado de detección de datos sensibles (PII/PCI) en bases de datos y almacenamiento en la nube.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)

## 📋 Características

- ✅ **17+ patrones de detección**: Tarjetas de crédito, SSN, emails, AWS keys, claves privadas
- 🎯 **Clasificación inteligente de severidad**: CRITICAL → HIGH → MEDIUM → LOW
- 🐳 **Totalmente dockerizado**: MySQL + LocalStack S3 + Scanner
- 📊 **Reportes detallados**: JSON + visualización en consola
- 🔄 **Deduplicación automática**: Tracking de hallazgos ya vistos

## 🏗️ Arquitectura
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   MySQL     │────▶│ Hawk-Eye    │◀────│  S3/LocalS  │
│   Database  │     │  Scanner    │     │    Stack    │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   Reports    │
                    │ JSON + Stats │
                    └──────────────┘
```

## 🚀 Instalación

### Prerrequisitos

- Docker & Docker Compose
- Python 3.11+
- 4GB RAM mínimo

### Setup rápido
```bash
# 1. Clonar repositorio
git clone https://github.com/safernandez666/hawk-eye-scanner.git
cd hawk-eye-scanner

# 2. Levantar servicios
docker-compose up -d

# 3. Generar datos de prueba (opcional)
python3 generar_datos.py

# 4. Ejecutar scan
docker exec -it hawk-scanner python run_hawk_scanner.py
```

## 📊 Ejemplo de salida
```
🦅 HAWK-EYE SCANNER - Automated Security Scan
==============================================================
🔍 Escaneando mysql... ✅
🔍 Escaneando s3... ✅
📊 Resultados consolidados: 19 hallazgos

🔴 CRITICAL - 4 hallazgos
  [1] Credit Card - Visa
      Fuente: mysql
      Tabla: payments
      Matches: 4532********0366

🟠 HIGH - 2 hallazgos
  [1] Social Security Number (SSN)
      Fuente: s3
      Archivo: hr/empleados_confidencial.pdf

📈 RESUMEN ESTADÍSTICO
   CRITICAL: 4
   HIGH: 2
   MEDIUM: 13
```

## 🔍 Patrones detectados

### 💳 Datos Financieros (PCI DSS)
- Tarjetas: Visa, Mastercard, Amex, Discover
- IBAN, Bitcoin addresses

### 👤 Información Personal (PII)
- SSN (Social Security Numbers)
- Emails, teléfonos (US/Internacional)

### 🔐 Credenciales y Secretos
- AWS Access/Secret Keys
- Claves privadas SSH/PGP
- API Keys, JWT Tokens, Passwords

### 🌐 Infraestructura
- IPs privadas (RFC 1918)
- URLs con credenciales embebidas

## ⚙️ Configuración

### connection.yml
Define las fuentes de datos a escanear:
```yaml
sources:
  mysql:
    poc_mysql:
      host: hawk-mysql
      database: pocdb
      user: root
      password: rootpassword
  
  s3:
    poc_s3:
      access_key: test
      secret_key: test
      bucket_name: poc-bucket
      endpoint_url: http://localstack:4566
```

### fingerprint.yml
Define los patrones de detección (regex):
```yaml
"Credit Card - Visa": '\b4[0-9]{12}(?:[0-9]{3})?\b'
"Social Security Number (SSN)": '\b\d{3}-\d{2}-\d{4}\b'
"AWS Access Key": '\b(AKIA|A3T|...)[A-Z0-9]{16}\b'
```

## 📁 Estructura del proyecto
```
hawk-eye-scanner/
├── docker-compose.yml          # Orquestación de servicios
├── Dockerfile                  # Imagen del scanner
├── hawk-scanner/
│   ├── run_hawk_scanner.py     # Script principal
│   ├── severity_classifier.py  # Clasificador de severidad
│   ├── connection.yml          # Config de fuentes
│   └── fingerprint.yml         # Patrones de detección
├── generar_datos.py            # Generador de datos de prueba
└── alerts/                     # Resultados de escaneos
```

## 🛡️ Severidad y priorización

| Severidad | Tipo de datos | Acción |
|-----------|--------------|--------|
| 🔴 **CRITICAL** | Tarjetas, AWS Secret Keys | Acción inmediata |
| 🟠 **HIGH** | SSN, Passwords, API Keys | Remediar < 24h |
| 🟡 **MEDIUM** | Emails, Teléfonos, IPs | Revisar < 7 días |
| 🟢 **LOW** | Bitcoin addresses | Monitorear |

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama: `git checkout -b feature/nueva-funcionalidad`
3. Commit: `git commit -m 'Add: nueva funcionalidad'`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Abre un Pull Request

## 📝 Roadmap

- [ ] Integración con TheHive/SOAR
- [ ] Validación de tarjetas con algoritmo de Luhn
- [ ] Soporte para PostgreSQL y MongoDB
- [ ] Dashboard web con métricas en tiempo real
- [ ] Notificaciones vía Slack/Email
- [ ] Sistema de whitelisting

## ⚠️ Disclaimer

Este proyecto es para **fines educativos y de investigación en seguridad**. No utilizar en sistemas de producción sin autorización explícita. Los datos de prueba incluidos son ficticios.

## 📄 Licencia

MIT License - ver [LICENSE](LICENSE) para más detalles

## 👤 Autor

**Santiago Fernandez**
- LinkedIn: [Tu Perfil](https://linkedin.com/in/safernandez666)
- Blog: [tu-blog.com](https://blog.santiagoagustinfernandez.com)

## 🙏 Agradecimientos

- [Hawk-Scanner](https://github.com/rohitcoder/hawk-eye) - Motor de escaneo
- [LocalStack](https://github.com/localstack/localstack) - Emulación de AWS

---

⭐ Si te resulta útil, dale una estrella al repo
