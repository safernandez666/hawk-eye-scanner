#!/usr/bin/env python3
"""
Generador de datos de prueba PCI/PII
Crea datos ficticios en MySQL y S3 para testing del scanner
"""

import pymysql
import boto3
from datetime import datetime

print("=" * 60)
print("🔧 Generando datos de prueba PCI/PII")
print("=" * 60)

# ========================================
# MYSQL - Datos de tarjetas
# ========================================
print("\n[1] Conectando a MySQL...")
try:
    conn = pymysql.connect(
        host='localhost',
        port=3306,
        user='root',
        password='rootpassword',
        database='pocdb',
        connect_timeout=10
    )
    cursor = conn.cursor()
    print("    ✅ Conectado a MySQL")
except Exception as e:
    print(f"    ❌ Error conectando a MySQL: {e}")
    print("    💡 Asegúrate que docker-compose esté corriendo")
    exit(1)

print("\n[2] Creando tabla de pagos...")
cursor.execute("DROP TABLE IF EXISTS payments")
cursor.execute("""
CREATE TABLE payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    card_number VARCHAR(20),
    cvv VARCHAR(4),
    expiry_date VARCHAR(10),
    amount DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")
print("    ✅ Tabla creada")

print("\n[3] Insertando datos PCI (tarjetas de crédito)...")
cards = [
    ('Juan Pérez', 'juan.perez@email.com', '555-123-4567', '4532015112830366', '123', '12/2026', 123.50),
    ('María García', 'maria.garcia@gmail.com', '555-987-6543', '5425233430109903', '456', '06/2025', 899.99),
    ('Carlos López', 'carlos.lopez@company.org', '555-456-7890', '378282246310005', '789', '03/2027', 2100.00),
    ('Ana Martínez', 'ana.martinez@test.com', '555-234-5678', '6011111111111117', '321', '09/2026', 450.75),
]

for card in cards:
    cursor.execute("""
        INSERT INTO payments (customer_name, email, phone, card_number, cvv, expiry_date, amount)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, card)

conn.commit()
print(f"    ✅ {len(cards)} tarjetas insertadas")

# Verificar
cursor.execute("SELECT COUNT(*) FROM payments")
count = cursor.fetchone()[0]
print(f"    📊 Total de registros: {count}")

conn.close()

# ========================================
# S3 (LocalStack) - Documentos con PII
# ========================================
print("\n[4] Conectando a S3 (LocalStack)...")
try:
    s3 = boto3.client(
        's3',
        endpoint_url='http://localhost:4566',
        aws_access_key_id='test',
        aws_secret_access_key='test',
        region_name='us-east-1'
    )
    print("    ✅ Conectado a LocalStack S3")
except Exception as e:
    print(f"    ❌ Error conectando a S3: {e}")
    exit(1)

bucket_name = 'poc-bucket'

print("\n[5] Creando bucket...")
try:
    s3.create_bucket(Bucket=bucket_name)
    print(f"    ✅ Bucket '{bucket_name}' creado")
except s3.exceptions.BucketAlreadyOwnedByYou:
    print(f"    ℹ️  Bucket '{bucket_name}' ya existe")
except Exception as e:
    print(f"    ℹ️  Bucket ya existe o error: {e}")

print("\n[6] Generando archivo PDF con PII...")
pdf_content = """
CONFIDENCIAL - DOCUMENTO INTERNO
TechCorp Solutions - Información de Empleados
==============================================

Empleado: Roberto Sánchez
SSN: 123-45-6789
Email: roberto.sanchez@techcorp.com
Teléfono: 555-111-2222
Tarjeta corporativa: 4532-0151-1283-0366

Empleado: Diego Morales
SSN: 456-78-9012
Email: diego.morales@techcorp.com
Teléfono: 555-333-4444
Tarjeta corporativa: 5425-2334-3010-9903

Empleado: Sofía Hernández
SSN: 987-65-4321
Email: sofia.h@techcorp.com
Teléfono: 555-555-6666
Tarjeta corporativa: 3782-822463-10005
"""

s3.put_object(
    Bucket=bucket_name, 
    Key='hr/empleados_confidencial.pdf',
    Body=pdf_content.encode('utf-8'),
    ContentType='application/pdf'
)
print(f"    ✅ PDF subido: s3://{bucket_name}/hr/empleados_confidencial.pdf")

print("\n[7] Generando archivo TXT con más PII...")
contactos_txt = """LISTA DE CONTACTOS INTERNOS - CONFIDENCIAL

1. Miguel Torres
   SSN: 111-22-3333
   Email: miguel.torres@techcorp.com
   Teléfono: +1-555-777-8888
   Tarjeta: 4111-1111-1111-1111

2. Patricia Ramírez - Gerente General
   SSN: 444-55-6666
   Email: patricia.ramirez@techcorp.com
   Teléfono: +1-555-999-0000

3. Laura Fernández
   SSN: 777-88-9999
   Email: laura.fernandez@techcorp.com
   Teléfono: +1-555-111-2222
"""

s3.put_object(
    Bucket=bucket_name,
    Key='contacts/internal_directory.txt',
    Body=contactos_txt.encode('utf-8'),
    ContentType='text/plain'
)
print(f"    ✅ TXT subido: s3://{bucket_name}/contacts/internal_directory.txt")

# Verificar archivos en S3
print("\n[8] Verificando archivos en S3...")
response = s3.list_objects_v2(Bucket=bucket_name)
if 'Contents' in response:
    print(f"    📊 Archivos en bucket:")
    for obj in response['Contents']:
        print(f"       - {obj['Key']} ({obj['Size']} bytes)")

print("\n" + "=" * 60)
print("✅ DATOS DE PRUEBA GENERADOS EXITOSAMENTE")
print("=" * 60)
print("\n📋 Resumen:")
print(f"  • MySQL tabla 'payments': {len(cards)} registros con tarjetas")
print(f"  • S3 archivo PDF: hr/empleados_confidencial.pdf")
print(f"  • S3 archivo TXT: contacts/internal_directory.txt")
print("\n💡 Siguiente paso:")
print("   docker exec -it hawk-scanner python run_hawk_scanner.py")
print()
