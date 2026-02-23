#!/usr/bin/env python3
"""Generador de datos de prueba para Hawk-Eye Scanner"""

import json
import random
import boto3
import pymysql
from datetime import datetime, timedelta

# Configuración MySQL
MYSQL_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': 'rootpassword',
    'database': 'pocdb'
}

# Configuración S3 (LocalStack)
S3_CONFIG = {
    'endpoint_url': 'http://localhost:4566',
    'aws_access_key_id': 'test',
    'aws_secret_access_key': 'test',
    'region_name': 'us-east-1'
}

# Datos de prueba por severidad
CRITICAL_DATA = {
    'credit_cards': [
        '4532-1234-5678-9012', '5425-1234-5678-9010', '3782-822463-10005',
        '6011-1234-5678-9012', '4111-1111-1111-1111', '5555-5555-5555-4444'
    ],
    'private_keys': [
        '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwMbRvI0MBZhpJ\n-----END RSA PRIVATE KEY-----',
        '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----'
    ],
    'aws_secret_keys': [
        'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'AKIAIOSFODNN7EXAMPLE+wJalrXUtnFEMI/K7MDENG'
    ]
}

HIGH_DATA = {
    'ssns': ['123-45-6789', '987-65-4321', '555-12-3456', '111-22-3333'],
    'aws_access_keys': ['AKIAIOSFODNN7EXAMPLE', 'AKIAI44QH8DHBEXAMPLE'],
    'api_keys': ['sk_live_abcdef123456789', 'api_key_xyz789', 'key_1234567890abcdef'],
    'jwt_tokens': [
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.signature'
    ],
    'passwords': [
        'password123', 'admin123', 'secret123', 'P@ssw0rd!', 'MyP@ss123'
    ]
}

MEDIUM_DATA = {
    'emails': [
        'john.doe@example.com', 'jane.smith@company.org', 
        'admin@company.com', 'support@helpdesk.io',
        'contact@business.net', 'sales@enterprise.com'
    ],
    'phones': [
        '+1-555-123-4567', '+1-555-987-6543', 
        '+44-20-7946-0958', '+33-1-42-86-82-28',
        '+1-800-555-0199', '+1-555-555-5555'
    ],
    'ip_private': [
        '192.168.1.1', '10.0.0.1', '172.16.0.1',
        '192.168.0.100', '10.10.10.10'
    ],
    'ibans': [
        'GB82WEST12345698765432', 'DE89370400440532013000',
        'FR1420041010050500013M02606', 'ES9121000418450200051332'
    ]
}

LOW_DATA = {
    'bitcoin': [
        '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'
    ],
    'ethereum': [
        '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
        '0xdAC17F958D2ee523a2206206994597C13D831ec7'
    ]
}

def generate_mysql_data():
    """Genera datos en MySQL"""
    print("Generando datos en MySQL...")
    
    try:
        conn = pymysql.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        
        # Crear tablas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255),
                email VARCHAR(255),
                phone VARCHAR(50),
                ssn VARCHAR(20),
                card_number VARCHAR(50),
                api_key VARCHAR(255),
                notes TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                customer_id INT,
                card_number VARCHAR(50),
                iban VARCHAR(50),
                amount DECIMAL(10,2)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255),
                password VARCHAR(255),
                jwt_token TEXT,
                aws_key VARCHAR(100)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS servers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255),
                private_ip VARCHAR(50),
                ssh_key TEXT
            )
        ''')
        
        # Insertar datos variados (20 registros por tabla)
        for i in range(20):
            # Customers - mix de severidades
            cursor.execute('''
                INSERT INTO customers (name, email, phone, ssn, card_number, api_key, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                f'Customer {i}',
                random.choice(MEDIUM_DATA['emails']),
                random.choice(MEDIUM_DATA['phones']),
                random.choice(HIGH_DATA['ssns']),
                random.choice(CRITICAL_DATA['credit_cards']),
                random.choice(HIGH_DATA['api_keys']),
                random.choice(LOW_DATA['bitcoin'])
            ))
            
            # Payments - CRITICAL
            cursor.execute('''
                INSERT INTO payments (customer_id, card_number, iban, amount)
                VALUES (%s, %s, %s, %s)
            ''', (
                i + 1,
                random.choice(CRITICAL_DATA['credit_cards']),
                random.choice(MEDIUM_DATA['ibans']),
                round(random.uniform(10, 1000), 2)
            ))
            
            # Users - HIGH
            cursor.execute('''
                INSERT INTO users (username, password, jwt_token, aws_key)
                VALUES (%s, %s, %s, %s)
            ''', (
                f'user{i}',
                random.choice(HIGH_DATA['passwords']),
                random.choice(HIGH_DATA['jwt_tokens']),
                random.choice(HIGH_DATA['aws_access_keys'])
            ))
            
            # Servers - CRITICAL (SSH keys)
            cursor.execute('''
                INSERT INTO servers (name, private_ip, ssh_key)
                VALUES (%s, %s, %s)
            ''', (
                f'server{i}.internal',
                random.choice(MEDIUM_DATA['ip_private']),
                random.choice(CRITICAL_DATA['private_keys'])
            ))
        
        conn.commit()
        cursor.close()
        conn.close()
        print(f"  ✅ MySQL: 80 registros creados (20 x 4 tablas)")
        
    except Exception as e:
        print(f"  ❌ Error MySQL: {e}")

def generate_s3_data():
    """Genera archivos JSON en S3"""
    print("Generando datos en S3...")
    
    try:
        s3 = boto3.client('s3', **S3_CONFIG)
        
        # Verificar/crear bucket
        try:
            s3.head_bucket(Bucket='poc-bucket')
        except:
            s3.create_bucket(Bucket='poc-bucket')
        
        # Archivo 1: Datos de clientes (mix de severidades)
        customers_data = []
        for i in range(30):
            customers_data.append({
                "id": i,
                "name": f"Customer {i}",
                "email": random.choice(MEDIUM_DATA['emails']),
                "phone": random.choice(MEDIUM_DATA['phones']),
                "ssn": random.choice(HIGH_DATA['ssns']),
                "card": random.choice(CRITICAL_DATA['credit_cards']),
                "api_key": random.choice(HIGH_DATA['api_keys']),
                "bitcoin": random.choice(LOW_DATA['bitcoin'])
            })
        
        s3.put_object(
            Bucket='poc-bucket',
            Key='customers.json',
            Body=json.dumps(customers_data)
        )
        
        # Archivo 2: Configuración con secrets (CRITICAL)
        config_data = {
            "database": {
                "host": "localhost",
                "password": random.choice(HIGH_DATA['passwords']),
                "api_key": random.choice(HIGH_DATA['api_keys'])
            },
            "aws": {
                "access_key": random.choice(HIGH_DATA['aws_access_keys']),
                "secret_key": random.choice(CRITICAL_DATA['aws_secret_keys'])
            },
            "jwt": random.choice(HIGH_DATA['jwt_tokens']),
            "private_key": random.choice(CRITICAL_DATA['private_keys'])
        }
        
        s3.put_object(
            Bucket='poc-bucket',
            Key='config/secrets.json',
            Body=json.dumps(config_data, indent=2)
        )
        
        # Archivo 3: Logs con datos sensibles
        logs_data = []
        for i in range(50):
            logs_data.append({
                "timestamp": (datetime.now() - timedelta(hours=i)).isoformat(),
                "level": random.choice(["INFO", "WARN", "ERROR"]),
                "message": f"User login: {random.choice(MEDIUM_DATA['emails'])}",
                "ip": random.choice(MEDIUM_DATA['ip_private']),
                "session": random.choice(HIGH_DATA['jwt_tokens'])[:50] + "..."
            })
        
        s3.put_object(
            Bucket='poc-bucket',
            Key='logs/app-2026-02-22.json',
            Body=json.dumps(logs_data)
        )
        
        # Archivo 4: Transacciones financieras
        transactions = []
        for i in range(25):
            transactions.append({
                "id": f"TXN{i:05d}",
                "card": random.choice(CRITICAL_DATA['credit_cards']),
                "iban": random.choice(MEDIUM_DATA['ibans']),
                "amount": round(random.uniform(10, 5000), 2),
                "email": random.choice(MEDIUM_DATA['emails'])
            })
        
        s3.put_object(
            Bucket='poc-bucket',
            Key='finance/transactions.json',
            Body=json.dumps(transactions)
        )
        
        # Archivo 5: Datos mínimos (para probar LOW)
        crypto_data = {
            "wallets": [
                {"type": "bitcoin", "address": random.choice(LOW_DATA['bitcoin'])},
                {"type": "ethereum", "address": random.choice(LOW_DATA['ethereum'])}
            ]
        }
        
        s3.put_object(
            Bucket='poc-bucket',
            Key='crypto/wallets.json',
            Body=json.dumps(crypto_data)
        )
        
        print(f"  ✅ S3: 5 archivos creados")
        
    except Exception as e:
        print(f"  ❌ Error S3: {e}")

if __name__ == "__main__":
    print("="*50)
    print("Generador de datos de prueba")
    print("="*50)
    print()
    
    generate_mysql_data()
    generate_s3_data()
    
    print()
    print("="*50)
    print("✅ Datos generados correctamente")
    print("="*50)
