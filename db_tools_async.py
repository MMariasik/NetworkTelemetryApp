import aiosqlite
import logging
import asyncio
from datetime import datetime

# Ścieżka do pliku bazy danych
DB_PATH = "NTA_data.db"

async def init_db():
    """
    Inicjalizuje schemat relacyjnej bazy danych.
    Uruchamiane jednorazowo przy starcie aplikacji (np. w main.py).
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            # Włączenie trybu WAL (Write-Ahead Logging) - krytyczne dla współbieżności w systemach IDS
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            
            # Tabela inwentarza urządzeń (Discovery & Polling)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    vendor TEXT,
                    device_type TEXT,
                    sys_name TEXT,
                    status TEXT,
                    last_seen TIMESTAMP
                )
            """)
            
            # Tabela zdarzeń bezpieczeństwa (Alerty IDS)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS ids_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    alert_type TEXT,
                    source TEXT,
                    threat_level TEXT,
                    target_ip TEXT,
                    message TEXT
                )
            """)
            
            # Tabela telemetrii wydajnościowej (SNMP Metrics)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    timestamp TIMESTAMP,
                    cpu_load_5s REAL,
                    ram_used_percent REAL,
                    total_processes INTEGER,
                    FOREIGN KEY(ip) REFERENCES devices(ip)
                )
            """)
            
            await db.commit()
            logging.info("[DB] Asynchroniczna baza danych SQLite zainicjalizowana pomyślnie (Tryb WAL).")
    except Exception as e:
        logging.critical(f"[DB ERROR] Nie można zainicjalizować bazy: {e}")


async def store_log_async(event_data: dict):
    """
    Zapisuje alert bezpieczeństwa w sposób nieblokujący (awaitable).
    Oczekuje słownika z kluczami: timestamp, type, source, threatLevel, ip, message.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            # Walidacja i rzutowanie czasu
            ts = event_data.get("timestamp")
            if isinstance(ts, datetime):
                ts_str = ts.isoformat()
            else:
                ts_str = ts or datetime.utcnow().isoformat()

            await db.execute("""
                INSERT INTO ids_alerts (timestamp, alert_type, source, threat_level, target_ip, message)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ts_str,
                event_data.get("type", "UNKNOWN"),
                event_data.get("source", "unknown"),
                event_data.get("threatLevel", "info"),
                event_data.get("ip", "0.0.0.0"),
                event_data.get("message", "")
            ))
            await db.commit()
    except Exception as e:
        logging.error(f"[DB ERROR] Błąd zapisu alertu IDS: {e}")


async def store_device_async(ip: str, general_info: dict):
    """
    Aktualizuje inwentarz urządzeń (Upsert). 
    Zastępuje starą synchroniczną funkcję store_device.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            now = datetime.utcnow().isoformat()
            vendor = general_info.get("vendor", "Unknown")
            device_type = general_info.get("device_type", "Unknown")
            sys_name = general_info.get("sysName", "Unknown")
            status = general_info.get("status", "unknown")
            
            # Upsert - jeśli IP istnieje, aktualizuj status i czas; jeśli nie, wstaw nowy rekord
            await db.execute("""
                INSERT INTO devices (ip, vendor, device_type, sys_name, status, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    status=excluded.status,
                    last_seen=excluded.last_seen,
                    sys_name=CASE WHEN excluded.sys_name != 'Unknown' THEN excluded.sys_name ELSE sys_name END,
                    vendor=CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE vendor END
            """, (ip, vendor, device_type, sys_name, status, now))
            
            await db.commit()
    except Exception as e:
        logging.error(f"[DB ERROR] Błąd zapisu/aktualizacji urządzenia {ip}: {e}")


async def store_metrics_async(metrics: dict):
    """
    Zapisuje kluczowe metryki wydajnościowe sprzętu.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            ip = metrics.get("ip")
            if not ip:
                return
                
            now = datetime.utcnow().isoformat()
            
            # Wstawienie przykładowych wyekstrahowanych danych (dostosuj pod strukturę build_metrics)
            cpu_load = metrics.get("cpu_load", 0.0)
            ram_used = metrics.get("ram_used_percent", 0.0)
            procs = metrics.get("total_processes", 0)

            await db.execute("""
                INSERT INTO performance_metrics (ip, timestamp, cpu_load_5s, ram_used_percent, total_processes)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, now, cpu_load, ram_used, procs))
            
            await db.commit()
    except Exception as e:
        logging.error(f"[DB ERROR] Błąd zapisu metryk dla {metrics.get('ip')}: {e}")