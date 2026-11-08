import aiosqlite
import asyncio
from datetime import datetime, timezone

DB_PATH = "NTA.db"

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA synchronous=NORMAL;")
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY, vendor TEXT, device_type TEXT,
                sys_name TEXT, status TEXT, last_seen TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ids_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP,
                alert_type TEXT, source TEXT, threat_level TEXT,
                target_ip TEXT, message TEXT
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TIMESTAMP,
                cpu_5sec REAL, cpu_1min REAL, cpu_5min REAL,
                mem_pool_processor_used REAL, mem_pool_io_used REAL,
                cpu_load_1m REAL, cpu_load_5m REAL,
                cpu_user REAL, cpu_system REAL, cpu_idle REAL,
                ram_total REAL, ram_free REAL, ram_cached REAL, ram_buffered REAL,
                swap_total REAL, swap_free REAL,
                total_processes INTEGER, tcp_in_errors INTEGER,
                FOREIGN KEY(ip) REFERENCES devices(ip)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS interface_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TIMESTAMP,
                if_number INTEGER,
                if_descr TEXT,
                oper_status TEXT,
                in_octets INTEGER, out_octets INTEGER,
                in_ucast_pkts INTEGER, out_ucast_pkts INTEGER,
                in_errors INTEGER, out_errors INTEGER,
                FOREIGN KEY(ip) REFERENCES devices(ip)
            )
        """)
        await db.commit()

async def store_device_async(ip: str, general_info: dict = None):
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.now(timezone.utc).isoformat()
        status = general_info.get("status", "unknown") if general_info else "unknown"
        vendor = general_info.get("vendor", "Unknown") if general_info else "Unknown"

        await db.execute("""
            INSERT INTO devices (ip, vendor, status, last_seen) 
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET 
                status=excluded.status, 
                last_seen=excluded.last_seen
        """, (ip, vendor, status, now))
        await db.commit()

async def store_log_async(event_data: dict):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            ts = event_data.get("timestamp")
            if isinstance(ts, datetime):
                ts_str = ts.isoformat()
            else:
                ts_str = str(ts) if ts else datetime.utcnow().isoformat()

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
        print(f"[DB ERROR] Błąd zapisu alertu IDS: {e}")

async def store_full_metrics_async(ip: str, performance: dict, interfaces: list):
    if not performance and not interfaces:
        return

    now = datetime.now(timezone.utc).isoformat()

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            if performance:
                await db.execute("""
                    INSERT INTO performance_metrics (
                        ip, timestamp, cpu_5sec, cpu_1min, cpu_5min, mem_pool_processor_used, mem_pool_io_used,
                        cpu_load_1m, cpu_load_5m, cpu_user, cpu_system, cpu_idle,
                        ram_total, ram_free, ram_cached, ram_buffered, swap_total, swap_free,
                        total_processes, tcp_in_errors
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip, now,
                    performance.get("cpu_5sec"), performance.get("cpu_1min"), performance.get("cpu_5min"),
                    performance.get("mem_pool_processor_used"), performance.get("mem_pool_io_used"),
                    performance.get("cpu_load_1m"), performance.get("cpu_load_5m"),
                    performance.get("cpu_user"), performance.get("cpu_system"), performance.get("cpu_idle"),
                    performance.get("ram_total"), performance.get("ram_free"),
                    performance.get("ram_cached"), performance.get("ram_buffered"),
                    performance.get("swap_total"), performance.get("swap_free"),
                    performance.get("total_processes"), performance.get("tcp_in_errors")
                ))

            if interfaces:
                iface_records = []
                for iface in interfaces:
                    iface_records.append((
                        ip, now,
                        iface.get("if_number"),
                        iface.get("ifDescr"),
                        iface.get("ifOperStatus"),
                        iface.get("ifInOctets"),
                        iface.get("ifOutOctets"),
                        iface.get("ifInUcastPkts"),
                        iface.get("ifOutUcastPkts"),
                        iface.get("ifInErrors"),
                        iface.get("ifOutErrors")
                    ))

                await db.executemany("""
                    INSERT INTO interface_metrics (
                        ip, timestamp, if_number, if_descr, oper_status,
                        in_octets, out_octets, in_ucast_pkts, out_ucast_pkts,
                        in_errors, out_errors
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, iface_records)

            await db.commit()
    except Exception as e:
        print(f"[DB ERROR] Błąd masowego zapisu metryk dla {ip}: {e}")