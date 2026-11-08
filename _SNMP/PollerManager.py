import asyncio

from startup_config import DEVICE_SIGNATURES
from _DB.db_tools_async import store_device_async, store_full_metrics_async

monitored_devices = {}

devices_lookup_table = {}

def resolve_device_type(sys_descr):
    sys_descr = sys_descr.lower()
    for key, value in DEVICE_SIGNATURES.items():
        if key.lower() in sys_descr:
            return value


class PollerManager:
    async def poll_devices(self, poller, raw_hosts):
        discovery_tasks = [poller.get_device_identity(host['ip']) for host in raw_hosts]
        discovered_data = await asyncio.gather(*discovery_tasks)
        for data in discovered_data:
            if data['status'] == 'up':
                data.update({'device_type': resolve_device_type(data['sysDescr'])})
                monitored_devices[data['ip']] = data
                print(f"[+] Dodano do monitoringu: {data['ip']} [{data['vendor']}]")
                await store_device_async(ip=data["ip"], general_info=data)
            else:
                print(f"[-] Urządzenie {data['ip']} jest niedostępne (status: {data['status']})")
                await store_device_async(ip=data["ip"], general_info={"status": data['status']})
        
        return monitored_devices

    def debug_print_device_info(self, ip, result):
        print(f"\n=== WSZYSTKIE DANE DLA URZĄDZENIA: {ip} ===")
        device_info = monitored_devices.get(ip, {})
        print(f"[BASE INFO] Nazwa: {device_info.get('sysName')}, Vendor: {device_info.get('vendor')}, Typ: {device_info.get('device_type')}")
        print(f"[PERFORMANCE]: {result.get('performance')}")
        print(f"[INTERFACES] (Liczba zebranych: {len(result.get('interfaces', []))}):")
        for iface in result.get("interfaces", []):
            if_num = iface.get('if_number')
            if_descr = iface.get('ifDescr', 'Unknown')
            status = iface.get('ifOperStatus', 'Unknown')
            
            in_bytes = iface.get('ifInOctets', '0')
            out_bytes = iface.get('ifOutOctets', '0')
            in_pkts = iface.get('ifInUcastPkts', '0')
            out_pkts = iface.get('ifOutUcastPkts', '0')
            in_errs = iface.get('ifInErrors', '0')
            out_errs = iface.get('ifOutErrors', '0')
            
            print(
                f"    - Port {if_num} ({if_descr}) -> Status: {status} | "
                f"Rx: {in_bytes}B ({in_pkts} pkts), Errors: {in_errs} | "
                f"Tx: {out_bytes}B ({out_pkts} pkts), Errors: {out_errs}"
            )

    async def poll_metrics(self, poller, snmp_analyzer=None):
        if not monitored_devices:
            print("[!] Brak urządzeń do monitorowania.")
            return
        print("[*] Pobieranie metryk wydajnościowych dla monitorowanych urządzeń...")
        metric_tasks = [poller.get_device_metrics(data) for data in monitored_devices.values()]
        metrics_results = await asyncio.gather(*metric_tasks)
        
        analysis_tasks = []
        
        for ip, result in zip(monitored_devices.keys(), metrics_results):
            if result:
                await store_device_async(ip=ip, general_info={"status": "up"})
                
                await store_full_metrics_async(
                    ip=ip,
                    performance=result.get("performance", {}),
                    interfaces=result.get("interfaces", [])
                )
                
                self.debug_print_device_info(ip, result)
                
                if snmp_analyzer:
                    task = asyncio.create_task(snmp_analyzer.analyze_metrics(result))
                    analysis_tasks.append(task)
            else:
                await store_device_async(ip=ip, general_info={"status": "down"})
        
        if analysis_tasks:
            await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        print("[*] Koniec pobierania metryk wydajnościowych")