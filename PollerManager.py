import asyncio

monitored_devices = {}

class PollerManager:
    async def poll_devices(self, poller, raw_hosts):
        discovery_tasks = [poller.get_device_identity(host['ip']) for host in raw_hosts]
        discovered_data = await asyncio.gather(*discovery_tasks)
        print("znalezione dane:")
        for data in discovered_data:
            print(f"  - {data}")

        for data in discovered_data:
            if data['status'] == 'up':
                monitored_devices[data['ip']] = data
                print(f"[+] Dodano do monitoringu: {data['ip']} [{data['vendor']}]")
            else:
                print(f"[-] Urządzenie {data['ip']} jest niedostępne (status: {data['status']})")

        return monitored_devices

    async def poll_metrics(self, poller):
        if not monitored_devices:
            print("[!] Brak urządzeń do monitorowania.")
            return

        print("[*] Pobieranie metryk wydajnościowych dla monitorowanych urządzeń...")
        metric_tasks = [poller.get_device_metrics(data) for data in monitored_devices.values()]
        metrics_results = await asyncio.gather(*metric_tasks)

        for ip, metrics in zip(monitored_devices.keys(), metrics_results):
            if metrics:
                print(f"  - Metryki dla {ip}: {metrics}")
            else:
                print(f"  - Nie można pobrać metryk dla {ip}")