from scapy.all import get_if_list, get_if_addr
import time
import asyncio

import MySnifferClass
import SubnetScanner
from SnmpPoller import AsyncSNMPPoller

monitored_devices = {}

    # Run with sudo!

def getInterfaceFromUser():
    print("Available interfaces:")
    for interface in get_if_list():
        print(f"{interface}, with addr: {get_if_addr(interface)}")

    print("Provide network interface for SNMP ", end="")
    while(True):
        interface_SNMP = input("[virbr0]: ") or "virbr0"
        if interface_SNMP not in get_if_list():
            print(f"Error: Interface \"{interface_SNMP}\" does not exist, try again: ", end="")
        else:
            break

    print("Provide network interface for Port Mirroring ", end="")
    while(True):
        interface_PM = input("[tap-span]: ") or "tap-span"
        if interface_PM not in get_if_list():
            print(f"Error: Interface \"{interface_PM}\" does not exist, try again: ", end="")
        else:
            break

    return interface_SNMP, interface_PM


async def start_app():
    interface_SNMP, interface_PM = getInterfaceFromUser()
    
    mySniffer = MySnifferClass.MySniffer(interface_PM)
    poller = AsyncSNMPPoller()

    print("[*] Rozpoczynam jednorazowe skanowanie sieci...")
    raw_hosts = SubnetScanner.scanForDevices(interface_SNMP) # ARP Scan
    print(f"[*] Zakończono skanowanie sieci. Znaleziono {len(raw_hosts)} urządzeń.")

    # Równoległe sprawdzanie SNMP dla wszystkich znalezionych po ARP
    discovery_tasks = [poller.get_device_identity(host['ip']) for host in raw_hosts]
    discovered_data = await asyncio.gather(*discovery_tasks)
    print("znalezione dane:")
    for data in discovered_data:
        print(f"  - {data}")

    for data in discovered_data:
        monitored_devices[data['ip']] = data
        if data['status'] == 'up':
            print(f"[+] Dodano do monitoringu: {data['ip']} [{data['vendor']}]")
        else:
            print(f"[-] Urządzenie {data['ip']} jest niedostępne (status: {data['status']})")

    while True:
        print("test3")
        await asyncio.sleep(30) # Interwał odpytywania
        for data in discovered_data:
            data = monitored_devices[data['ip']]
            metrics = await poller.get_device_metrics(data)
            if metrics:
                print(f"  - Metryki dla {data['ip']}: {metrics}")
            else:
                print(f"  - Nie można pobrać metryk dla {data['ip']}")

if __name__ == "__main__":
    try:
        asyncio.run(start_app())
    except KeyboardInterrupt:
        print("\nZamykanie NetPulse...")