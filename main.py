from scapy.all import get_if_list, get_if_addr
import time
import asyncio
import multiprocessing
import ipaddress

from MySnifferClass import MySniffer
from SubnetScanner import scanForDevices
from PollerManager import PollerManager
from SnmpPoller import AsyncSNMPPoller
from packetAnalyzer import MyAnalyzer
from snmp_analyzer import SNMPTelemetryAnalyzer
from db_tools_async import init_db

    # Run with sudo!

def getInterfaceFromUser():
    print("Available interfaces:")
    for interface in get_if_list():
        print(f"{interface}, with addr: {get_if_addr(interface)}")

    print("Provide network interface for SNMP ", end="")
    while(True):
        interface_SNMP = input("[tap0]: ") or "tap0"
        if interface_SNMP not in get_if_list():
            print(f"Error: Interface \"{interface_SNMP}\" does not exist, try again: ", end="")
        else:
            break

    print("Provide network interface for Port Mirroring ", end="")
    while(True):
        interface_PM = input("[tap1]: ") or "tap1"
        if interface_PM not in get_if_list():
            print(f"Error: Interface \"{interface_PM}\" does not exist, try again: ", end="")
        else:
            break

    return interface_SNMP, interface_PM

async def start_app():


    print("\nWELCOME TO NTA - YOUR ACTIVE NETWORK MONITORING SOLUTION\n")
    print("""    ███╗   ██╗████████╗ █████╗               ███╗   ██╗██╗██████╗ ██████╗ ███████╗
    ████╗  ██║╚══██╔══╝██╔══██╗              ████╗  ██║██║██╔══██╗██╔══██╗██╔════╝
    ██╔██╗ ██║   ██║   ███████║    █████╗    ██╔██╗ ██║██║██║  ██║██████╔╝███████╗
    ██║╚██╗██║   ██║   ██╔══██║    ╚════╝    ██║╚██╗██║██║██║  ██║██╔══██╗╚════██║
    ██║ ╚████║   ██║   ██║  ██║              ██║ ╚████║██║██████╔╝██║  ██║███████║
    ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝              ╚═╝  ╚═══╝╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝
                                                                              """)

    await init_db()

    interface_SNMP, interface_PM = getInterfaceFromUser()
    
    shared_queue = multiprocessing.Queue()

    mySniffer = MySniffer(interface_PM, shared_queue, myIP=get_if_addr(interface_SNMP))
    analyzer = MyAnalyzer(shared_queue, safe_network=ipaddress.ip_network(get_if_addr(interface_SNMP) + '/24', strict=False))

    poller = AsyncSNMPPoller()
    snmp_analyzer = SNMPTelemetryAnalyzer()

    raw_hosts = [{'test': {'ip': '1.1.1.1'}}]

    await PollerManager().load_lookup_table("devices.json")

    k = 0
    reset_k = 6
    pool_cooldown = 10

    while True:
        print("Updating monitored devices and polling SNMP metrics...")
        if k % reset_k == 0:
            print("[*] Ponowne skanowanie sieci...")
            new_raw_hosts = scanForDevices(interface_SNMP)

            added = [h for h in new_raw_hosts if h not in raw_hosts]
            removed = [h for h in raw_hosts if h not in new_raw_hosts]

            if added or removed:
                print("[*] Zmiany w sieci wykryte, aktualizuję listę monitorowanych urządzeń...")

                print("dodane:", added)
                print("usunięte:", removed)

                raw_hosts = new_raw_hosts
                await PollerManager().poll_devices(poller, raw_hosts)

        await PollerManager().poll_metrics(poller, snmp_analyzer)
        await asyncio.sleep(pool_cooldown)
        k = (k + 1) % reset_k

def main():
    try:
        asyncio.run(start_app())
    except KeyboardInterrupt:
        print("\nZamykanie NTA...")

if __name__ == "__main__":
    main()