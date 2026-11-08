from scapy.all import get_if_list, get_if_addr
import asyncio
import multiprocessing

from _NetTrafic.MySnifferClass import MySniffer
from _Networks.SubnetScanner import scanForDevices
from _SNMP.PollerManager import PollerManager
from _SNMP.SnmpPoller import AsyncSNMPPoller
from _NetTrafic.packetAnalyzer import MyAnalyzer
from _SNMP.snmp_analyzer import SNMPTelemetryAnalyzer
from _DB.db_tools_async import init_db
from startup_config import TRUSTED_SUBNETS

    # Run with sudo!

def getInterfacesFromUser():
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

def printBanner():
    print("\nWELCOME TO NTA - YOUR ACTIVE NETWORK MONITORING SOLUTION\n")
    print("""    ███╗   ██╗████████╗ █████╗               ███╗   ██╗██╗██████╗ ██████╗ ███████╗
    ████╗  ██║╚══██╔══╝██╔══██╗              ████╗  ██║██║██╔══██╗██╔══██╗██╔════╝
    ██╔██╗ ██║   ██║   ███████║    █████╗    ██╔██╗ ██║██║██║  ██║██████╔╝███████╗
    ██║╚██╗██║   ██║   ██╔══██║    ╚════╝    ██║╚██╗██║██║██║  ██║██╔══██╗╚════██║
    ██║ ╚████║   ██║   ██║  ██║              ██║ ╚████║██║██████╔╝██║  ██║███████║
    ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝              ╚═╝  ╚═══╝╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝
                                                                              """)

shared_queue = multiprocessing.Queue()

async def start_app():
    await init_db()
    printBanner()
    interface_SNMP, interface_PM = getInterfacesFromUser()
    
    mySniffer = MySniffer(interface_PM, shared_queue, myIP=get_if_addr(interface_SNMP))
    analyzer = MyAnalyzer(shared_queue, safe_networks=TRUSTED_SUBNETS.keys())
    
    poller = AsyncSNMPPoller()
    snmp_analyzer = SNMPTelemetryAnalyzer()
    
    raw_hosts = [{'test': {'ip': '2.1.3.7'}}]
    
    k = 0
    reset_k = 6
    pool_cooldown = 10
    
    while True:
        print("Updating monitored devices and polling SNMP metrics...")
        if k % reset_k == 0:
            print("[*] Ponowne skanowanie sieci...")
            new_raw_hosts = await asyncio.to_thread(scanForDevices, interface_SNMP, TRUSTED_SUBNETS)
            
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


if __name__ == "__main__":
    try:
        asyncio.run(start_app())
    
    except KeyboardInterrupt:
        print("\nZamykanie NTA...")
        while not shared_queue.empty():
            try:
                shared_queue.get_nowait()
            except shared_queue.Empty:
                break