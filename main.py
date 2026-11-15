from scapy.all import get_if_list, get_if_addr
import asyncio
import multiprocessing
import queue

from _NetTrafic.MySnifferClass import MySniffer
from _Networks.SubnetScanner import scanForDevices
from _SNMP.PollerManager import PollerManager
from _SNMP.SnmpPoller import AsyncSNMPPoller
from _NetTrafic.packetAnalyzer import MyAnalyzer
from _SNMP.snmp_analyzer import SNMPTelemetryAnalyzer
from _DB.db_tools_async import init_db
from startup_config import VLAN_INTERFACES

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
        interface_PM = input("[tap0.999]: ") or "tap0.999"
        if interface_PM not in get_if_list():
            print(f"Error: Interface \"{interface_PM}\" does not exist, try again: ", end="")
        else:
            break
    
    return interface_SNMP, interface_PM

async def getNewHosts(interface_SNMP):
    new_raw_hosts = await asyncio.to_thread(scanForDevices, VLAN_INTERFACES)
    
    mgmt_ip_prefix = ".".join(get_if_addr(interface_SNMP).split(".")[:3]) + "."
    
    deduplicated_hosts = {}
    for host in new_raw_hosts:
        mac = host['mac']
        ip = host['ip']
        
        if mac not in deduplicated_hosts:
            deduplicated_hosts[mac] = host
        else:
            if ip.startswith(mgmt_ip_prefix):
                deduplicated_hosts[mac] = host
                
    return list(deduplicated_hosts.values()) 

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
    interface_SNMP, interface_PM = getInterfacesFromUser() # interface_SNMP might be deprecated soon
    
    mySniffer = MySniffer(interface_PM, shared_queue, myIP=get_if_addr(interface_SNMP))
    analyzer = MyAnalyzer(shared_queue, safe_networks=VLAN_INTERFACES.values())
    
    poller = AsyncSNMPPoller()
    snmp_analyzer = SNMPTelemetryAnalyzer()
    
    raw_hosts = [{'test': {'ip': '2.1.3.7'}}]
    
    k = 0
    reset_k = 6
    pool_cooldown = 10
    
    try:
        while True:
            print("[NTA] Updating monitored devices and polling SNMP metrics")
            if k % reset_k == 0:
                print("[NTA] Rescanning the network")
                new_raw_hosts = await getNewHosts(interface_SNMP=interface_SNMP)
                
                added = [h for h in new_raw_hosts if h not in raw_hosts]
                removed = [h for h in raw_hosts if h not in new_raw_hosts]
                
                if added or removed:
                    print("[NTA] Network changes detected, updating list of monitored devices")
                    
                    print("Added:", added)
                    print("Removed:", removed)
                    
                    raw_hosts = new_raw_hosts
                    await PollerManager().poll_devices(poller, raw_hosts)
            
            await PollerManager().poll_metrics(poller, snmp_analyzer)
            await asyncio.sleep(pool_cooldown)
            k = (k + 1) % reset_k 
    except asyncio.CancelledError:
        print("\n[NTA] An interrupt signal was received. The asyncio loop was stopped")
    finally:
        print("[NTA] Graceful Shutdown has begun")
        if 'mySniffer' in locals():
            print("[NTA] Stopping listening on SPAN port")
            try:
                mySniffer.sniffer.stop()
            except Exception:
                pass
                
        print("[NTA] Flushing data exchange buffers")
        try:
            while True:
                shared_queue.get_nowait()
        except queue.Empty:
            pass
            
        shared_queue.close()
        shared_queue.join_thread()
        print("[NTA] System resources released successfully")


if __name__ == "__main__":
    try:
        asyncio.run(start_app())
    
    except KeyboardInterrupt:
        print("\nClosing NTA...")