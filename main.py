from scapy.all import get_if_list, get_if_addr
import time


import MySnifferClass
import SubnetScanner

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
        interface_PM = input("[virbr0]: ") or "tap-span"
        if interface_PM not in get_if_list():
            print(f"Error: Interface \"{interface_PM}\" does not exist, try again: ", end="")
        else:
            break

    return interface_SNMP, interface_PM


try:
    interface_SNMP, interface_PM = getInterfaceFromUser()
    
    mySniffer = MySnifferClass.MySniffer(interface_PM)
    #devices = SubnetScanner.scanForDevices(interface_SNMP)
    #SubnetScanner.printDevices(devices)
    #SubnetScanner.getMoreInfo(devices)

    while(True):
        print("test3")
        time.sleep(15)
        
except KeyboardInterrupt:
    exit()
except Exception as e:
    print(f"Unexpected error: {e}")
