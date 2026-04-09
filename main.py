from scapy.all import get_if_list, get_if_addr
import time


import MySnifferClass
import SubnetScanner

    # Run with sudo!

def getInterfaceFromUser():
    print("Available interfaces:")
    for interface in get_if_list():
        print(f"{interface}, with addr: {get_if_addr(interface)}")

    print("Provide network interface ", end="")
    while(True):
        interface = input("[virbr0]: ") or "virbr0"
        if interface not in get_if_list():
            print(f"Error: Interface \"{interface}\" does not exist, try again: ", end="")
        else:
            break
    
    return interface


try:
    interface = getInterfaceFromUser()
    
    #mySniffer = MySnifferClass.MySniffer(interface)
    devices = SubnetScanner.scanForDevices(interface)
    SubnetScanner.printDevices(devices)
    SubnetScanner.getMoreInfo(devices)

    while(True):
        print("test3")
        time.sleep(15)
        
except KeyboardInterrupt:
    exit()
except Exception as e:
    print(f"Unexpected error: {e}")