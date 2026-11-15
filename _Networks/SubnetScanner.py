from scapy.all import ARP, Ether, srp

def scanForDevices(interface_map: dict) -> list:
    print(f"[NTA] Starting a multi-threaded ARP scan on {len(interface_map)} subinterfaces")
    clients = []
    
    for iface, target_cidr in interface_map.items():
        print(f"[NTA] Scanning network {target_cidr} via native interface {iface}...")
        
        arp = ARP(pdst=target_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        result = srp(packet, timeout=2, verbose=0, iface=iface)[0]
        
        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    unique_clients = {client['ip']: client for client in clients}.values()
    
    print(f"[NTA] Scan completed. Found {len(unique_clients)} unique devices (L2).")
    return list(unique_clients)

def printDevices(devices: list):
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in devices:
        print("{:16}    {}".format(client['ip'], client['mac']))