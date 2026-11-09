from scapy.all import ARP, Ether, srp

def scanForDevices(interface_map: dict) -> list:
    print(f"[*] Rozpoczynam wielowątkowe skanowanie ARP na {len(interface_map)} podinterfejsach...")
    clients = []
    
    for iface, target_cidr in interface_map.items():
        print(f"[*] Skanowanie sieci {target_cidr} przez natywny interfejs {iface}...")
        
        arp = ARP(pdst=target_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        result = srp(packet, timeout=2, verbose=0, iface=iface)[0]
        
        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    unique_clients = {client['ip']: client for client in clients}.values()
    
    print(f"[*] Zakończono skanowanie. Znaleziono {len(unique_clients)} unikalnych urządzeń (L2).")
    return list(unique_clients)



def printDevices(devices: list):
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in devices:
        print("{:16}    {}".format(client['ip'], client['mac']))