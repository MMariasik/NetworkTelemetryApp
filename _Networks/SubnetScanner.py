from scapy.all import ARP, Ether, srp
import ipaddress

def scanForDevices(interface: str, subnets: list) -> list:
    print(f"[*] Rozpoczynam skanowanie dla {len(subnets)} zdefiniowanych podsieci...")
    clients = []
    scanned_networks = set()
    
    for network in subnets:
        # Konwersja binarnego obiektu ipaddress na ciąg znaków CIDR wymagany przez Scapy
        network_cidr = str(network)
        
        if network_cidr not in scanned_networks:
            print(f"[*] Wykrywanie hostów w podsieci: {network_cidr} przez interfejs {interface}")
            clients.extend(ARPscan(interface, network_cidr))
            scanned_networks.add(network_cidr)
    
    unique_clients = {client['ip']: client for client in clients}.values()
    
    print(f"[*] Zakończono skanowanie. Znaleziono {len(unique_clients)} unikalnych urządzeń.")
    return list(unique_clients)

def ARPscan(interface: str, target_cidr: str) -> list:
    arp = ARP(pdst=target_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    
    result = srp(packet, timeout=3, verbose=0, iface=interface)[0]
    
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return clients

def printDevices(devices: list):
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in devices:
        print("{:16}    {}".format(client['ip'], client['mac']))