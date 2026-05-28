import asyncio
from pysnmp.hlapi.asyncio import (
    SnmpEngine, 
    CommunityData, 
    UdpTransportTarget, 
    ContextData, 
    ObjectType, 
    ObjectIdentity, 
    get_cmd
)

# --- KONFIGURACJA UNIWERSALNA ---
# Słownik OID-ów podzielony na kategorie i vendorów
OIDS = {
    # --- DANE BAZOWE (Pobierane raz - Scalar OIDs kończą się na .0) ---
    "base": {
        "sysDescr": "1.3.6.1.2.1.1.1.0", 
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",    # Czas działania
        "sysLocation": "1.3.6.1.2.1.1.6.0",  # Lokalizacja
        "sysContact": "1.3.6.1.2.1.1.4.0",   # Kontakt do admina
    },

    # --- WYDAJNOŚĆ (Pobierane często) ---
    "performance": {
        "Cisco IOS/Nexus": {
            # Zasoby ogólne (Zazwyczaj wymagają indeksu instancji .1 na końcu)
            "cpu_5sec": "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1",    # Użycie CPU z ostatnich 5 sekund (%)
            "cpu_1min": "1.3.6.1.4.1.9.9.109.1.1.1.1.4.1",    # Użycie CPU z ostatniej minuty (%)
            "cpu_5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1",    # Użycie CPU z ostatnich 5 minut (%)
            "ram_used": "1.3.6.1.4.1.9.9.109.1.1.1.1.12.1",   # Pamięć RAM wykorzystana (Bajty)
            "ram_free": "1.3.6.1.4.1.9.9.109.1.1.1.1.13.1",   # Pamięć RAM wolna (Bajty)
            
            # Pamięci puli I/O (Kluczowe przy anomaliach i pps burstach)
            "mem_pool_processor_used": "1.3.6.1.4.1.9.9.48.1.1.1.5.1", # RAM procesora
            "mem_pool_io_used": "1.3.6.1.4.1.9.9.48.1.1.1.5.2",        # RAM dla buforowania pakietów I/O
            
            # Środowiskowe / Hardware
            "temperature": "1.3.6.1.4.1.9.9.13.1.3.1.3",      # Temperatura sensora w st. Celsjusza (Tabela)
            "fan_state": "1.3.6.1.4.1.9.9.13.1.4.1.3",        # Status wentylatora: 1=normal, 3=critical
            "power_supply_state": "1.3.6.1.4.1.9.9.13.1.5.1.3", # Status zasilacza
            "tcam_usage_pct": "1.3.6.1.4.1.9.9.845.1.1.1.1.3", # Procentowe zużycie sprzętowego TCAM (L3 Switche)
            
            # Stacking / Praca w stosie (Wymagają WALK)
            "stack_switch_role": "1.3.6.1.4.1.9.9.500.1.2.1.1.3", # Rola: 1=master, 2=member
            "stack_switch_state": "1.3.6.1.4.1.9.9.500.1.2.1.1.6", # Stan: 1=ready, inne to awaria
            "stack_port_status": "1.3.6.1.4.1.9.9.500.1.2.2.1.1",  # Status portów stacku z tyłu: 1=up, 2=down
            
            # Power over Ethernet (PoE)
            "poe_total_power": "1.3.6.1.2.1.105.1.3.1.1.2",       # Całkowity budżet PoE zasilacza (W)
            "poe_consumed_power": "1.3.6.1.2.1.105.1.3.1.1.3",    # Aktualnie pobierana moc PoE (W)
            "poe_port_status": "1.3.6.1.2.1.105.1.1.1.3",         # Status portu: 3=deliveringPower, 4=fault (Tabela)
            
            # Routing i Płaszczyzna Sterowania (Control Plane - Tabela)
            "bgp_peer_state": "1.3.6.1.2.1.15.3.1.2",             # Stan sesji BGP: 6=established (Tabela)
            "bgp_peer_uptime": "1.3.6.1.2.1.15.3.1.24",           # Uptime sesji BGP w sekundach
            "ospf_neighbor_state": "1.3.6.1.2.1.14.10.1.6",       # Stan sąsiada OSPF: 8=full (Tabela)
            "ospf_neighbor_events": "1.3.6.1.2.1.14.10.1.11",     # Licznik zmian stanu sąsiedztwa (Flapping detekcja)
            
            # Bezpieczeństwo, NAT i VPN (Kluczowe dla IDS)
            "nat_active_translations": "1.3.6.1.4.1.9.10.77.1.1.1.0", # Aktualna liczba wpisów w tabeli NAT
            "nat_failed_translations": "1.3.6.1.4.1.9.10.77.1.1.3.0", # Licznik odrzuconych translacji (Przepełnienie/DDoS)
            "vpn_active_tunnels_ipsec": "1.3.6.1.4.1.9.9.171.1.2.1.1", # Liczba aktywnych tuneli Site-to-Site
            "vpn_failed_tunnels_global": "1.3.6.1.4.1.9.9.171.1.3.1.1", # Nieudane negocjacje IPsec (Brute-force / Skanowanie)
            "vpn_in_dropped_packets": "1.3.6.1.4.1.9.9.171.1.2.1.17",  # Pakiety odrzucone na wejściu do tunelu Crypto
            
            # Jakość Łącza i Polityki Ruchu
            "ip_sla_latest_rtt": "1.3.6.1.4.1.9.9.42.1.2.10.1.1",    # Wynik opóźnienia IP SLA Ping/Jitter (ms)
            "ip_sla_status": "1.3.6.1.4.1.9.9.42.1.2.10.1.2",        # Status testu: 1=ok, 3=timeout
            "qos_drop_bytes": "1.3.6.1.4.1.9.9.166.1.15.1.1.11"      # Bajty odrzucone przez restrykcje QoS (Tabela)
        },
        "Linux/Unix Server": {
            "cpu_load_1m": "1.3.6.1.4.1.2021.10.1.3.1",    # Load average (1 min)
            "ram_total": "1.3.6.1.4.1.2021.4.5.0",         # Całkowity RAM
            "ram_free": "1.3.6.1.4.1.2021.4.6.0"           # Wolny RAM
        },
        "MikroTik RouterOS": {
            "cpu_load": "1.3.6.1.2.1.25.3.3.1.2.1",        # Użycie CPU
            "ram_total": "1.3.6.1.2.1.25.2.2.0",           # (Zależy od wersji MIB)
        },
        "Juniper Junos": {
            "cpu_load": "1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0" # Użycie procesora Routing Engine
        }
    },

    # --- INTERFEJSY SIECIOWE (Standard IF-MIB - działa prawie wszędzie) ---
    # UWAGA: Te OIDy to tabele. Aby pobrać dane, trzeba znać indeks interfejsu (np. .1, .2)
    # lub użyć operacji WALK / GETBULK.
    "interfaces": {
        "ifNumber": "1.3.6.1.2.1.2.1.0",              # Liczba interfejsów w urządzeniu
        
        # OIDy bazowe (wymagają dodania indeksu, np. 1.3.6.1.2.1.2.2.1.2.1 dla IF nr 1)
        "ifDescr": "1.3.6.1.2.1.2.2.1.2",             # Nazwa (np. GigabitEthernet0/0)
        "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",        # Status: 1 (Up), 2 (Down)
        
        # Liczniki 64-bitowe (SNMPv2c/v3) - KLUCZOWE DLA IDS (Wykrywanie DDoS)
        "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",     # Bajty wchodzące (Rx)
        "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",   # Bajty wychodzące (Tx)
        "ifInUcastPkts": "1.3.6.1.2.1.31.1.1.1.7",    # Pakiety Unicast Rx
        "ifInDiscards": "1.3.6.1.2.1.2.2.1.13",       # Pakiety odrzucone wejściowe (wskazuje przeciążenie)
    }
}

# Słownik do automatycznej identyfikacji dostawcy na podstawie sysDescr
VENDOR_MAP = {
    "Cisco": "Cisco IOS/Nexus",
    "NX-OS": "Cisco Nexus",
    "Linux": "Linux/Unix Server",
    "MikroTik": "MikroTik RouterOS",
    "Windows": "Windows Server",
    "Huawei": "Huawei VRP Platform",
    "Juniper": "Juniper Junos",
    "Arista": "Arista EOS",
    "Pfsense": "pfSense Firewall",
    "FortiGate": "Fortinet FortiGate",
    "HP": "HP ProCurve/Aruba"
}

class AsyncSNMPPoller:
    def __init__(self, communities=['public', 'cisco', 'admin'], port=161, timeout=2, retries=1):
        self.communities = communities
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.engine = SnmpEngine()
        self.auth_cache = {}  # Keszuje: {ip: {"community": str, "transport": UdpTransportTarget}}

    async def get_device_identity(self, ip):
        """Jednorazowe pobranie tożsamości (Discovery) i inicjalizacja transportu."""
        for community in self.communities:
            response = await self._try_query(ip, community)
            if response:
                # Zapamiętujemy parametry autoryzacji i reużywamy obiekt transportu
                self.auth_cache[ip] = {
                    'community': community,
                    'transport': response['transport']
                }
                vendor = self._identify_vendor(response['sysDescr'])
                return {
                    'ip': ip,
                    'status': 'up',
                    'vendor': vendor,
                    'community': community,
                    'sysName': response['sysName'],
                    'sysDescr': response['sysDescr'][:50]
                }
        return {'ip': ip, 'status': 'down'}

    async def _try_query(self, ip, community):
        """Pojedyncza próba Discovery."""
        try:
            transport = await UdpTransportTarget.create(
                (ip, self.port), 
                timeout=self.timeout, 
                retries=self.retries
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                self.engine,
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(OIDS["base"]["sysName"])),
                ObjectType(ObjectIdentity(OIDS["base"]["sysDescr"]))
            )

            if not errorIndication and not errorStatus:
                return {
                    'transport': transport,
                    'sysName': str(varBinds[0][1]),
                    'sysDescr': str(varBinds[1][1])
                }
        except Exception as e:
            # W produkcji zamień na lekki logger, print blokuje I/O przy wysokim PPS
            pass
        return None

    def _identify_vendor(self, description):
        """Fingerprinting urządzenia na podstawie sysDescr."""
        desc_lower = description.lower()
        for key, name in VENDOR_MAP.items():
            if key.lower() in desc_lower:
                return name
        return "Generic/Unknown"

    #------------------------------------------------------------------------------------

    async def get_device_metrics(self, device_data):
        """Pobiera metryki wydajnościowe na podstawie zidentyfikowanego dostawcy."""
        if not device_data or device_data.get('status') != 'up':
            return None

        ip = device_data['ip']
        vendor = device_data['vendor']
        
        vendor_metrics = OIDS["performance"].get(vendor)
        if not vendor_metrics:
            print(f"[!] Brak definicji metryk performance dla vendora: {vendor}")
            return None

        query_objects = [ObjectType(ObjectIdentity(oid)) for oid in vendor_metrics.values()]
        
        # Reużywamy transport i community z cache, jeśli istnieją
        if ip in self.auth_cache:
            transport = self.auth_cache[ip]['transport']
            community = self.auth_cache[ip]['community']
        else:
            community = device_data.get('community', 'public')
            try:
                transport = await UdpTransportTarget.create((ip, self.port), timeout=self.timeout, retries=self.retries)
            except Exception:
                return None
        
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                self.engine,
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                *query_objects
            )

            if not errorIndication and not errorStatus:
                metric_names = list(vendor_metrics.keys())
                results = {'ip': ip}
                for i in range(len(varBinds)):
                    results[metric_names[i]] = varBinds[i][1].prettyPrint()
                return results
        except Exception as e:
            print(f"[!] Błąd pobierania metryk z {ip}: {e}")
        return None