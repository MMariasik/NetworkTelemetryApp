# config.py
VLAN_INTERFACES = {
    'tap0.10': '192.168.10.0/24',  # VLAN Zarządzania
    'tap0.20': '192.168.20.0/24',  # VLAN Klientów
    'tap0.30': '192.168.30.0/24'   # VLAN IoT
}
# Słownik sygnatur sprzętowych
DEVICE_SIGNATURES = {
    "(C3640-A3JS-M)": "Switch",
    "(I86BI_LINUXL2-ADVENTERPRISEK9-M)": "Switch",
    "(C7200-ADVENTERPRISEK9-M)": "Router"
}