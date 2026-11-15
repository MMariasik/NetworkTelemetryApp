# Use only once when interfaces aren't set up yet

interpreter_path = "/home/matim/Desktop/IDS/NetworkTelemetryApp/NTA/bin/python"

import os
os.system('sudo ./interface_setup.sh')
os.system(f'sudo {interpreter_path} main.py')