# NetworkTelemetryApp #

NetworkTelemetryApp is a standalone Network Intrusion Detection and Response System (NIDRS) specifically designed to protect local networks from compromised Internet of Things (IoT) devices. Originally developed as an anomaly detection component for a broader monitoring project (<ins>https://github.com/251181/NetPulse/tree/develop</ins> ), it has evolved into a fully independent system capable of not only detecting threats but actively responding to them.

## Overview ##
The application serves as a dedicated security layer for modern smart environments. Its primary goal is to continuously monitor network traffic, identify IoT devices that have been attacked or infected (e.g., recruited into botnets), and automatically isolate them from the rest of the network.

By shifting from a passive IDS to an active NIDRS, NetworkTelemetryApp ensures that compromised endpoints are neutralized before they can cause lateral damage or communicate with malicious command-and-control servers.

## Features ##
    **Network Scanning** — Discover devices connected to the network and gather information about them.

    **Network Traffic Monitoring** — Capture and analyze network traffic to identify unusual patterns and suspicious activity.

    **Anomaly Detection** — Analyze network activity to identify irregularities that may indicate potential security threats.

    **Threat Identification** — Detect potentially dangerous behavior and suspicious network activity. 

    **IoT Device Discovery** — Scan and identify smart devices and other endpoints connected to the network.

    **Traffic Profiling** — Capture and analyze network traffic to establish baseline behaviors for specific IoT devices.

    **Compromise Detection** — Identify anomalies, unauthorized outbound connections, and malicious patterns indicative of a hacked device.

    **Automated Quarantine** — Actively respond to detected threats by isolating compromised devices, preventing further network infection and lateral movement.

## Project Evolution ##
This project originated as the core detection engine for a larger network monitoring tool (NetPulse). It has since been extracted and rebuilt into a fully independent NIDRS, shifting its focus from general network anomaly detection to targeted IoT threat response and mitigation.

## Future Development ##
I am actively developing this project as part of my bachelor's engineering thesis. The upcoming milestones focus on expanding the NIDRS capabilities, specifically:

    Refining automated network quarantine mechanisms.

    Improving behavioral profiling for a wider range of IoT devices.

    Minimizing false positives during threat identification and isolation.

## Disclaimer ##
This application is developed for educational and research purposes. Only use it to scan, monitor, and quarantine devices on networks you own or have explicit permission to secure.