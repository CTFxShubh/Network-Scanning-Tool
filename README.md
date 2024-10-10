# Network-Scanning-Tool

## Project Overview

The Network Scanning Tool is a comprehensive C language project designed to help network administrators and cybersecurity professionals efficiently discover devices, perform port scanning, and assess vulnerabilities within a network infrastructure. The tool offers various scanning techniques and is capable of generating detailed reports to enhance security posture.

This project was developed as part of a B.Tech Computer Science & Engineering program at Parul University, under the guidance of Dr. Mohammad Shahnawaz Shaikh.

## Features

Network Discovery: Uses protocols such as ICMP, ARP, and SNMP to identify devices within the network.

Port Scanning: Implements multiple techniques like TCP connect scans, SYN scans, and UDP scans.

Vulnerability Assessment: Leverages a database of known vulnerabilities (CVEs) to scan services and devices for security risks.

Reporting & Analysis: Generates customizable reports summarizing scan results and suggested remediation.

Logging & Auditing: Maintains detailed logs of scan activities for auditing and forensic analysis.

## Prerequisites

Before compiling and running the tool, ensure you have the following:

~ GCC Compiler
~ Make
~ pthread libraries 
~ libpcap or any other necessary network libraries.
~ Supported scan types include:

1. tcp

2. syn

3. udp

## File Structure

src/: Contains the C source code for the tool.

include/: Header files for modular functionalities like ICMP, TCP, and UDP scanning.

## Future Work

Adding GUI Support for ease of use.

Integrating with third-party SIEM solutions for automated threat response.

## Authors

1. Krenil Raj

2. Shubh Patel

3. Prarthan Christian

4. Kartikay Mistry

## License

This project is licensed under the MIT License.
