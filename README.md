# port-scanner

This port scanner is used to scan IP addresses (single, range or CIDR notation) for certain ports (range or comma separated list). The scanner can also import the IP addresses from a text file where each line contains a different valid IP address. The scan can be done on either UDP or TCP ports. Furthermore, before scanning each host, the existence of the host is verified with an ICMP ping. The final output of the scan is then exported in the local directory of the program as "output.html"

In order to run the program, sudo permissions must be used and python3 must be locally installed (as well as all pip3 package dependencies: netaddr, os, sys, random, ipaddress, scapy and PrettyTable). To run the program, use the terminal command `sudo python3 assignment3.py`
