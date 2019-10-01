
from netaddr import *
import os
import sys
from scapy.all import *
import random
import ipaddress



SYNACK = 0x12
def main():

    conf.verb = 0

    print("Welcome to Jared's IP address scanner!")
    
    # THIS SECTION TAKES IP ADDRESS FORMAT
    ip_addr_option = input("\nChoose the number for the option of IP address or range you would like to scan:\n1 - single IP\n2 - CIDR block\n3 - range of addresses\n")
    if ip_addr_option == '1':
        ip_addr_start = input("Enter an ip address: ")
        ip_addr_end = ip_addr_start
    elif ip_addr_option == '2':
        cidr_block = input("Enter a CIDR notation block: ")
        ips = IPNetwork(cidr_block)
        ip_addr_start = ips[0]
        ip_addr_end = ips[-1]
    elif ip_addr_option == '3':
        ip_addr_start = input("input a starting address: ")
        ip_addr_end = input("input a final address: ")
    else:
        print("Error! That was not a valid option!")


    # THIS SECTION TAKE PORT # FORMAT
    port_number_option = input("\nChoose the number for the option of port number format you would like to input:\n1 - range\n2 - comma separated list (ex: \"22,80,443\")\n")
    if port_number_option == '1':
        port_start = input("Enter a start port: ")
        port_end = input("Enter a last port: ")
        ports = list(range(int(port_start), int(port_end)))
    elif port_number_option == '2':
        ports = input("Enter a comma separated list of ports: ").split(',')
        ports = [int(x) for x in ports]

    protocol_option = input("\nChoose an option for the type of scan: \n1 - TCP\n2 - UDP\nEnter an option: ")
    if protocol_option == '1':
        protocol = "TCP"
    elif protocol_option == '2':
        protocol = "UDP"

    scan_hosts(ip_addr_start, ip_addr_end,ports, protocol)



def scan_hosts(ip_addr_start, ip_addr_end,ports, protocol):
    for ip_int in range(int(ipaddress.IPv4Address(ip_addr_start)),int(ipaddress.IPv4Address(ip_addr_end))+1):
        host = ipaddress.IPv4Address(ip_int)
        print("\nScanning host {}".format(host))
        #check to see if host exists, if not: break
        for port in ports:
            #print("Scanning port {}".format(port))
            if protocol == 'TCP':
                tcp_scan_port(host, port)
            elif protocol == 'UDP':
                udp_scan_port(host, port)


def tcp_scan_port(ip_addr, port):
    srcport = random.randint(32678, 61000)
    response_packet = sr1(IP(dst=str(ip_addr))/TCP(sport=srcport, dport=int(port), flags = "S"), timeout=.25)
    if response_packet == None:
        print_port(port, "PORT CLOSED OR BLOCKED")
        return

    response_flags = response_packet.getlayer(TCP).flags
    
    if response_flags == SYNACK:
        print_port(port, "PORT OPEN")
    else:
        print_port(port, "PORT CLOSED OR BLOCKED")
    
    rst_pkt = IP(dst=str(ip_addr))/TCP(sport=srcport, dport=int(port), flags = "R")
    send(rst_pkt)

def udp_scan_port(ip_addr, port):
    srcport = random.randint(32678, 61000)
    response_packet = sr1(IP(dst=ip_addr)/UDP(sport=srcport, dport=int(port)), timeout=2)
    if response_packet == None:
        print_port(port, "PORT OPEN or FILTERED")
    else:
        if response_packet.hasLayer(UDP):
            print_port(port, "PORT OPEN")
        elif response_packet.hasLayer(ICMP):
            print_port(port, "PORT CLOSED")
        else:
            print_port(port, "PORT STATUS UNKNOWN")

def print_port(port, state):
    print(str(port) + " : " + state)

if __name__ == '__main__':
    main()
