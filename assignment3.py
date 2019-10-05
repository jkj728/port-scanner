#Github repository: https://github.com/jkj728/port-scanner

from netaddr import *
import os
import sys
from scapy.all import *
import random
import ipaddress
from prettytable import PrettyTable


SYNACK = 0x12
def main():
    table = PrettyTable(["Host IP Address", "Port", "Port Status", "Protocol"])
    conf.verb = 0

    print("Welcome to Jared's IP address scanner!")
    
    # THIS SECTION TAKES THE IP ADDRESS FORMAT. It uses the information gathered to create a list of ip_addresses
    ip_addr_option = input("\nChoose the number for the option of IP address or range you would like to scan:\n1 - single IP\n2 - CIDR block\n3 - range of addresses\n4 - read from a file\n")
    if ip_addr_option == '1':
        ip_addr_start = input("Enter an ip address: ")
        ip_addr_end = ip_addr_start
        ip_addresses = range(int(ipaddress.IPv4Address(ip_addr_start)),int(ipaddress.IPv4Address(ip_addr_end))+1)
    elif ip_addr_option == '2':
        cidr_block = input("Enter a CIDR notation block: ")
        ips = IPNetwork(cidr_block)
        ip_addr_start = ips[0]
        ip_addr_end = ips[-1]
        ip_addresses = range(int(ipaddress.IPv4Address(ip_addr_start)),int(ipaddress.IPv4Address(ip_addr_end))+1)
    elif ip_addr_option == '3':
        ip_addr_start = input("input a starting address: ")
        ip_addr_end = input("input a final address: ")
        ip_addresses = range(int(ipaddress.IPv4Address(ip_addr_start)),int(ipaddress.IPv4Address(ip_addr_end))+1)
    elif ip_addr_option == '4':
        print('**File must be formatted such that each line has a single ip address**')
        file_name = input("Enter a file name: ")
        f = open(file_name, "r")
        f1 = f.readlines()
        ip_addresses = []
        for x in f1:
            ip_addresses.append(int(ipaddress.IPv4Address(x.rstrip())))
    else:
        print("Error! That was not a valid option!")
        exit()


    # THIS SECTION TAKE PORT # FORMAT. It uses the information gathered to create a list of port #s.
    port_number_option = input("\nChoose the number for the option of port number format you would like to input:\n1 - range\n2 - comma separated list (ex: \"22,80,443\")\n")
    if port_number_option == '1':
        port_start = input("Enter a start port: ")
        port_end = input("Enter a last port: ")
        ports = list(range(int(port_start), int(port_end)))
    elif port_number_option == '2':
        ports = input("Enter a comma separated list of ports: ").split(',')
        ports = [int(x) for x in ports]
    else:
        print("Error! That was not a valid option!")
        exit()

    #THIS SECTION TAKES PROTOCOL INFORMATION
    protocol_option = input("\nChoose an option for the type of scan: \n1 - TCP\n2 - UDP\nEnter an option: ")
    if protocol_option == '1':
        protocol = "TCP"
    elif protocol_option == '2':
        protocol = "UDP"
    else:
        print("Error! That was not a valid option!")
        exit()

    scan_hosts(ip_addresses, ports, protocol, table)

    #This sction writes the output to a file called "output.html"
    o = open("output.html", "w+")
    o.write(table.get_html_string(attributes={"border":"1"}))


#This function takes in the list of IP_addresses, ports and protocol to scan the actual hosts. It also takes in the table parameter to update the user output.
def scan_hosts(ip_addresses, ports, protocol, table):
    for ip_int in ip_addresses:
        host = ipaddress.IPv4Address(ip_int)
        print("\nScanning host {}".format(host))

        #check to see if host exists, if not: do not scan
        exists = is_up(host)

        if exists:
            table.add_row([host, "", "", ""])
            for port in ports:
                if protocol == 'TCP':
                    tcp_scan_port(host, port, table)
                elif protocol == 'UDP':
                    udp_scan_port(host, port, table)
    
        else:
            table.add_row([host, "", "Host nonexistent or blocked", ""])
            print("Host either does not exist or is blocked")


#this function performs a stealth TCP scan by sending a TCP SYN packet, checking for a response, and then sending a RSK packet after. It also logs the port information to the output table.
def tcp_scan_port(ip_addr, port, table):
    srcport = random.randint(32678, 61000)
    response_packet = sr1(IP(dst=str(ip_addr))/TCP(sport=srcport, dport=int(port), flags = "S"), timeout=.25)

    if response_packet == None:
        print_port(port, "PORT CLOSED OR BLOCKED")
        table.add_row(["",port,"PORT CLOSED OR BLOCKED", "TCP"])
        return

    response_flags = response_packet.getlayer(TCP).flags
    
    if response_flags == SYNACK:
        print_port(port, "PORT OPEN")
        table.add_row(["",port,"PORT OPEN", "TCP"])
    else:
        print_port(port, "PORT CLOSED OR BLOCKED")
        table.add_row(["",port,"PORT CLOSED OR BLOCKED", "TCP"])
    
    rst_pkt = IP(dst=str(ip_addr))/TCP(sport=srcport, dport=int(port), flags = "R")
    send(rst_pkt)

#This functions performs a basic UDP scan on a host.
def udp_scan_port(ip_addr, port, table):
    srcport = random.randint(32678, 61000)
    response_packet = sr1(IP(dst=str(ip_addr))/UDP(sport=srcport, dport=int(port)), timeout=2)

    if response_packet == None:
        print_port(port, "PORT OPEN or FILTERED")
        table.add_row(["",port,"PORT OPEN or FILTERED", "UDP"])
    else:
        if response_packet.hasLayer(UDP):
            print_port(port, "PORT OPEN")
            table.add_row(["",port,"PORT OPEN", "UDP"])
        elif response_packet.hasLayer(ICMP):
            print_port(port, "PORT CLOSED")
            table.add_row(["",port,"PORT CLOSED", "UDP"])
        else:
            print_port(port, "PORT STATUS UNKNOWN")
            table.add_row(["",port,"UNKNOWN", "UDP"])

#This function is simply used to log the port state in a common format
def print_port(port, state):
    print(str(port) + " : " + state)

#This function is used to send an ICMP packet to verify that the host is up before attempting to scan its ports
def is_up(ip_addr):
    response_packet = sr1(IP(dst=str(ip_addr))/ICMP(), timeout=2)
    if response_packet == None:
        return False
    return True

if __name__ == '__main__':
    main()
