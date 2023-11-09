#!/usr/bin/env python3

__author__ = "Vineeth Mukundan"
__version__ = "1.0.0"
__description__ = """
Author: Vineeth Mukundan
Version 1.0.0

RDP Scanner

This script can be used to check if a system is enabled for RDP at the application level. At times,
companies usually block RDP from the application layer and not the network layer. If you run
nmap or any tool that works on the network layer, it will show that RDP is enabled. This tool will
check the accessibility of terminal services from the application layer.

Usage: python rdp_checker.py -i INPUTFILE -c CSVFILE

Options:

-h, --help show this help message and exit
-i INPUTFILE, --input=INPUTFILE List of IP addresses with one IP address per line
-c CSVFILE, --csv=CSVFILE Output CSV filename

Dependencies:
 - nmap
 - python-nmap
"""

import optparse
import sys
import nmap

status_dict = {}


def check_rdp(ip_addr):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip_addr, arguments='-p 3389')
        
        if 'tcp' in nm[ip_addr] and 3389 in nm[ip_addr]['tcp']:
            rdp_status = "RDP Port Open"
        else:
            rdp_status = "Closed/Inaccessible"
        
        status_dict[ip_addr] = rdp_status
    except Exception as e:
        print(f"[-] Error occurred while running script: {e}")
        status_dict[ip_addr] = "Error"



def writeCSV(outputfilename):
    with open(outputfilename, "w") as csvfile:
        outputdata = "IP Address,RDP Status\n"
        for ip_addr in status_dict.keys():
            outputdata += f"{ip_addr},{status_dict[ip_addr]}\n"
        csvfile.write(outputdata)
        csvfile.flush()
    print(f"[+] {outputfilename} written successfully.")



def main():
    parser = optparse.OptionParser(
        "python3 rdp_checker.py -i INPUTFILE -c CSVFILE\n\r\n\rIf CSVFILE not provided, CSV filename will be the same as that of INPUTFILE \n" + __description__)
    parser.add_option("-i", "--input", dest="inputfile", help="List of IP addresses with one IP address per line")
    parser.add_option("-c", "--csv", dest="csvfile", help="Output CSV filename")
    options, args = parser.parse_args()
    if not options.inputfile:
        print("[-] Input file is required")
        parser.print_help()
        sys.exit(1)
    else:
        if not options.csvfile:
            options.csvfile = options.inputfile.split(".")[0] + ".csv"
        else:
            if not options.csvfile.split(".")[len(options.csvfile.split(".")) - 1] == "csv":
                options.csvfile = options.csvfile + ".csv"
        ip_addresses = open(options.inputfile, "r").readlines()
        counter = 0
        for ip_address in ip_addresses:
            ip_address = ip_address.strip()
            total = len(ip_addresses)
            percentage = float(counter * 100) / float(total)
            print(f"[+] Processing {counter+1} of {total} [{ip_address}] IP addresses. Percentage complete: {percentage:.2f}%")
            check_rdp(ip_address)
            counter += 1
        writeCSV(options.csvfile)


if __name__ == "__main__":
    main()
