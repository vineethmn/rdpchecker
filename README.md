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
