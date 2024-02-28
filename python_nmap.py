import nmap
import argparse
from datetime import datetime
from libnmap.parser import NmapParser, NmapParserException

def scan(target, output_file):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-Pn -sV')

    # Get the XML output after the scan
    xml_output = nm.get_nmap_last_output()

    # Write the XML output to the specified output file
    with open(output_file, 'wb') as f:  # Open the file in binary mode
        f.write(xml_output)  # Write binary data directly to the file



def generate_report(input_file, output_file):
    try:
        nmap_report = NmapParser.parse_fromfile(input_file)
        report_output = ""
        for host in nmap_report.hosts:
            if host.is_up():
                report_output += f"\nHost: {host.address}\n"
                for serv in host.services:
                    report_output += f"  Port {serv.port}: {serv.service}\n"
                    if serv.cpelist:
                        cpe_str = ', '.join(str(cpe) for cpe in serv.cpelist)  # Convert each item to string
                        report_output += f"    CPE: {cpe_str}\n"
        if report_output:
            with open(output_file, 'w') as f:
                f.write(f"Nmap Scan Results ({datetime.now()}):\n")
                f.write(report_output)
            print("Vulnerability report generated successfully.")
        else:
            print("No hosts found with open ports.")
    except NmapParserException as e:
        print("Unable to parse Nmap scan results:", e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Perform Nmap scan and generate vulnerability report.')
    parser.add_argument('target', type=str, help='Target IP or range')
    parser.add_argument('--output', '-o', type=str, default='nmap_scan.xml', help='Output file name')
    args = parser.parse_args()

    scan(args.target, args.output)
    generate_report(args.output, 'vulnerability_report.txt')