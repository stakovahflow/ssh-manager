#!/usr/bin/env python3
VERSION='2024-03-06-g'
import re
from pexpect import pxssh
import time
import pexpect
import csv
import sys
from getpass import getpass
import logging
from logging import StreamHandler

# Set the path for our log file:
logfile = '/tmp/interface.log'

if len(sys.argv) != 2:
    print('Please provide a host list')
    exit(0)
else:
    host_file=sys.argv[1]

# Statically assigned username:
USERNAME = input("Username: ")

# Get password from user
PASSWORD = getpass(f"{USERNAME} SSH password: ")

bigcommand = """for interface in $(ip -br a | grep -v "^docker\|^lo\|^veth" | awk '{print $1}'); do
        HOSTNAME=$(hostname);
        A=$(ip -br link show "$interface" | awk '{print $1","$3}');
        B=$(ip -br addr show "$interface" | awk '{print $3}');
        echo "[$HOSTNAME,$A,$B]";
done
"""

# Create an information collection list:
all_interface_info = []

# Configure logging to output to both file and console
def setup_logging():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    user_message_format = '%(message)s'

    # Logging to file:
    file_handler = logging.FileHandler(logfile)
    file_handler.setFormatter(logging.Formatter(log_format))
    file_handler.setLevel(logging.DEBUG)

    # Logging to console:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter(user_message_format))
    # May want to setup logging level (--verbose) flag in future iterations, from "INFO" to "DEBUG":
    stream_handler.setLevel(logging.INFO)

    # Get the root logger and add both handlers
    # Setup our logging levels
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

# Call the function to set up logging at the start of your script
setup_logging()

# Get interfaces list from remote hosts:
getinterfaces = """ip -br a | grep -v "^docker\|^lo\|^veth" | awk '{print "Interface: " $1}' | sort"""

# Function to get MAC addresses from remote hosts:
def getmacaddress(interface):
    getmacoutput = """ip -br link show dev %s | grep -E '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})' | awk '{print "MAC_ADDRESS: " $3}'""" % interface
    logging.debug(getmacoutput)
    return(getmacoutput)

# Function to get IP addresses from remote hosts:
def getipaddress(interface):
    getipoutput = """ip -br addr show dev %s | grep '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | awk '{print "IP_ADDRESS: " $3}'""" % interface
    logging.debug(getipoutput)
    return(getipoutput)

# Function to scrape data from remote hosts, leveraging getmacaddress() and getipaddress():
def run_command_on_remote(hostaddress, username, password):
    hostaddress = hostaddress.strip()
    logging.debug(f'Host: {hostaddress}')
    print(f"Retrieving interface info from: {hostaddress}")
    try:
        interface_info = []
        # Establish SSH connection
        client = pxssh.pxssh(options={"UserKnownHostsFile": "/dev/null", "StrictHostKeyChecking": "no", "PubkeyAuthentication": "no"})
        fout = open("/tmp/" + hostaddress + ".log", 'wb')
        client.logfile = fout
        client.login(hostaddress, username, password)
        time.sleep(.1)
        # Get hostname:
        client.sendline('echo "HOST_NAME: $(hostname)"')
        client.prompt()
        SAVEPROMPT = client.PROMPT
        host_output = client.before.decode('utf-8')
        for host in host_output.splitlines():
            if host.startswith("HOST_NAME: "):
                hostname = host.replace("HOST_NAME: ", "")
                break
        # Get interfaces:
        client.sendline(getinterfaces)
        client.prompt()
        client.sync_original_prompt()
        interface_output = client.before.decode('utf-8').splitlines()
        for interface_line in interface_output:
            if interface_line.startswith("Interface: "):
                interfacename = interface_line.replace("Interface: ", "")
                logging.debug(f'Hostname: {hostname}, Interface:{interfacename}')
                # Get MAC Address (per interface):
                client.sendline(getmacaddress(interfacename))
                client.prompt()
                client.sync_original_prompt()
                mac_output = client.before.decode('utf-8').splitlines()
                mac_addresses = []
                for mac_line in mac_output:
                    if mac_line.startswith("MAC_ADDRESS: "):
                        mac_address = mac_line.replace("MAC_ADDRESS: ", "")
                        logging.debug(f'Hostname: {hostname}, Interface:{interfacename}, MAC:{mac_address}')
                        mac_addresses.append(mac_address)
                # Get IP Address (per interface):
                client.sendline(getipaddress(interfacename))
                client.prompt()
                client.sync_original_prompt()
                ip_output = client.before.decode('utf-8').splitlines()
                ip_addresses = []
                for ip_line in ip_output:
                    if ip_line.startswith("IP_ADDRESS: "):
                        ip_address = ip_line.replace("IP_ADDRESS: ", "").strip("\r\n")
                        logging.debug(f'Hostname: {hostname}, Interface:{interfacename}, IP:{ip_address}')
                        ip_addresses.append(ip_address)
                # Append our interface_info dictionary with the data we've collected:
                interface_info.append({'Hostname': hostname, 'Interface': interfacename, 'MAC Address': ', '.join(mac_addresses), 'IP Address': ', '.join(ip_addresses)})
                logging.info(f'Hostname: {hostname}, Interface: {interfacename}, MAC Address: {mac_addresses}, IP Address: {ip_addresses}')
        client.logout()
        return interface_info
    except KeyboardInterrupt:
        logging.info(f'Operation cancelled by user')
        exit(1)
    except pxssh.ExceptionPxssh as e:
        logging.info(f'SSH login to {hostaddress} failed')
        logging.debug(f"{e}")
        return None
    child.logfile.close()

# Read list of remote systems
with open (host_file, mode='r', newline='') as remote_systems:
    for system in remote_systems:
        try:
            interface_info = run_command_on_remote(system, USERNAME, PASSWORD)
            if interface_info:
                all_interface_info.extend(interface_info)
        except Exception as e:
            logging.error(f'An error occurred when attempting to access {system}: {e}')


# Write interface information to a CSV file
csv_file = "host_interfaces.csv"
with open(csv_file, mode='w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=["Hostname", "Interface", "MAC Address", "IP Address"])
    writer.writeheader()
    writer.writerows(all_interface_info)

print(f"Interface information has been exported to {csv_file}.")
