#!/usr/bin/env python3
# Last modified: 2024-01-10 @ 11:29 PM

import csv
import base64
import argparse
import os
import logging
import pexpect
import socket
import subprocess
from cryptography.fernet import Fernet
from pexpect import pxssh
import getpass
from logging import StreamHandler
import sys
import shutil

# Get our application name:
appname = sys.argv[0]
def liner():
    # Get the size of the terminal
    terminal_size = shutil.get_terminal_size(fallback=(80, 20))

    # Print a line of dashes ("-") that matches the width of the terminal
    print("-" * terminal_size.columns)
    
liner()
# Configure logging
# logging.basicConfig(filename='ssh_manager.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure logging to output to both file and console
def setup_logging():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    user_message_format = '%(message)s'

    # File Handler - for log file
    file_handler = logging.FileHandler('ssh_manager.log')
    file_handler.setFormatter(logging.Formatter(log_format))
    file_handler.setLevel(logging.DEBUG)

    # Stream Handler - for console output
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter(user_message_format))
    stream_handler.setLevel(logging.INFO)

    # Get the root logger and add both handlers
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

# Call the function to set up logging at the start of your script
setup_logging()



# Global Variables:
# Fernet key variable 
cached_fernet_key = None


# Function to define read_fernet_key function
def read_fernet_key(keyfile):
    # Store the key in the cached_fernet_key variable
    global cached_fernet_key
    if cached_fernet_key is not None:
        return Fernet(cached_fernet_key)

    try:
        with open(keyfile, 'rb') as key_file:
            cached_fernet_key = key_file.read()
        return Fernet(cached_fernet_key)
    except FileNotFoundError:
        print(f'Fernet key file "{keyfile}" not found. Please generate a key first.')
        exit(1)


# Function to decrypt passwords:
def decrypt_password(encrypted_password, keyfile):
    fernet = read_fernet_key(keyfile)
    try:
        return fernet.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        logging.error(f"Decryption error for password: {e}")
        return None


# Function to read the CSV file and decode passwords
def read_csv(csv_file, keyfile):
    data = []
    try:
        with open(csv_file, 'r') as file:
            reader = csv.reader(file)
            next(reader)  # Skip the header row
            for row in reader:
                host, port, username, encrypted_password = row
                password = decrypt_password(encrypted_password, keyfile)
                if password is None:
                    logging.error(f'Decryption failed for host {host}. Skipping this entry.')
                    continue
                data.append((host, int(port), username, password))
        return data
    except Exception as e:
        logging.error(f'Error reading CSV file: {e}')
        return []


# Function to remove duplicate SSH keys from ~/.ssh/authorized_keys on remote hosts
def clean_duplicate_ssh_keys(host, port, username, password):
    try:
        # Start an SSH session to the remote host
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no","UserKnownHostsFile": "/dev/null"})
        s.login(host, username, password, port=int(port), auto_prompt_reset=False)

        # Command to remove duplicate SSH keys
        # This command sorts the authorized_keys file and removes duplicate lines
        command = "unset HISTFILE && awk '!seen[$0]++' ~/.ssh/authorized_keys > /tmp/authorized_keys && mv /tmp/authorized_keys ~/.ssh/authorized_keys"
        s.sendline(command)
        s.prompt()  # Wait for the command to complete

        logging.info(f"Duplicate SSH keys cleaned from {host}:{port}")
        s.logout()
    except pxssh.ExceptionPxssh as e:
        logging.error(f"pxssh failed on login. {e}")
    except Exception as e:
        logging.error(f"Error cleaning duplicate SSH keys from {host}:{port}: {e}")


# Function to read the public key from the file
def get_public_key(ssh_identity_path):
    ssh_public_key_path = f'{ssh_identity_path}.pub'
    if os.path.exists(ssh_identity_path) and os.path.exists(ssh_public_key_path):
        with open(ssh_public_key_path, 'r') as file:
            ssh_public_key = file.read().strip()
        file.close()
        logging.info(f'Successfully retrieved ssh public key contents: {ssh_public_key_path}')
        return(ssh_public_key)
    else:
        logging.error(f'Please ensure public key exists: {ssh_public_key_path}')
        

# Function to add SSH keys to remote hosts:
def add_ssh_key(host, port, username, password, ssh_identity_path):
    try:
        # Retrieve public key from get_public_key
        public_key = get_public_key(ssh_identity_path)
        
        # Start an SSH session to the remote host
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no","UserKnownHostsFile": "/dev/null"})
        s.login(host, username, password, port=int(port), auto_prompt_reset=False)

        # Command to add the public key to authorized_keys
        command = f"unset HISTFILE && mkdir -p ~/.ssh && echo '{public_key}' >> ~/.ssh/authorized_keys"
        s.sendline(command)
        s.prompt()  # Wait for the command to complete
        logging.info(f"SSH key copied to {host}:{port}")
        s.logout()
    except pxssh.ExceptionPxssh as e:
        logging.error(f"pxssh failed on login. {e}")
    except Exception as e:
        logging.error(f"Error copying SSH key to {host}:{port}: {e}")


def remove_ssh_key(host, port, username, password, ssh_identity_path, remove_all=False):
    try:
        # Start an SSH session to the remote host
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no","UserKnownHostsFile": "/dev/null"})
        s.login(host, username, password, port=int(port), auto_prompt_reset=False)
        if remove_all:
            logging.info(f"Removing authorized_keys from remote host(s)")
            # Command to remove ALL public keys from authorized_keys:
            command = f"unset HISTFILE && rm -rf ~/.ssh/authorized_keys"
        else:
            # Read the public key from the file
            public_key = get_public_key(ssh_identity_path)
            logging.info(f"Removing {ssh_identity_path} from authorized_keys on remote host(s)")
            # Command to remove the specified public key from authorized_keys
            command = f"unset HISTFILE && grep -v '{public_key}' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys_tmp && mv ~/.ssh/authorized_keys_tmp ~/.ssh/authorized_keys"
        s.sendline(command)
        s.prompt()  # Wait for it...

        logging.info(f"SSH key removed from {host}:{port}")
        s.logout()
    except pxssh.ExceptionPxssh as e:
        logging.error(f"pxssh failed on login. {e}")
    except Exception as e:
        logging.error(f"Error removing SSH key from {host}:{port}: {e}")


def verify_ssh(host, port, username, password, ssh_identity_path=None):
    try:
        # If an SSH key is provided and exists, set the IdentityFile option
        if ssh_identity_path and os.path.exists(ssh_identity_path):
            try:
                logging.debug(f"Attempting to connect to {host}:{port} using SSH key")
                s = pxssh.pxssh(options={"StrictHostKeyChecking": "no","UserKnownHostsFile": "/dev/null", 'IdentityFile': ssh_identity_path})
                #s = pxssh.pxssh(options={'IdentityFile': ssh_identity_path})
                s.login(host, username, port=int(port), auto_prompt_reset=False)
                logging.info(f"Successfully connected to {host}:{port} using SSH key")
                s.logout()
                return
            except pxssh.ExceptionPxssh as e:
                logging.info(f"SSH key login failed, falling back to password for {host}:{port}. Error: {e}")
                s = pxssh.pxssh(options={"StrictHostKeyChecking": "no","UserKnownHostsFile": "/dev/null"})
        else:
            s = pxssh.pxssh(options={"StrictHostKeyChecking": "no","UserKnownHostsFile": "/dev/null"})

        # Attempt to log in with password
        logging.debug(f"Attempting to connect to {host}:{port} using password")
        s.login(host, username, password=password, port=int(port), auto_prompt_reset=False)
        logging.info(f"Successfully connected to {host}:{port} using password")
        s.logout()
    except pxssh.ExceptionPxssh as e:
        logging.error(f"pxssh failed on login to {host}:{port}. {e}")
        s.close()
    except Exception as e:
        logging.error(f"Error connecting to {host}:{port}: {e}")
        s.close()


def verify_ssh_fail(host, port, username, password, ssh_identity_path=None):
    if ssh_identity_path:
        ssh_public_key = f'{ssh_identity_path}.pub'
    try:
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no","UserKnownHostsFile": "/dev/null"})
        # If an SSH key is provided and exists, set the IdentityFile option
        if ssh_identity_path and os.path.exists(ssh_identity_path):
            s.options['IdentityFile'] = ssh_identity_path

        # Attempt to log in using the SSH key or password
        if ssh_identity_path and os.path.exists(ssh_identity_path):
            try:
                s.login(host, username, port=int(port), auto_prompt_reset=False)
                logging.info(f"Successfully connected to {host}:{port} using SSH key")
                s.logout()
                return
            except pxssh.ExceptionPxssh as e:
                logging.info(f"SSH key login failed, falling back to password for {host}:{port}. Error: {e}")

        # If CLI credentials are used or SSH key login failed, use password
        # if use_cli_credentials:
        #    password = getpass.getpass(prompt="Enter SSH password: ")

        s.login(host, username, password=password, port=int(port), auto_prompt_reset=False)
        logging.info(f"Successfully connected to {host}:{port} using password")
        s.logout()
    except pxssh.ExceptionPxssh as e:
        logging.error(f"pxssh failed on login to {host}:{port}. {e}")
        s.close()
    except Exception as e:
        logging.error(f"Error connecting to {host}:{port}: {e}")
        s.close()


# Verify basic port connectivity to remote host
def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, port))
        logging.info(f'Port {port} is open on {host}')
    except Exception as e:
        logging.error(f'Port {port} is closed on {host}: {e}')


def examples():
    examples = f"""
Notes:
Key files are generated by the accompanying "inventory-manager" script. 


Advice: 

One functional argument (--add, --remove, --verify, or --clean) should be used for any given operation.

--identity is mandatory for any --add, --remove, or --verify operations, as we need to know which key is being used

--key is mandatory only if decrypting the password stored in a CSV file

--csv is mandatory only if a --host is not defined

--host overrides the CSV function


Examples and Additional Help:
Add a key to hosts in CSV:

# This example is using the default CSV "hosts.csv" which has its passwords encrypted with a default key "key.txt"

# Effectively, these commands do exactly the same thing:
{appname} --identity ~/.ssh/id_ed25519 --add
{appname} --identity ~/.ssh/id_ed25519 --csv hosts.csv --key key.txt --add

# This example is using a user-specified CSV file and encryption key file to Verify SSH key & password access
{appname} --identity ~/.ssh/id_ecdsa --csv hosts-new.csv --key key-new.txt --verify

# This command will remove the defined SSH identity from the hosts defined in the hosts-new.csv file, which may be unlocked using the key-new.txt file:
{appname} --identity ~/.ssh/id_ecdsa --csv hosts-new.csv --key key-new.txt --remove

# This command works effectively like "ssh-copy-id -i ~/.ssh/id_ecdsa superuser@192.1268.12.34" and that is essentially what it's doing:
{appname} --identity ~/.ssh/id_ecdsa --host 192.1268.12.34 --username superuser --add

# This command is used to verify a specific key is installed on a host,
{appname} --identity ~/.ssh/id_ed25519 --host 192.168.12.34 --verify --username superuser 
{appname} --identity ~/.ssh/id_ed25519 --host 192.168.12.34 --username superuser --add
{appname} --identity ~/.ssh/id_ed25519 --csv hosts.csv --key key.txt --host 192.168.12.34 --username superuser --verify


"""
    print(examples)


def helpandexit(parser):
    print('')
    parser.print_help()
    exit(1)

# Main function to perform tasks based on user-specified operations
def main():
    parser = argparse.ArgumentParser(description='Manage SSH keys for multiple hosts from a CSV inventory file.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # Let's add some additional help 
    # Operational flags
    parser.add_argument('--examples', action='store_true', help='(optional) Display examples')
    parser.add_argument('--add', action='store_true', help='(optional) Add SSH keys to remote hosts')
    parser.add_argument('--clean', action='store_true', help='(optional) Clean duplicate SSH keys from remote hosts')
    parser.add_argument('--remove', action='store_true', help='(optional) Remove SSH key from remote hosts')
    parser.add_argument('--removeall', action='store_true', help='(optional) Remove ALL SSH keys from remote hosts (This may be DANGEROUS!)')
    parser.add_argument('--verify', action='store_true', help='(optional) Verify SSH connectivity to remote hosts. If key is successful, password is skipped. If key fails, password is attempted.')
    
    # SSH parameters
    parser.add_argument('--username', type=str, help='(optional) SSH username (overrides CSV)')
    parser.add_argument('--identity', type=str, help='(optional) Path to SSH public key')
    parser.add_argument('--port', type=int, default=22, help='(optional) SSH port, default is 22')
    parser.add_argument('--host', type=str, default="all", help='(optional) Specify a single host on which to perform SSH add, clean, remove, removeall, or verify operation')
    
    # CSV file
    parser.add_argument('--csv', type=str, default='hosts.csv', required=False, help='Path to CSV file with host information')
    
    # Fernet key file
    parser.add_argument('--key', type=str, default='key.txt', required=False, help='Path to Fernet key file for decryption')
    
    args = parser.parse_args()
    
    # Check if no arguments were provided
    if len(sys.argv) == 1:
        parser.print_help()
        liner()
        examples()
        sys.exit(1)
    
    # Display example usage:
    if args.examples:
        examples()
        exit(0)
    
    try:
        if not args.verify and not args.add and not args.remove and not args.clean:
            logging.error("No operation specified. Use --add, --clean, --remove, or --verify.")
            helpandexit(parser)
        
        if args.verify and not args.identity:
            logging.info(f'Password will be used as SSH identity was not specified')
        
        # identity file must be specified for all uses of --add or --remove (including --removeall)
        if args.add or args.remove:
            if not args.identity:
                logging.error(f'SSH private key (--identity) must be defined to add key to remote host(s)')
                helpandexit(parser)
        
        # removall flag must be used with remove so as to prevent accidental removal of all SSH keys from specified hosts
        if args.removeall and not args.remove:
            logging.error(f'--removall must only be used in conjunction with --remove ')
            helpandexit(parser)
        
        if args.identity:
            if args.identity.endswith('.pub'):
                logging.error(f'SSH Identity should not be a public key: {args.identity}')
                identity = args.identity
                helpandexit(parser)
            else:
                identity = args.identity
            # Verify path exists for both private and public keys:
            if not os.path.exists(args.identity):
                logging(f'SSH Identity path is invalid: {args.identity}\nPlease verify the path and re-run ')
                helpandexit(parser)
            if not os.path.exists(f'{args.identity}.pub'):
                logging(f'SSH Public key does not exist for identity: {args.identity}\nPlease verify the path and re-run ')
                helpandexit(parser)
        
        # Check if the username is provided via command line
        cli_username = args.username
        cli_password = None
        port = args.port
        if cli_username:
            cli_password = getpass.getpass(prompt="Enter SSH password: ")
        
        if args.host != 'all':
            if args.csv and args.key:
                logging.info(f'Individual --host overrides --csv operations')
            print(f'Specific host: {args.host}')
            if not args.username:
                logging.debug(f'Prompting for SSH username')
                cli_username = str(input(f'{args.host} SSH username: '))
                logging.debug(f'Received "{cli_username}" from user input')
            if not cli_password:
                logging.debug(f'Prompting for SSH password')
                cli_password = getpass.getpass(prompt=f'{args.host} SSH password: ')
                logging.debug(f'Received password (not shown) from user input')
            host_data = [(args.host, port, cli_username, cli_password)]
        else:
            # Read hosts data from CSV
            host_data = read_csv(args.csv, args.key)

        if not host_data:
            logging.error('No host data found in the CSV file or decryption failed.')
            return
        
        # Perform operations based on the command-line arguments
        for host, port, username, decrypted_password in host_data:
            # Override username and password if provided via command line
            if cli_username:
                username = cli_username
                decrypted_password = cli_password
            if args.add:
                logging.debug(f'Attempting to perform --add operation for {username}@{host}:{port}')
                add_ssh_key(host, port, username, decrypted_password, args.identity)
                logging.debug(f'Attempting to perform --clean operation for {username}@{host}:{port}')
                clean_duplicate_ssh_keys(host, port, username, decrypted_password)
                logging.debug(f'--clean operation completed for {username}@{host}:{port}')
            elif args.clean:
                logging.debug(f'Attempting to perform --clean operation for {username}@{host}:{port}')
                clean_duplicate_ssh_keys(host, port, username, decrypted_password)
                logging.debug(f'--clean operation completed for {username}@{host}:{port}')
            elif args.remove:
                logging.debug(f'Attempting to perform --remove operation for {username}@{host}:{port}')
                remove_ssh_key(host, port, username, decrypted_password, args.identity, False)
                logging.debug(f'--remove operation completed for {username}@{host}:{port}')
            elif args.removeall:
                logging.debug(f'Attempting to perform --removeall operation for {username}@{host}:{port}')
                remove_ssh_key(host, port, username, decrypted_password, args.identity, True)
                logging.debug(f'--removeall operation completed for {username}@{host}:{port}')
            elif args.verify:
                logging.debug(f'Attempting to perform --verify operation for {username}@{host}:{port}')
                verify_ssh(host, port, username, decrypted_password, args.identity)
                logging.debug(f'--verify operation completed for {username}@{host}:{port}')
            else:
                logging.error("No operation specified. Use --add, --clean, --remove, or --verify.")
                helpandexit(parser)
    except KeyboardInterrupt:
        logging.error(f'User cancelled operation')

if __name__ == '__main__':
    main()


# Disabled Strict Hostkey checking:
# s = pxssh.pxssh(options={"StrictHostKeyChecking": "no","UserKnownHostsFile": "/dev/null"})