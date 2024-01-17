#!/usr/bin/env python3
# Version: 0.0.11
# Last modified: 2024-01-16
# Description: Application to manage user credentials
version = 20240116001

import csv
import argparse
import os
import getpass
import base64
import sys
from cryptography.fernet import Fernet

# Global Variables:
# Fernet key variable 
cached_fernet_key = None

# Define read_fernet_key function to better handle repetition of keyfile reading
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

# Encrypt passwords function:
def encrypt_password(password, keyfile):
    fernet = read_fernet_key(keyfile)
    return fernet.encrypt(password.encode()).decode()


# Decrypt passwords function:
def decrypt_password(encrypted_password, keyfile):
    # Read the Fernet key using read_fernet_key function to see if global variable is set:
    fernet = read_fernet_key(keyfile)
    try:
        return fernet.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        return "Decryption error: " + str(e)


def encode_base64(data):
	return base64.b64encode(data.encode()).decode()


def decode_base64(encoded_data):
	return base64.b64decode(encoded_data).decode()


def read_key(keyfile):
	with open(keyfile, 'r') as key:
		line = key.readline()
		# print(decode_base64(line))
		key.close()
	print(f'Read key from {keyfile}')


# Define a function to generate a Fernet key and store it in a file
def generate_fernet_key(keyfile):
	key = Fernet.generate_key()
	with open(keyfile, 'wb') as key_file:
		key_file.write(key)
	print(f'Fernet key has been generated and saved to {keyfile}')


# Verify the TCP port number for SSH
def validate_port(port):
	try:
		port = int(port)
		if 1 <= port <= 65535:
			return port
		else:
			raise ValueError("Port must be in the range 1-65535.")
	except ValueError:
		raise ValueError("Invalid port. Please enter a valid integer between 1 and 65535.")


def read_csv_data(csv_filename):
	data = []
	try:
		with open(csv_filename, 'r') as csv_file:
			csv_reader = csv.DictReader(csv_file)
			for row in csv_reader:
				data.append(row)
	except FileNotFoundError:
		pass  # CSV file not found, return an empty list
	return data

def write_csv_data(csv_filename, data):
    try:
        with open(csv_filename, 'w', newline='') as csv_file:
            fieldnames = ['host', 'port', 'user', 'password']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerows(data)
        print(f"Data written to '{csv_filename}' successfully.")
    except Exception as e:
        print(f"An error occurred while writing to '{csv_filename}': {e}")

# Inside the add_host function
def add_host(csv_filename, host=None, port=None, user=None, keyfile="key.txt", password=None):
	# Prompt for host if not provided by the CLI:
	if host is None:
		host = input("Host Address: ")

	# Prompt for SSH Port with a default value:
	if port is None:
		port = input("SSH Port (default is 22): ")
		if not port:
			port = 22
		else:
			# Validate SSH Port:
			try:
				port = validate_port(port)
			except ValueError as e:
				print(e)
				return  # Exit the function if port validation fails.

	# Prompt for username if not provided by the CLI:
	if user is None:
		user = input(f"Username for {host}: ")

	# Prompt for the password if not provided via CLI
	if password is None:
		password = getpass.getpass(f"Enter the password for {user}@{host}: ")

	# Encrypt the password
	encrypted_password = encrypt_password(password, keyfile)
	print(f"Encrypted Password: {encrypted_password}")	

	# Prepare the data
	data = [{"host": host, "port": port, "user": user, "password": encrypted_password}]

	# Read existing data from the CSV file
	existing_data = read_csv_data(csv_filename)

	# Check if an entry with the same host, port, and user already exists
	existing_entry = next(
		(
			entry
			for entry in existing_data
			if entry['host'] == host and entry['port'] == str(port) and entry['user'] == user
		),
		None,
	)

	# If a duplicate entry exists, inform the user and do not add it
	if existing_entry:
		print(f"An entry for Host: '{host}', Port: '{port}', User: '{user}' already exists. Skipping.")
	else:
		# Otherwise, add the new entry
		existing_data.extend(data)
		write_csv_data(csv_filename, existing_data)

	print(f"CSV file '{csv_filename}' with credentials has been created/appended.")

# Inside the update_host function
def update_host(csv_filename, host, port, user, keyfile, password=None):
	if host is None:
		print("Host needs to be specified via --host argument")
		exit(1)

	print(f"Updating CSV '{csv_filename}' entry for Host: '{host}'")

	# Prompt for username if not provided by the CLI:
	if user is None:
		user = input(f"Enter the username for {host}: ")

	# Prompt for the password if not provided via CLI
	if password is None:
		password = getpass.getpass(f"Enter the password for {user}@{host}: ")

	# Encrypt the password
	encrypted_password = encrypt_password(password, keyfile)

	# Read existing data from the CSV file
	existing_data = read_csv_data(csv_filename)

	# Check if an entry with the same host, port, and user exists
	existing_entry = next(
		(
			entry
			for entry in existing_data
			if entry['host'] == host and entry['port'] == str(port) and entry['user'] == user
		),
		None,
	)

	# If a duplicate entry exists, update it; otherwise, add a new entry
	if existing_entry:
		existing_entry.update({"password": encrypted_password.decode()})
		write_csv_data(csv_filename, existing_data)
		print(f"Updated CSV entry for Host: '{host}'")
	else:
		print(f"No existing entry found for Host: '{host}'. Adding a new entry.")
		add_host(csv_filename, host, port, user, keyfile, password)


def remove_host(csv_filename, host, port, user=None):
	print(f"Removing CSV entry '{csv_filename}' for Host: '{host}:{port}'")

	# Read existing data from the CSV file
	existing_data = []
	if os.path.exists(csv_filename):
		with open(csv_filename, 'r') as csv_file:
			csv_reader = csv.DictReader(csv_file)
			for row in csv_reader:
				existing_data.append(row)

	# Remove the specified entry
	existing_data = [
		entry for entry in existing_data
		if not (
			entry['host'] == host
			and entry['port'] == str(port)
			and (user is None or entry['user'] == user)
		)
	]

	# Write the updated data to the CSV file
	with open(csv_filename, 'w', newline='') as csv_file:
		fieldnames = ['host', 'port', 'user', 'password']
		writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
		writer.writeheader()
		writer.writerows(existing_data)

	print(f"Removed CSV entry for Host: '{host}'")


def view_host(csv_filename, host, port, user, keyfile, decode_password=False):
	# Initialize Fernet with the key
	# Read the Fernet key using read_fernet_key function to see if global variable is set:	
	fernet = read_fernet_key(keyfile)
	print(f"Viewing CSV entry '{csv_filename}' for Host: '{host}'")
	with open(csv_filename, 'r') as csv_file:
		csv_reader = csv.DictReader(csv_file)
		# Match all hosts:
		if host == "All":
			# print("Viewing all hosts")
			for row in csv_reader:
				if decode_password:
					decrypted_password = decrypt_password(row['password'], keyfile)
				else:
					decrypted_password = "******** (encrypted)"
				print(f"Host: {row['host']}, Port: {row['port']}, User: {row['user']}, Password: {decrypted_password}")
		else:
			for row in csv_reader:
				# Host and User match:
				if row['host'] == host and row['user'] == user:
					# print("Host & User match:")
					if decode_password:
						decrypted_password = decrypt_password(row['password'], keyfile)
					else:
						decrypted_password = "******** (encrypted)"
					print(f"Host: {row['host']}, Port: {row['port']}, User: {row['user']}, Password: {decrypted_password}")
				# Host-only match:
				# print("Host & User match:")
				elif row['host'] == host and user is None:
					if decode_password:
						decrypted_password = decrypt_password(row['password'], keyfile)
					else:
						decrypted_password = "******** (encrypted)"
					# print("Host-only match")
					print(
						f"Host: {row['host']}, Port: {row['port']}, User: {row['user']}, Password: {decrypted_password}")
				else:
					continue


def deduplicate_csv_file(csv_filename):
    data = read_csv_data(csv_filename)
    if not data:
        return

    # Identify and remove duplicate entries
    unique_data = []
    seen_entries = set()

    for entry in data:
        entry_key = (entry['host'], entry['port'], entry['user'])
        if entry_key not in seen_entries:
            seen_entries.add(entry_key)
            unique_data.append(entry)

    # Write the deduplicated data back to the CSV file
    with open(csv_filename, 'w', newline='') as csv_file:
        fieldnames = ['host', 'port', 'user', 'password']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(unique_data)

    print(f"Deduplicated CSV file '{csv_filename}'")


def main():
    parser = argparse.ArgumentParser(description="Manage user credentials in a CSV file.")
    parser.add_argument("--csv", default='hosts.csv', help="CSV File name")
    
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--newkey", action="store_true", help="Generate a new Fernet key")
    operations.add_argument("--add", action="store_true", help="Add host entry")
    operations.add_argument("--remove", action="store_true", help="Remove host entry")
    operations.add_argument("--update", action="store_true", help="Update host entry")
    operations.add_argument("--view", action="store_true", help="View host entry")
    operations.add_argument("--deduplicate", action="store_true", help="Deduplicate the CSV file")

    parser.add_argument("--host", help="SSH host address")
    parser.add_argument("--port", default=22, type=int, help="SSH port")
    parser.add_argument("--user", default=None, help="SSH username")
    parser.add_argument("--password", default=None, help="Password (plaintext) (please use with care)")
    parser.add_argument("--decrypt", action="store_true", help="Decode password when viewing")
    parser.add_argument("--key", default="key.txt", help="Define security key (base64-encoded encryption key for securely storing passwords in CSV file.)")
    
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()
    
    if args.version:
        print(f'Application version: {version}')
        exit(0)
    if args.newkey:
        newkey = args.key
        if os.path.exists(newkey):
            print(f'Key file exists: {newkey}')
            print("Exiting.")
            exit(1)
        else:
            print(f'Creating new encryption key: {newkey}')
            generate_fernet_key(newkey)
            print(f'Key file created: {newkey}')
            exit(0)
    csv_filename = args.csv
    host = args.host
    port = args.port
    user = args.user
    password = args.password
    keyfile = args.key
    if args.deduplicate:
        print(f'Deduplicating {csv_filename}')
        deduplicate_csv_file(csv_filename)
        print(f'Deduplication of {csv_filename} completed')
        return

    if args.view:
        view_host(csv_filename, host, port, user, keyfile, decode_password=args.decrypt)

    if args.add:
        add_host(csv_filename, host, port, user, keyfile, password)
    
    if args.update:
        update_host(csv_filename, host, port, user, keyfile, password)

    if args.remove:
        remove_host(csv_filename, host, port, user)

if __name__ == "__main__":
    main()