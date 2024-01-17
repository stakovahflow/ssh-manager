# ssh-manager
ssh host, username, password manager application and accompanying ssh key management application

Applications:

	1. inventory-manager.py: manages an inventory database (CSV) with Fermet symetric key encryption of passwords
 
	2. ssh-manager.py: manages adding, removing, verifying, etc., of SSH credentials from CSV file created by inventory-manager.py

Stay tuned for news!
#################################################################################

# Create new default Fermet keyfile:
    ./inventory-manager.py --newkey

# Create new default Fermet keyfile:
    ./inventory-manager.py --newkey --key custom-key.txt

# Add new entry for host "172.16.1.77" (will be prompted for username, password):
   ./inventory-manager.py --host 172.16.1.77 --add

# Add new entry for host "10.44.33.22" with username "superuser" using key file "custom-key.txt" and inventory file "custom-hosts.csv"::
    ./inventory-manager.py --key custom-key.txt --csv custom-hosts.csv --user superuser --pass Passw0rd123 --host 192.168.1.31 --add

# Add new entry for host "192.168.1.31" with username "superuser" using the default key (key.txt) and inventory file (hosts.csv) (will be prompted for password):
    ./inventory-manager.py --user superuser --host 192.168.1.31 --add

# Remove entry for host "10.44.33.22" with username "superuser" using key file "custom-key.txt" and inventory file "custom-hosts.csv":
    ./inventory-manager.py --key custom-key.txt --csv custom-hosts.csv --user superuser --host 10.44.33.22 --remove

# View all CSV file entries using default key (key.txt) and inventory file (hosts.csv):
    ./inventory-manager.py --view --host All

# View all entries, with decrypted password:
    ./inventory-manager.py --key key.txt --csv hosts.csv --view --host All --decrypt

# View entries for host "172.16.1.77" with decrypted password:
    ./inventory-manager.py --key key.txt --csv hosts.csv --view --host 172.16.1.77 --decrypt
    
# Add new entry for host "192.168.77.88" with SSH port "2222", using the default key (key.txt) and inventory file (hosts.csv) (will be prompted for username and password):
    ./inventory-manager.py --host 192.168.1.31 --port 2222 --add

