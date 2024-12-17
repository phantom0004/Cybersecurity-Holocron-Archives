![image](https://github.com/phantom0004/th3executor/assets/42916447/487d47d1-12e0-4083-8ae3-04e26d463c38)
# About Th3Executor

Th3Executor is a robust tool crafted specifically for penetration testers and security researchers. It offers a comprehensive framework for conducting a wide array of operations on remote systems. From gathering critical system information to establishing persistence and executing payloads, Th3Executor equips users with the necessary tools to navigate complex security scenarios.

With Th3Executor, users can seamlessly execute commands and deploy payloads on target systems, enabling them to assess and strengthen system defenses effectively. Whether it's reconnaissance, exploitation, or post-exploitation tasks, Th3Executor streamlines the process, allowing users to focus on their objectives with precision and efficiency.

## Features

- **Remote Execution:** Execute commands and scripts on remote systems.
- **System Information:** Gather detailed information about the target system, including OS version, IP address, and more.
- **Persistence:** Establish persistence on Windows systems by adding the script to the startup registry.
- **Payload Conversion:** Convert Python payloads to executable files for easier deployment.
- **Payload Obfuscation:** Obscure Python payloads to evade detection by antivirus software.
- **Reverse TCP Connections:** Establish reverse TCP connections remotely.
- **Screenshot Capturing:** Capture screenshots of the target machine's desktop.
- **Remote Shell Access:** Gain command-line access to target systems.
- **Keylogger Creation:** Create keyloggers to capture target keystrokes.
- **Robust Encyrption Algorithms** Secure communication with robust encryption.
- **Ability to change encyrption keys midconnection:** Dynamically update encryption keys during active connections.

## Snippet of main menu

![image](https://github.com/phantom0004/th3executor/assets/42916447/b75e7677-9309-4f3a-92bc-b299a2c938de)

## Usage

1. Begin by setting up the payload and server configurations using the setup.py script.
2. Start the `th3executor.py` server script.
3. Ensure the target runs either the converted executable or the python file.
4. Connect to the target system seamlessly.
5. Execute commands and payloads to achieve your objectives.

## How to run the setup and main program (server):
```bash
Setup: python3 executor_setup.py 
Main Program: python3 th3executor.py

**OPTIONAL (Usually for testing purposes)**
Payload: python3 payload.py
```

## Disclaimer

Th3Executor is intended for authorized penetration testing and security research purposes only. Misuse of this tool for malicious activities is prohibited. Use it responsibly and ethically.

## License

This project is licensed under the [MIT License](LICENSE).
