from flask import Flask, request, render_template
import socket
import subprocess
import re
import os
import time
import sqlite3
from termcolor import *

def create_sql_table():
    # Connect to in-memory database
    conn = sqlite3.connect('sql_injection_data.db') 
    c = conn.cursor()

    try:
        # Create the table with appropriate data types
        c.execute('''CREATE TABLE IF NOT EXISTS items (
                        ID INTEGER PRIMARY KEY AUTOINCREMENT,
                        item_name TEXT NOT NULL,
                        item_ID TEXT NOT NULL,
                        item_description TEXT NOT NULL
                    )''')
    except Exception as err:
       print(colored(f"\n[-] Unable to create SQL table! -> {err}\n", "red", attrs=["bold"]))

    # Insert 10 rows of test data
    test_data = [
        ("Apple", "123", "A bright red apple!"),
        ("Banana", "456", "A tasty banana!"),
        ("Orange", "789", "A yummy orange"),
        ("Grape", "012", "A cluster of sweet grapes"), 
        ("Mango", "345", "A tropical delight"),
        ("Strawberry", "678", "Small and sweet berries"),
        ("Watermelon", "901", "A refreshing summer fruit"),
        ("Pineapple", "234", "A spiky fruit with a juicy core"),
        ("Kiwi", "567", "A fuzzy fruit with a tart flavor"),
        ("Blueberry", "890", "Tiny blue berries with a burst of flavor")
    ]
    
    c.executemany("INSERT INTO items (item_name, item_ID, item_description) VALUES (?, ?, ?)", test_data)
    conn.commit()  # Save changes to the database
    print(colored("\n[!] SQL table created in memory with product items added\n", "yellow", attrs=["bold"]))
    conn.close()  # Close the connection

def sql_search_item(item_name, item_id):
    if not item_name or not item_id:
        return "No product Information, Missing Fields"
    else:
        conn = sqlite3.connect("sql_injection_data.db")
        c = conn.cursor()
        c.execute(f"SELECT item_description FROM items WHERE item_name = {item_name} AND item_id = {item_id}")
        result = c.fetchone()
        
        if not result:
            result = "No data"
            
        conn.close()
        return result

def banner():
    banner = colored("""
              _                                   _               __                          
 /\   /\_   _| |_ __   ___ _ __ __ ___      _____| |__           / _\ ___ _ ____   _____ _ __ 
 \ \ / / | | | | '_ \ / _ \ '__/ _` \ \ /\ / / _ \ '_ \   _____  \ \ / _ \ '__\ \ / / _ \ '__|
  \ V /| |_| | | | | |  __/ | | (_| |\ V  V /  __/ |_) | |_____| _\ \  __/ |   \ V /  __/ |   
   \_/  \__,_|_|_| |_|\___|_|  \__,_| \_/\_/ \___|_.__/          \__/\___|_|    \_/ \___|_|   
                                                                                                  
    """, "green")
    
    print(banner, "[+] Server has now started \n")
    
def clear_screen():
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For macOS and Linux
        os.system('clear')

def section_message(section_name):
    print(f"""
          \n
          ==========>
          SERVER LOGS FOR {section_name.upper()}
          ==========>
          \n
          """)

app = Flask(__name__)

@app.route("/")
def main():
    return render_template("index.html")

@app.route("/xss", methods=["GET", "POST"])
def xss_testing():
    username, comment = '', ''
    if request.method == "POST":
        username = request.form.get("username", "No value entered yet")
        comment = (request.form.get("comment", "No value entered yet")).strip()
    
    return render_template("xss-testing.html", username=username, comment=comment)

@app.route("/sql-injection", methods=["GET", "POST"])
def sql_injection_testing():
    create_sql_table()
    item_name, item_id = '', ''
    if request.method == "POST":
        item_name = request.form.get("item_name", "")
        item_id = request.form.get("item_ID", "")

    output = sql_search_item(item_name, item_id)
    print(output)
    return render_template("sql-injection-testing.html", item_name=item_name, item_ID=item_id)

@app.route("/brute-forcing", methods=["GET", "POST"])
def brute_force_testing():
    username, password = '', ''
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
    
    return render_template("brute-force-testing.html", username=username, password=password)
    
@app.route("/command-injection", methods=["GET", "POST"])
def command_injection_testing():
    ping_ip = ''
    output = ''    
    if request.method == "POST":
        ping_ip = request.form.get("ip_address", "").strip()
        
        output_regex = re.match("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$", ping_ip)
        if output_regex:
            try:
                output = subprocess.check_output(f"ping {ping_ip} -n 1", shell=True, universal_newlines=True)
            except subprocess.CalledProcessError as e:
                output = str(e)
        else:
            output = "Invalid IP entered! Please try again using a proper IPv4 format"
    
    return render_template("command-injection-testing.html", ping_ip=ping_ip, output=output)

if __name__ == "__main__":
    print("### SERVER SETUP ###")
    usr_choice = input("Enable debugging? Y/N : ").strip().upper()
    debug_flag = usr_choice == "Y"
    ip_addr = "127.0.0.1"

    ip_choice = input("\nChoose your networking choice : \n1) Run on private IP\n2) Run on localhost\n\nInput : ").strip()
    print()
        
    try:
        if ip_choice == "1":
            print("[+] Using Private IP")
            try:
                hostname = socket.gethostname()
                ip_addr = socket.gethostbyname(hostname)
            except Exception as err:
                exit(f"An error has occured when trying to aquire the private IP -> {err}")
        else:
            print("[+] Using Localhost")
    finally:
        print("Starting up server based on choices . . .")
        time.sleep(2)
        clear_screen()       
         
        banner()
        app.run(host=ip_addr, debug=debug_flag)