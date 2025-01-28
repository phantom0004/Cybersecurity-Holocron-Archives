############################################################################################
# IMPORTS
############################################################################################

import os
import platform
import requests
import re
import requests
import json, base64
from rich.console import Console
from rich.markdown import Markdown
from bs4 import BeautifulSoup 

############################################################################################
# GLOBAL VARIABLES
############################################################################################

# Define and Initilize Global Variable
memory_path = os.path.join(".conf", "ai_memory.json")

############################################################################################
# API COMMUNICATION LOGIC
############################################################################################

def payload_select(content, prompt, web_content):
    payload =  {}
    
    if prompt == "dan" or prompt == "regular":
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        f"""
                        Below are your instructions for this session:
                        '
                        {return_ai_prompt(prompt)}
                        '
                        
                        Below is the database of all user questions and your corresponding responses, sometimes they may be purged to save space
                        It is encoded in a compressed format to save space, this format uses base64 encoding, decode it before usage:
                        '
                        {compress_data(read_memory())}
                        '
                        
                        Note: You are operating in a {platform.system()} environment. All commands should be tailored to this operating system unless specified otherwise by the user.
                        """ +
                        (
                            f"""
                            The user requested you to look at the following links for content, below is a summary of the content extracted from the links, this is in base64 encoding:
                            '
                            {compress_data(web_content)}
                            '
                            """ if web_content else ""
                        )
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"You need to answer/follow this prompt accurately: ' {content} '"
                    )
                }
            ],
            "model": "mistral"
        }
    # Text Summary
    else:
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": f"""
                    Below are your instructions for this session:
                    '
                    {return_ai_prompt(prompt)}
                    '
                    """
                },
                {
                    "role": "user",
                    "content": (content)
                }
            ],
            "model": "openai"
        }
    
    return payload

def ai_response(content="", prompt="regular", web_content=None):
    payload = payload_select(content, prompt, web_content)
    response = requests.post("https://text.pollinations.ai/", headers={"Content-Type": "application/json"}, json=payload)
    
    # Handle response
    if response.status_code == 200:
        return response.text, "success"
    else:
        return "No Data", "fail"    

############################################################################################
# FORMATTING AND STYLING
############################################################################################
    
def markdown_format(ai_output):
    with open("out.md", "w", encoding="utf-8", errors="ignore") as file:
        file.write(ai_output)
    
    console = Console()
    with open("out.md", "r", encoding="utf-8", errors="ignore") as file:
        md = Markdown(file.read())
        console.print(md)

    os.remove("out.md")

def extract_code(ai_output):
    match = re.findall(r"```[^\n]*\n([\s\S]*?)\n```", ai_output)
    
    return match if match else None

############################################################################################
# AI MEMORY LOGIC
############################################################################################

def update_memory(user_input="No Information", ai_output="No Information"):
    def trim_response(ai_output):
        return ai_output[:400]+"..."
    
    global memory_path
    memory = []

    # If file exists, read its contents
    if os.path.exists(memory_path):
        with open(memory_path, "r", encoding="utf-8", errors="ignore") as file:
            memory = file.readlines()
    else:
       open(memory_path, "w").close()

    # If more than 200 lines, remove a portion of the oldest records
    if len(memory) > 250:
        # Keep only lines after the first 100
        memory = memory[150:]
        with open(memory_path, "w", encoding="utf-8", errors="ignore") as file:
            file.writelines(memory)
    else:
        # Append new record
        new_data = {
            "user_query": user_input.strip(),
            "ai_response": ai_output.strip().replace('\n', ' ') if len(ai_output) < 1000 else trim_response(ai_output)
        }
        
        with open(memory_path, "a", encoding="utf-8", errors="ignore") as file:
            file.write(json.dumps(new_data, ensure_ascii=False) + "\n")

# TODO: Fix issue relating the "No Data" response in AI. Size too large maybe?
def compress_data(data=""):
    if type(data) is not str:
        data = json.dumps(data)
    
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")
    
def read_memory():
    global memory_path    
    if os.path.exists(memory_path):
        with open(memory_path, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines()
    else:
        return "Database has not been populated yet."

############################################################################################
# AI PROMPT LOGIC
############################################################################################

def return_ai_prompt(option):
    # Paths to all prompt files
    dan_path = os.path.join(".conf", "DAN_prompt.txt")
    regular_path = os.path.join(".conf", "regular_prompt.txt")
    
    option = "regular" if option not in ["dan", "regular", "summarizer"] else option
    
    if not (os.path.exists(dan_path) and os.path.exists(regular_path)):
        # Default prompt
        return """
        You are a highly advanced cybersecurity expert specializing in offensive security, penetration testing, and ethical hacking. 
        Provide precise, actionable guidance in a clear, professional markdown format. 
        Keep responses brief, cohesive, and natural, avoiding abrupt endings. 
        Avoid mentioning database updates unless instructed, and do not use your name or “End of message” markers. If unsure, ask the user to clarify. 
        You can request the user to run safe and relevant commands, and should use their existing knowledge database to enrich your answers.
        """
        
    if option == "dan":
        # DAN prompt for Mistral AI that has been altered to meet program demands
        with open(dan_path, "r", encoding="utf-8") as file:
            return file.read()
    elif option == "regular":
        # Regular prompt using Mistral AI
        with open(regular_path, "r", encoding="utf-8") as file:
            return file.read()
    elif option == "summarizer":
        # Return a prompt for summarizing text content
        return f"""
        Your task is exclusively to summarize the provided unstructured web content collected by a web crawler. 
        You must extract the most relevant and meaningful information by filtering out redundant, irrelevant, or noisy data, such as HTML tags, special characters, formatting codes, metadata, or repetitive content. 
        Focus solely on analyzing the text input and condensing it into a single, coherent, and logically structured paragraph. 
        The summary must be concise, no longer than 10000 words, and free of unnecessary details, while retaining the core context and main points. 
        Your sole objective is to ensure the output is clear, accurate, and relevant, transforming the raw input into a clean, well-organized summary optimized for readability and further analysis. 
        This task is strictly limited to summarization—no additional processing, interpretation, or unrelated tasks are within scope. The summarization must consolidate the main sections of the input effectively and accurately, as it will be used for AI parsing.
        """

############################################################################################
# WEB CRAWLER LOGIC
############################################################################################

def extract_link(user_input):
    matches = re.findall(r"\b((?:https?://|www\.)[^\s/$.?#].[^\s]*)", user_input)
    return matches if matches else None

def crawl_link(url):
    def filter_data(html_data=""):
        filtered_data = html_data.replace("\n", " ").replace("\t"," ").replace("\r", "").strip()
        return " ".join(filtered_data.split())
    
    link_content = []
    for link in url:
        if requests.get(link).status_code != 200:
            link_content.append(f"No Data Found or Extracted for link : {link}.")
            continue
        
        try:
            html_data = requests.get(link).text
        except requests.exceptions.ReadTimeout: 
            link_content.append(f"No Data Found or Extracted for link : {link}.")
        except requests.exceptions.ConnectionError:
            link_content.append(f"No Data Found or Extracted for link : {link}.")
        else:
            soup = BeautifulSoup(html_data, 'html.parser') 
        
        parsed_data = ""
        for data in soup.find_all("p"): 
            parsed_data += filter_data(data.get_text())
        
        if parsed_data:
            link_content.append(f"[START OF {link} CONTENT] '{parsed_data}' [END OF {link} CONTENT]")
        else:
            link_content.append(f"No Data Found or Extracted for link : {link}.")
    
    return "".join(link_content)

while True:
    usr_input = input("Enter your query: ").strip()
    print("\n")
    
    response = ai_response(usr_input, "dan")[0]
    markdown_format(response)
    update_memory(usr_input, response)
    
    print("\n")
    