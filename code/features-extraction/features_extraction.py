
from typing import Literal
from search_in_file import parse_file, search_keyword_in_code
from calculate_entropy import extract_is_minified_feature
import logging
import os

import csv
import os

LOGֹ_FORMAT = "%(levelname)s, time: %(asctime)s , line: %(lineno)d- %(message)s "
# create and configure logger
logging.basicConfig(
    filename="features-extraction-logging.log", level=logging.INFO, filemode="w"
)
logger = logging.getLogger()


file_name = 'js_code_example'
root_node = parse_file(file_name)

def search_PII(root_node) -> Literal[1, 0]:
    """
    (1) Access to personally-identifying information (PII): creditcard numbers, passwords, and cookies
    TODO:
    * current situation: have only two keywords
    * what to improve: have more keywords after the data exploration
    """
    logging.info("start func: search_PII")

    keywords = ['screenshot', ['keypress', 'POST'], 'creditcard', 'cookies', 'passwords', 'appData']
    return general_search(root_node, keywords)
    
def search_file_sys_access(root_node) -> Literal[1, 0]:
    
    """
    (2) Access to specific system resources:
    (a) File-system access: reading and writing files
    """
    
    '''#(2)a
    File-system access: reading and writing files
    #require('fs') is the File System Library that provides a simple
    and convenient way to interact with the file system on the computer.
    It provides functions for reading and writing files,
    creating and deleting directories, and more.'''

    keywords = ['read','write','file', 'require("fs")']
    
    logging.info("start func: search_file_sys_access")

    return general_search(root_node, keywords)
    
def search_file_process_creation(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (b) Process creation: spawning new processes
    """

    '''
        #(2)b
    Process creation: spawning new processes

    #exec -> execute, used to run cmd commands on the device, including creation of new processes.

    #spawn -> The spawn keyword in JavaScript is used to start a new process in Node.js.
    It creates a new process and runs a specified command in that process.

    #fork -> The fork method in the child_process module in Node.js is used to create a new
    Node.js process that is a child of the current process. Unlike the spawn method,
    which creates a new process and runs a separate command, the fork method creates
    a new process that runs the same code as the parent process.

    #child_process -> The child_process module in Node.js is a module for creating and controlling
    child processes in a Node.js application. It provides a way to start new processes,
    run shell commands, and manage the communication between a Node.js process and its child processes.'''
    
    logging.info("start func: search_file_process_creation")
    keywords = ['exec', 'spawn', 'fork', 'thread', 'process', 'child_process']
    return general_search(root_node, keywords) 

def search_network_access(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (c)Network access: sending or receiving data
    """
    logging.info("start func: search_network_access_data")
    '''(2)c
    Network access: sending or receiving data
    #send -> we use send keyweord because when it comes to outward comminicaton, we expect to receive data,
    but it is very very unlikely that we will transfer data out from the device.
    thus we marked 'send' keyword'''
    

    keywords = ['send', 'export', 'upload' ,'post', 'XMLHttpRequest', 'submit']
    return general_search(root_node, keywords)     

def search_Cryptographic_functionality(root_node) -> Literal[1, 0]:
    """
    (3) Use of specific APIs 
    (a) Access to crypto functionality:
    """
    logging.info("start func: search_crypto_data")

    '''(3)(a) Cryptographic functionality
    mining: The process of finding a hash that meets certain criteria in a cryptocurrency network.'''
    keywords = ['crypto', 'mining']
    
    return general_search(root_node, keywords)

def search_data_encoding(root_node) -> Literal[1, 0]:
    """
    (3) Use of specific APIs
    (b) encoded data: find encoded data in the script
    """
    logging.info("start func: search_encoded_data")

    '''(3)(b) Data encoding using encodeURIComponent etc.
    #base64 -> common encoding method.

    #encodeURIComponent -> common encoding function with utf-8.

    #querystring -> This is a built-in Node.js library for working
    with query strings. It provides methods for encoding and decoding query strings.

    #qs: This is a popular library for encoding and decoding query strings in both
    the browser and Node.js. It provides a more powerful set of features compared
    to the built-in querystring library.

    #btoa and atob: These are global functions in JavaScript for
    base64 encoding and decoding respectively.

    #Buffer: This is a built-in class in Node.js for working with binary data.
    You can use the .toString('base64') method to encode binary data as a base64 string.

    #JSON.stringify: This is a built-in method in JavaScript for converting a JavaScript
    object to a JSON string. JSON is a widely used format for encoding data structures and exchanging data between client and server.'''

    keywords = ['encodeURIComponent', 'querystring', 'qs', 'base64', 'btoa', 'atob', 'Buffer', 'JSON.stringify']
    
    return general_search(root_node, keywords)


def search_dynamic_code_generation(root_node) -> Literal[1, 0]:
    """
    (3) encoded data: find encoded data in the script
    (c) search_dynamic_code_generation: run external scripts within the script
    """
    logging.info("start func: search_dynamic_code_generation")


    '''(3)(c) Dynamic code generation using eval, Function, etc.
    #eval -> a function that is used to dynamically execute the code defined in the string code.
    # Function -> Function constructor: This allows you to dynamically create a new function
    and execute it. The Function constructor takes a string of code as its
    argument and returns a reference to a new function that can be executed.'''
    keywords = ['eval', 'Function']
    
    return general_search(root_node, keywords)

def search_package_installation(root_node) -> Literal[1, 0]:
    """
    (4) search_package_installation: unautherized external package installation
    """
    logging.info("start func: search_dynamic_code_generation")

    '''(4) Use of package installation scripts
    #In npm, pre-install and post-install are scripts that can
    be defined in the scripts section of the package.json file.
    These scripts are executed before and after the installation of packages, respectively.'''
    keywords = ['preinstall', 'postinstall', 'npm install']

    return general_search(root_node, keywords)

def general_search(root_node,keywords) -> Literal[1, 0]:
    
    
    logging.info("start func: general_search")

     # Traverse the syntax tree and check for the specific line of code
    sub_keywords = {} # {index of the sublist in keywords: keyword, [words that found]}
    # for each sublist in keywords, add the index and the keyword
    for index, keyword in enumerate(keywords):
      if type(keyword) == list:
        sub_keywords[index] = [keyword, []]

    is_using = 0
    if search_keyword_in_code(root_node, keywords, sub_keywords):
        is_using = 1
    
    
    return is_using 
  
    
def search_minified_code(directory_path) -> Literal[1, 0]:
    """
    5
    Presence of minified code (to avoid detection) or binary files (such as binary executables)
    """
    logging.info("start func: search_minified_code")
    is_minified = extract_is_minified_feature(directory_path)
    
    return is_minified
            
def traverse_directory(root_dir: str) -> None:
    for dirname, subdirs, files in os.walk(root_dir):
        path_lst = dirname.split(os.path.sep)
        package_index = path_lst.index('benign') + 1
        for filename in files:
            if not filename.endswith(".js"):
                continue
            file_path = os.path.join(dirname, filename)
            package_name = path_lst[package_index]

            logging.debug('================================================')
            logging.debug(f"File path: {file_path}")
            logging.debug(f"Package name: {package_name}")
            logging.debug(f"filename: {filename}")
            


def gather_data(root_dir,trigger):
    all_list = []
    if trigger:
        all_list.append(['package','version','PII','file_sys_access','file_process_creation',
        'network_access','Cryptographic_functionality', 'data_encoding',
        'dynamic_code_generation','package_installation','label'])
    for folder in os.listdir(root_dir):

        folder_path = os.path.join(root_dir, folder)
        print(f"{folder}, {folder_path}\n")

        if os.path.isfolder(folder_path):
            print("yes")
            file_name = os.path.basename(folder_path)
            current_file_values = file_name.split('-v-')
            current_list = []
            current_list.append(current_file_values[0])
            current_list.append(current_file_values[1])
            for dirpath, dirnames, filenames in os.walk(folder_path):
                None
            current_list.append(search_PII(parse_file(folder_path)))
            current_list.append(search_file_sys_access(parse_file(folder_path)))
            current_list.append(search_file_process_creation(parse_file(folder_path)))
            current_list.append(search_network_access(parse_file(folder_path)))
            current_list.append(search_Cryptographic_functionality(parse_file(folder_path)))
            current_list.append(search_data_encoding(parse_file(folder_path)))
            current_list.append(search_dynamic_code_generation(parse_file(folder_path)))
            current_list.append(search_package_installation(parse_file(folder_path)))
            current_list.append(search_package_installation(parse_file(folder_path)))
            label = "benign" if trigger else "malicious"
            current_list.append(label)
            all_list.append(current_list)
    return all_list

if __name__ == '__main__':

    root_dir_benign =  "C:\\Users\\Amit\\AMIT\\cyberdetectiontaskfinal\\amalfi-artifact\data\\training_data\\benign"
    root_dir_malicious =  "C:\\Users\\Amit\\AMIT\\cyberdetectiontaskfinal\\amalfi-artifact\data\\training_data\\malicious"
    end_result = gather_data(root_dir_benign,True) + gather_data(root_dir_malicious,False)
    exit()
    full_path = "C:\\Users\\Amit\\AMIT\\cyberdetectiontaskfinal\\amalfi-artifact\\data\\dataset\\change-features.csv"
    with open(full_path, "w", newline="") as f:
        # Create a CSV writer object
        writer = csv.writer(f)

        # Write the data to the file
        for row in end_result:
            writer.writerow(row)

    benign_path = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/packages/training_data/benign'
    traverse_directory(benign_path)