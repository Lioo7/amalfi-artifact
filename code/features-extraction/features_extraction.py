
from typing import Literal
from calculate_entropy import extract_is_minified_feature
from util import bitwise_operation, general_search, parse_file, extract_package_details, write_dict_to_csv
import logging
import os

LOGֹ_FORMAT = "%(levelname)s, time: %(asctime)s , line: %(lineno)d- %(message)s "
# create and configure logger
logging.basicConfig(
    filename="features-extraction-logging.log", level=logging.INFO, filemode="w"
)
logger = logging.getLogger()

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

def search_cryptographic_functionality(root_node) -> Literal[1, 0]:
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
    base64 -> common encoding method.
    encodeURIComponent -> common encoding function with utf-8.
    querystring -> This is a built-in Node.js library for working with query strings. 
    It provides methods for encoding and decoding query strings.
    qs: This is a popular library for encoding and decoding query strings in both the browser and Node.js. 
    It provides a more powerful set of features compared to the built-in querystring library.
    btoa and atob: These are global functions in JavaScript for base64 encoding and decoding respectively.
    Buffer: This is a built-in class in Node.js for working with binary data.
    You can use the .toString('base64') method to encode binary data as a base64 string.
    JSON.stringify: This is a built-in method in JavaScript for converting a JavaScript object to a JSON string. 
    JSON is a widely used format for encoding data structures and exchanging data between client and server.'''

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
    
def search_minified_code(directory_path) -> Literal[1, 0]:
    """
    5
    Presence of minified code (to avoid detection) or binary files (such as binary executables)
    """
    logging.info("start func: search_minified_code")
    is_minified = extract_is_minified_feature(directory_path)
    
    return is_minified
            
def extract_features(root_dir: str, malicious) -> None:
    """
    This function is used to traverse a given directory and extract features of each javascript file in it.
    The extracted features are saved in a dictionary named `package_features` in the format of `{package_name: [feature_1, feature_2, ..., feature_n]}`.

    Args:
    - root_dir (str): The path of the root directory to traverse.
    - malicious (bool): Indicates whether the files in the directory are malicious or benign.

    Returns:
    None. The function saves the extracted features in a csv file.

    """
    logging.info("start func: extract_features")
    logging.info(f'malicious?: {malicious}')
    
    package_features = {} # {package_name:[f1, f2, ..., fn]}
    visited_packages = set() # the set will contain the packages name that were traversed 
    NUM_OF_FEATURES_INCLUDE = 12 # number of features include name, version and label
    
    for dirname, subdirs, files in os.walk(root_dir):
        
        path_lst = dirname.split(os.path.sep)
        packages_type = "malicious" if malicious else "benign"
        package_index = path_lst.index(packages_type) + 1
        
        for filename in files:
            if not filename.endswith(".js"):
                continue
            file_path = os.path.join(dirname, filename)
            package_name = path_lst[package_index]

            logging.debug('================================================')
            logging.debug(f"File path: {file_path}")
            logging.debug(f"Package name: {package_name}")
            logging.debug(f"filename: {filename}")
            
            # check if the current package name already exists in the package_features dictionary
            if package_name not in package_features:
                # if not, initialize a list of NUM_OF_FEATURES_INCLUDE elements with value 0
                init_lst = [0] * NUM_OF_FEATURES_INCLUDE
                package_features[package_name] = init_lst
            
            name, version = extract_package_details(package_name) # 0, 1
            is_PII = search_PII(parse_file(file_path)) # 2
            is_file_sys_access = search_file_sys_access(parse_file(file_path)) # 3
            is_process_creation = search_file_process_creation(parse_file(file_path)) # 4
            is_network_access = search_network_access(parse_file(file_path)) # 5
            is_crypto_functionality = search_cryptographic_functionality(parse_file(file_path)) # 6
            is_data_encoding = search_data_encoding(parse_file(file_path)) # 7
            is_dynamic_code_generation = search_dynamic_code_generation(parse_file(file_path)) # 8
            is_package_installation = search_package_installation(parse_file(file_path)) # 9
            # check if the package was already processed
            if package_name not in visited_packages:  # 10
                logging.debug(f"{package_name} was not visit yet")
                index = dirname.find("/package")
                logging.debug(f"dirname[:index]: {dirname[:index]}")
                is_minified_code = search_minified_code(dirname[:index])
                visited_packages.add(package_name)
            else:
                is_minified_code = package_features[package_name][10]
            label = packages_type # 11
                
            # create a new list of the current package's features
            new_inner_lst = [name, version, is_PII, is_file_sys_access, is_process_creation, 
                             is_network_access, is_crypto_functionality, is_data_encoding, 
                             is_dynamic_code_generation, is_package_installation, is_minified_code, 
                             label]
            
            # get the old feature list for the current package name
            old_inner_lst = package_features[package_name]
            
            # perform the bitwise operation between the new and old feature lists
            updated_inner_lst = bitwise_operation(new_inner_lst[2:-1], old_inner_lst[2:-1], '|')
            
            # update the value in the package_features dictionary with the updated feature list
            package_features[package_name] = [name] + [version] + updated_inner_lst + [label]
    
    # define the path for the output CSV file
    csv_file = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/dataset/change-features.csv'
    
    # decide whether to write the data in append mode or write mode based on the input malicious flag
    method = 'a' if malicious else "w"
    
    # call the write_dict_to_csv function to write the package_features dictionary to the CSV file
    write_dict_to_csv(dict_data=package_features, csv_file=csv_file, method=method)


if __name__ == '__main__':
    benign_path = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/extracted-packages/training_data/benign'
    malicious_path = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/extracted-packages/training_data/malicious'
    extract_features(malicious_path, malicious=True)