import streamlit as st
import tarfile
import os
import sys
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score
from sklearn.metrics import recall_score
from sklearn.metrics import confusion_matrix
import joblib

from typing import Literal
import math
import datetime
from tree_sitter import Language, Parser
#----------------------------------------------------------------------------------------------
#extract tgz
def extract_tgz():
    st.set_page_config(page_title="Malicious Package Detector")

    st.title("Malicious Package Detector")

    file = st.file_uploader("Upload a TGZ file", type=["tgz"])
    output_dir = ""
    if file is not None:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        file_dir, file_name = os.path.split(file.name)
        output_dir = os.path.join(app_dir, os.path.splitext(file_name)[0])
        if os.path.exists(output_dir):
            return f"ERROR! {output_dir} already exists."

        try:
            with open(file.name, "wb") as f:
                f.write(file.getbuffer())

            st.write(f"Extracting {file_name}...")
            with tarfile.open(file_name, "r:gz") as tar:
                tar.extractall(app_dir)
            os.rename(os.path.join(app_dir, "package"), output_dir)
            st.write(f"{file_name} extracted successfully to {output_dir}.")
        except Exception as e:
            return f"ERROR! {e}"
    return output_dir


#--------------------------------------------------------------------------
#features extraction
#input of entire section = path string to desired folder
#output of entire section = array of features -> "[package name, version, feature1,feature2.... feature-n]"

Language.build_library(
  # Store the library in the `build` directory
  'build/my-languages.so',

  # Include one or more languages
  [
    'vendor/tree-sitter-javascript'
  ]
)

# Load the languages into your app as Language objects:
JS_LANGUAGE = Language('build/my-languages.so', 'javascript')

# reate a Parser and configure it to use one of the languages:
parser = Parser()
parser.set_language(JS_LANGUAGE)

def parse_file(file_name):
    # Open the file using the open() function, specifying the mode as 'r' for reading.
    file = open(file_name, 'r')
    # Read the contents of the file using the read() method
    code = file.read()
    # Parse the file and get the syntax tree
    tree = parser.parse(bytes(code, 'utf-8'))
    root_node = tree.root_node
    return root_node

def search_keyword_in_package(root_node, keywords, sub_keywords) -> bool:
    """
    This function searches for a keyword or sub keyword in the code using a provided root node.
    
    Parameters:
        root_node (Node): The root node of the code tree.
        keywords (list of str): A list of keywords to search for.
        sub_keywords (dict of lists): A dictionary where the keys are the names of sub keywords, and the values are the lists of words that make up the sub keyword.
    
    Returns:
        bool: True if a keyword or sub keyword is found, False otherwise.
  
    TODO:
        * current situation: the function stops after the function finds the first match
        * what to improve: have to add the function the ability to count the number of occurrences of all keywords
    """
    found = False
    
    for child in root_node.children:    
        # search if the child in one of the keywords
        if child.text.decode() in keywords:
            found = True
            break
        # search if the child in one of the sub keywords
        elif found == False:
            for inner_keyword in sub_keywords.values():
                if child.text.decode() in inner_keyword[0]:
                    inner_keyword[1].append(child.text.decode())
                    if inner_keyword[1] == inner_keyword[0]:
                        found = True
                        break
        # recursion 
        if found == False:
            found = search_keyword_in_package(child, keywords, sub_keywords)
            if found:
                break
    
    return found

import os

def search_substring_in_package(directory_path: str, keywords: str) -> int:
    """
    This function searches for a keyword in the files within a directory.
    
    Parameters:
        directory_path (str): The path to the directory.
        keyword (list of str): A list of keywords to search for.
    
    Returns:
        int: 1 if the keyword is found in any of the files, 0 otherwise.
    """
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if filename.endswith(".js") or filename.endswith(".ts"):
                with open(file_path, "r") as file:
                    file_content = file.read()
                    for keyword in keywords:
                        if keyword in file_content:
                            return 1
    return 0

def bitwise_operation(list1, list2, operation) -> list:
    """
    Perform a bitwise operation between elements of two lists of 1s and 0s.
    Parameters:
    list1 (List[int]): The first list of elements (1 or 0).
    list2 (List[int]): The second list of elements (1 or 0).
    operation (str): The bitwise operation to perform, one of '&' (AND), '|' (OR), or '^' (XOR).
    Returns:
    List[int]: The result of the bitwise operation.
    Raises:
    ValueError: If the lists have different lengths or if the operation is not one of the supported operations.
    """
    
    if len(list1) != len(list2):
        raise ValueError("Both lists must have the same length")
    if operation not in ['&', '|', '^']:
        raise ValueError("Invalid operation")

    operation_dict = {'&': '&', '|': '|', '^': '^'}
    operation = operation_dict[operation]
    result = [eval(f"{a} {operation} {b}") for a, b in zip(list1, list2)]
    
    return result

def general_search(root_node,keywords) -> Literal[1, 0]:

     # Traverse the syntax tree and check for the specific line of code
    sub_keywords = {} # {index of the sublist in keywords: keyword, [words that found]}
    # for each sublist in keywords, add the index and the keyword
    for index, keyword in enumerate(keywords):
      if type(keyword) == list:
        sub_keywords[index] = [keyword, []]

    is_using = 0
    if search_keyword_in_package(root_node, keywords, sub_keywords):
        is_using = 1
    
    return is_using 

def extract_package_details(package_name: str) -> tuple:
    """
    Extracts the name and version of a package from its package name string.
    Parameters:
        package_name (str): The package name string in the format 'name' + '-v-' + 'version'.
    Returns:
        tuple: A tuple containing the name and version of the package as separate strings.
    Example:
        >>> extract_package_details('package-v-1.0')
        ('package', '1.0')
    """

    name, version = package_name.split('-v-')
    return (name, version)



def calculate_entropy(data) -> float | Literal[0]:
    """
    Calculates the entropy of the input data.
    Parameters:
        data (bytes): binary data to calculate the entropy for.
    Returns:
        entropy (float): the entropy of the input data.
    """

    entropy = 0
    # Iterate over all possible values of bytes (0 to 255)
    for x in range(256):
        # Calculate the probability of the byte value x appearing in the data
        p_x = float(data.count(x.to_bytes(1, "big")))/len(data)
        # If the probability is greater than 0, add to the entropy value
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
            
    # Return the entropy value
    return entropy

def find_longest_line_in_the_file(filename) -> int:
    """
    This function takes in a filename as an argument and returns the length of the longest line in the file.
    Parameters:
    filename (str): The name of the file to be read.
    Returns:
    int: The length of the longest line in the file.
    """
    
    with open(filename, 'r') as file:
        longest_line = 0
        for line in file:
            if len(line) > longest_line:
                longest_line = len(line)
                 
    return longest_line

#----------------------------------
def search_PII(root_node) -> Literal[1, 0]:
    """
    (1) Access to personally-identifying information (PII): creditcard numbers, passwords, and cookies
    TODO:
    * current situation: have only two keywords
    * what to improve: have more keywords after the data exploration
    """

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

    keywords = ['read','write','file', 'require("fs")', 'os = require("os")', 'platform', 'hostname', 'system32']
    

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
    
    keywords = ['exec', 'spawn', 'fork', 'thread', 'process', 'child_process']
    return general_search(root_node, keywords) 

def search_network_access(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (c)Network access: sending or receiving data
    """
    '''(2)c
    Network access: sending or receiving data
    #send -> we use send keyweord because when it comes to outward comminicaton, we expect to receive data,
    but it is very very unlikely that we will transfer data out from the device.
    thus we marked 'send' keyword'''
    

    keywords = ['send', 'export', 'upload' ,'post', 'XMLHttpRequest', 'submit', 'dns', 'nodemailer']
    return general_search(root_node, keywords)     

def search_cryptographic_functionality(root_node) -> Literal[1, 0]:
    """
    (3) Use of specific APIs 
    (a) Access to crypto functionality:
    """

    '''(3)(a) Cryptographic functionality
    mining: The process of finding a hash that meets certain criteria in a cryptocurrency network.'''
    keywords = ['crypto', 'mining', 'miner', 'cpu']
    
    return general_search(root_node, keywords)

def search_data_encoding(root_node) -> Literal[1, 0]:
    """
    (3) Use of specific APIs
    (b) encoded data: find encoded data in the script
    """

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

    '''(4) Use of package installation scripts
    #In npm, pre-install and post-install are scripts that can
    be defined in the scripts section of the package.json file.
    These scripts are executed before and after the installation of packages, respectively.'''
    keywords = ['preinstall', 'postinstall', 'install', 'sudo']

    return general_search(root_node, keywords)

def search_minified_code(directory_path) -> Literal[1, 0]:
    """
    (5) Presence of minified code (to avoid detection) or binary files (such as binary executables)
    Extracts the is_minified feature from the files in the directory.
    Parameters:
        directory_path (str): the path to the directory to extract features from.
    Returns:
        is_minified (int): 1 if the code is minified, 0 otherwise.
    """ 
    
    # Store the entropy values of each file in the directory
    entropy_values = []

    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                continue
            
            # Construct the file path for each file
            file_path = os.path.join(dirpath, filename)
            # Read the contents of the file as binary data
            with open(file_path, "rb") as f:
                data = f.read()
            if len(data) > 0:
                # Calculate the entropy of the binary data
                entropy = calculate_entropy(data)
                # Append the entropy to the list of entropy values
                entropy_values.append(entropy)

    is_minified = 0

    # Calculate the average entropy and standard deviation of the entropy values
    if len(entropy_values) != 0:
        avg_entropy = sum(entropy_values) / len(entropy_values)
        std_dev_entropy = math.sqrt(sum((x - avg_entropy)**2 for x in entropy_values) / len(entropy_values))

        # Create a feature indicating whether the data is minified or not
        AVG_ENTROPY_THRESHOLD = 5
        STD_DEV_ENTROPY_THRESHOLD = 0.1
        if avg_entropy > AVG_ENTROPY_THRESHOLD and std_dev_entropy > STD_DEV_ENTROPY_THRESHOLD:
            is_minified = 1          
        
    return is_minified

def search_packages_with_no_content(directory_path: str) -> Literal[1, 0]:
    """
    The function takes in a directory path as input and returns 1 if the directory does not contain any '.js' or '.ts' files, and 0 otherwise.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns 1 if the directory does not contain any '.js' or '.ts' files and 0 otherwise.
    
    """
        
    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                continue
            else:
                return 0
        
    return 1

def search_geolocation(directory_path) -> Literal[1, 0]:
    """
    search_geolocation: unautherized acess to the location of the device 
    """

    # searching for an API that gets the location of the device base on its IP.   
    keywords = ['ipgeolocation']

    return search_substring_in_package(directory_path, keywords)

def longest_line_in_the_package(directory_path: str) -> int:
    """
    The function returns the longest line in the package.
    Malicious packages sometimes use obfuscation techniques, 
    that write the whole code in the file as one line.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns the longest line in the package.
    """

    # Store the longest line in the package
    longest_line_package = 0

    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                continue
            
            # Construct the file path for each file
            file_path = os.path.join(dirpath, filename)
            # Read the contents of the file as binary data
            longest_line_file = find_longest_line_in_the_file(file_path)
            if longest_line_file > longest_line_package:
                longest_line_package = longest_line_file
        
    return longest_line_package

def num_of_files_in_the_package(directory_path: str) -> int:
    """
    The function returns the number of files in the package.
    Malicious packages often tend to contain a very small amount of files.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns the of files in the package.
    """

    # Store the number of files in the package
    num_of_files = 0

    # Loop over all the files in the directory tree rooted at directory_path
    for _, _, filenames in os.walk(directory_path):
        num_of_files += len(filenames)
            
    return num_of_files

def does_contain_license(directory_path: str) -> int:
    """
    The function returns 1 if the package contain a license file and 0 otherwise.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns 1 if the package contain a license file and 0 otherwise.
    """

    # Loop over all the files in the directory tree rooted at directory_path
    for _, _, filenames in os.walk(directory_path):
        for filename in filenames:
            if filename == 'LICENSE':
                return 1
        
    return 0
         
def extract_features(root_dir: str) -> None:
    """
    This function is used to traverse a given directory and extract features of each javascript file in it.
    The extracted features are saved in a dictionary named `package_features` 
    in the format of `{package_name: [feature_1, feature_2, ..., feature_n]}`.
    Args:
    - root_dir (str): The path of the root directory to traverse.
    - malicious (bool): Indicates whether the files in the directory are malicious or benign.
    Returns:
    None. The function saves the extracted features in a csv file.
    """
    # st.text(f"1. root_dir = {root_dir}")
    package_features = {} # {package_name:[f1, f2, ..., fn]}
    visited_packages = set() # the set will contain the packages name that were traversed 
    NUM_OF_FEATURES_INCLUDE = 16 # number of features include name, version and label
    
    for dirname, _, files in os.walk(root_dir):
        # st.text(f"1.5. dirname = {dirname}") # = c:/../../app_folder
        path_lst = dirname.split(os.path.sep)
        # st.text(f"2. path_lst = {path_lst}") # = ['c',/../, /../, app-folder]
        main_dir = path_lst[-1] #app_folder
        # st.text(f"3. main_dir = {main_dir}")
        package_index = path_lst.index(main_dir) #app_folder
        
        # st.text(f"4. package_index = {package_index}")
        
        for filename in files:
            if not filename.endswith(".js") and not filename.endswith(".json"):
                continue
            file_path = os.path.join(dirname, filename)
            # st.text(f"5. file_path = {file_path}")
            package_name = path_lst[package_index]
            # st.text(f"6. package_name = {package_name}")

            
            # check if the current package name already exists in the package_features dictionary
            if package_name not in package_features:
                # if not, initialize a list of NUM_OF_FEATURES_INCLUDE elements with value 0
                init_lst = [0] * NUM_OF_FEATURES_INCLUDE
                package_features[package_name] = init_lst
            
            name, version = extract_package_details(package_name) # 0, 1
            is_PII = 1#search_PII(parse_file(file_path)) # 2
            # st.text(f"7. is_PII = {is_PII}")
            is_file_sys_access = 1 #search_file_sys_access(parse_file(file_path)) # 3
            # st.text(f"8. is_file_sys_access = {is_file_sys_access}")
            is_process_creation = search_file_process_creation(parse_file(file_path)) # 4
            # st.text(f"9. is_process_creation = {is_process_creation}")
            is_network_access = search_network_access(parse_file(file_path)) # 5
            is_crypto_functionality = search_cryptographic_functionality(parse_file(file_path)) # 6
            is_data_encoding = search_data_encoding(parse_file(file_path)) # 7
            is_dynamic_code_generation = search_dynamic_code_generation(parse_file(file_path)) # 8
            is_package_installation = search_package_installation(parse_file(file_path)) # 9
            # check if the package was already processed
            if package_name not in visited_packages: 
                index = dirname.find("/package")
                is_geolocation = search_geolocation(dirname[:index]) # 10
                is_minified_code = search_minified_code(dirname[:index]) # 11
                is_has_no_content = search_packages_with_no_content(dirname[:index]) # 12
                longest_line = longest_line_in_the_package(dirname[:index]) # 13
                num_of_files = num_of_files_in_the_package(dirname[:index]) # 14
                has_license = does_contain_license(dirname[:index]) # 15
                visited_packages.add(package_name)
            else:
                is_geolocation = package_features[package_name][10]
                is_minified_code = package_features[package_name][11]
                is_has_no_content = package_features[package_name][12]
                longest_line = package_features[package_name][13] 
                num_of_files = package_features[package_name][14]
                has_license = package_features[package_name][15]
            #label = packages_type # 16
            
            # create a new list of the current package's features
            new_inner_lst = [name, version, is_PII, is_file_sys_access, is_process_creation, 
                             is_network_access, is_crypto_functionality, is_data_encoding, 
                             is_dynamic_code_generation, is_package_installation, is_geolocation, is_minified_code, 
                             is_has_no_content, longest_line, num_of_files, has_license]
            
            # get the old feature list for the current package name
            old_inner_lst = package_features[package_name]
            
            # perform the bitwise operation between the new and old feature lists
            updated_inner_lst = bitwise_operation(new_inner_lst[2:-6], old_inner_lst[2:-6], '|')
            
            pre_list = [name, version]
            past_list = [is_geolocation, is_minified_code, is_has_no_content, longest_line, num_of_files, has_license]
            
            # update the value in the package_features dictionary with the updated feature list
            package_features[package_name] = pre_list + updated_inner_lst + past_list
    
    # print(f"...........{package_features.values()}")
    # print(f"...........{package_features}")
    return package_features.values()
#----------------------------------------------------------------------------------
#test on model

fileData = open("dataToDocker.pkl","rb")
myModel  = joblib.load(fileData)
fileData.close()

def predictInput(file_name):
    output = extract_features(file_name)
    print(f'output: {output}')
    features = output[2:]
    st.text(f"features: {features}")
    result = myModel.predict(np.array(output).reshape(1,-1))
    print(f'result: {result}')
    return result[0]
	
def displayResult(input_file):
	try:
		#output = model.predict([[int(recID),int(dur),int(src_bytes_input),int(dst_bytes_input)]])[0]
		st.text(f"input file: {input_file}")
		prediction = predictInput(input_file)
		if prediction == -1:
			prediction = "1 - Malicious"
		elif prediction == 1:
			prediction = "0 - Benign"
		st.text(f"prediction: {prediction}")
	except Exception as er:
		st.text("ERROR!")
		st.text(f"er: {er}")
	
if __name__ == "__main__":
    file = extract_tgz()
    if isinstance(file, str):
        displayResult(file)
