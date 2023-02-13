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
			st.text(f"{output_dir} already exists.")
			return output_dir

		with open(file.name, "wb") as f:
			f.write(file.getbuffer())

		st.write(f"Extracting {file_name}...")
		#extract_tgz(file_name, app_dir)
		with tarfile.open(file_name, "r:gz") as tar:
			tar.extractall(app_dir)
		os.rename(os.path.join(app_dir, "package"), output_dir)
		st.write(f"{file_name} extracted successfully to {output_dir}.")
	return output_dir

#--------------------------------------------------------------------------
#features extraction
#input of entire section = path string to desired folder
#output of entire section = array of features -> "[package name, version, feature1,feature2.... feature-n]"


def search_substring_in_package(directory_path: str, keywords: str) -> int:

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

    if len(list1) != len(list2):
        raise ValueError("Both lists must have the same length")
    if operation not in ['&', '|', '^']:
        raise ValueError("Invalid operation")

    operation_dict = {'&': '&', '|': '|', '^': '^'}
    operation = operation_dict[operation]
    result = [eval(f"{a} {operation} {b}") for a, b in zip(list1, list2)]
    
    return result

def general_search(file_name, keyword_list):
    with open(file_name, 'r', encoding="utf8") as file:
        # Read the contents of the file using the read() method
        code = file.read()
        # Check if any top-level keyword is present in the code
        for keyword in keyword_list:
            if isinstance(keyword, list):
                # If the keyword is a list, recursively search for its sub-keywords
                if all(sub_keyword in code for sub_keyword in keyword):
                    return 1
            else:
                # If the keyword is a string, search for it directly
                if keyword in code:
                    return 1
        # If no top-level keyword was found, recursively search for sub-keywords in all lists
        for keyword in keyword_list:
            if isinstance(keyword, list):
                if general_search(file_name, keyword):
                    return 1
        # If no keyword or sub-keyword was found, return False
        return 0


def extract_package_details(package_name: str) -> tuple:

    name, version = package_name.split('-v-')
    return (name, version)



def calculate_entropy(data) -> float | Literal[0]:


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

    with open(filename, 'r') as file:
        longest_line = 0
        for line in file:
            if len(line) > longest_line:
                longest_line = len(line)
                 
    return longest_line

#----------------------------------
def search_PII(root_node) -> Literal[1, 0]:

    keywords = ['screenshot', ['keypress', 'POST'], 'creditcard', 'cookies', 'passwords', 'appData']
    return general_search(root_node, keywords)
    
def search_file_sys_access(root_node) -> Literal[1, 0]:

    keywords = ['read','write','file', 'require("fs")', 'os = require("os")', 'platform', 'hostname', 'system32']
    

    return general_search(root_node, keywords)
    
def search_file_process_creation(root_node) -> Literal[1, 0]:

    keywords = ['exec', 'spawn', 'fork', 'thread', 'process', 'child_process']
    return general_search(root_node, keywords) 

def search_network_access(root_node) -> Literal[1, 0]:

    keywords = ['send', 'export', 'upload' ,'post', 'XMLHttpRequest', 'submit', 'dns', 'nodemailer']
    return general_search(root_node, keywords)     

def search_cryptographic_functionality(root_node) -> Literal[1, 0]:

    keywords = ['crypto', 'mining', 'miner', 'cpu']
    
    return general_search(root_node, keywords)

def search_data_encoding(root_node) -> Literal[1, 0]:


    keywords = ['encodeURIComponent', 'querystring', 'qs', 'base64', 'btoa', 'atob', 'Buffer', 'JSON.stringify']
    
    return general_search(root_node, keywords)


def search_dynamic_code_generation(root_node) -> Literal[1, 0]:

    keywords = ['eval', 'Function']
    
    return general_search(root_node, keywords)

def search_package_installation(root_node) -> Literal[1, 0]:

    keywords = ['preinstall', 'postinstall', 'install', 'sudo']

    return general_search(root_node, keywords)

def search_minified_code(directory_path) -> Literal[1, 0]:

    
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

        
    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                continue
            else:
                return 0
        
    return 1

def search_geolocation(directory_path) -> Literal[1, 0]:


    # searching for an API that gets the location of the device base on its IP.   
    keywords = ['ipgeolocation']

    return search_substring_in_package(directory_path, keywords)

def longest_line_in_the_package(directory_path: str) -> int:


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

    # Store the number of files in the package
    num_of_files = 0

    # Loop over all the files in the directory tree rooted at directory_path
    for _, _, filenames in os.walk(directory_path):
        num_of_files += len(filenames)
            
    return num_of_files

def does_contain_license(directory_path: str) -> int:

    # Loop over all the files in the directory tree rooted at directory_path
    for _, _, filenames in os.walk(directory_path):
        for filename in filenames:
            if filename == 'LICENSE':
                return 1
        
    return 0
         
def extract_features(root_dir: str) -> None:

    st.text(f"1. root_dir = {root_dir}")
    package_features = {} # {package_name:[f1, f2, ..., fn]}
    visited_packages = set() # the set will contain the packages name that were traversed 
    NUM_OF_FEATURES_INCLUDE = 16 # number of features include name, version and label
    package_extracted = False
    package_extracted2 = False
    for dirname, _, files in os.walk(root_dir):
        #st.text(f"1.5. dirname = {dirname}") # = c:/../../app_folder
        path_lst = dirname.split(os.path.sep)
        #st.text(f"2. path_lst = {path_lst}") # = ['c',/../, /../, app-folder]
        main_dir = path_lst[-1] #app_folder
        #st.text(f"3. main_dir = {main_dir}")
        package_index = path_lst.index(main_dir) #app_folder
        
        
        name = ""
        version = ""
        for filename in files:
            if not filename.endswith(".js") and not filename.endswith(".json"):
                continue
            file_path = os.path.join(dirname, filename)
            #st.text(f"5. file_path = {file_path}")
            package_name = path_lst[package_index]
            #st.text(f"6. package_name = {package_name}")

            
            # check if the current package name already exists in the package_features dictionary
            #st.text(f"package_extracted2: {package_extracted2}")
            if package_name not in package_features:# and not package_extracted2:
                #st.text("here!!")
                # if not, initialize a list of NUM_OF_FEATURES_INCLUDE elements with value 0
                init_lst = [0] * NUM_OF_FEATURES_INCLUDE
                package_features[package_name] = init_lst
                #package_extracted2 = True
            
            if not package_extracted:
                name, version = extract_package_details(package_name) # 0, 1
                package_extracted = True
            #st.text(f"start features detections...")
            is_PII = search_PII(file_path) # 2
            #st.text(f"7. is_PII = {is_PII}")
            is_file_sys_access = search_file_sys_access(file_path) # 3
            #st.text(f"8. is_file_sys_access = {is_file_sys_access}")
            is_process_creation = search_file_process_creation(file_path) # 4
            #st.text(f"9. is_process_creation = {is_process_creation}")
            is_network_access = search_network_access(file_path) # 5
            is_crypto_functionality = search_cryptographic_functionality(file_path) # 6
            is_data_encoding = search_data_encoding(file_path) # 7
            is_dynamic_code_generation = search_dynamic_code_generation(file_path) # 8
            is_package_installation = search_package_installation(file_path) # 9
            # check if the package was already processed
            #st.text(f"10. is_package_installation = {is_package_installation}")
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
            #st.text(f"old_inner_lst: {old_inner_lst}")
            #st.text(f"new_inner_lst: {new_inner_lst}")
            # perform the bitwise operation between the new and old feature lists
            updated_inner_lst = bitwise_operation(new_inner_lst[2:-6], old_inner_lst[2:-6], '|')
            
            pre_list = [name, version]
            past_list = [is_geolocation, is_minified_code, is_has_no_content, longest_line, num_of_files, has_license]
            
            # update the value in the package_features dictionary with the updated feature list
            #st.text(f"pre_list: {pre_list}")
            #st.text(f"updated_inner_lst: {updated_inner_lst}")
            #st.text(f"past_list: {past_list}")
            package_features[package_name] = pre_list + updated_inner_lst + past_list
    
    #st.text(f"...........{package_features.values()}")
    #st.text(f"...........{package_features}")
    #st.text(f"final list: {list(package_features.values())[0]}")
    return list(package_features.values())[0][2:]
#----------------------------------------------------------------------------------
#test on model

fileData = open("dataToDocker.pkl","rb")
myModel  = joblib.load(fileData)
fileData.close()

def predictInput(file_name):
	
    output = extract_features(file_name)
    st.text(f"final output: {output}")
    #st.text(f"first output: {extract_features(file_name)}")
    #st.text(f"second output: {output}")
    result = myModel.predict(np.array(output).reshape(1,-1))
    return result[0]
	

def displayResult(input_file):
	try:
		#output = model.predict([[int(recID),int(dur),int(src_bytes_input),int(dst_bytes_input)]])[0]
		st.text(f"input file: {input_file}")
		output = predictInput(input_file)
		if output == -1:
			output = "1 - anomaly"
		elif output == 1:
			output = "0 - normal"
		st.text(f"output: {output}")
	except Exception as er:
		st.text("could not calculate")
		st.text(f"er: {er}")
	
if __name__ == "__main__":
    file = extract_tgz()
    displayResult(file)