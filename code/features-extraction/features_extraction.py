
from search_in_file import parse_file, search_keyword_in_code
from calculate_entropy import extract_is_minified_feature
import logging

LOGֹ_FORMAT = "%(levelname)s, time: %(asctime)s , line: %(lineno)d- %(message)s "
# create and configure logger
logging.basicConfig(
    filename="features-extraction-logging.log", level=logging.INFO, filemode="w"
)
logger = logging.getLogger()

"""
Features list:

Single-version features:
(1) Access to personally-identifying information (PII): creditcard numbers, passwords, and cookies
(2) Access to specific system resources
    (a) File-system access: reading and writing files
    (b) Process creation: spawning new processes
    (c) Network access: sending or receiving data
(3) Use of specific APIs
    (a) Cryptographic functionality
    (b) Data encoding using encodeURIComponent etc.
    (c) Dynamic code generation using eval, Function, etc.
(4) Use of package installation scripts
(5) Presence of minified code (to avoid detection) or binary files (such as binary executables)
"""

"""
TODO: Add more keywords, some explnation and create a function for each feature


'''#(2)a
File-system access: reading and writing files
keywords = ['read','write','file', 'require('fs')']
#require('fs') is the File System Library that provides a simple
 and convenient way to interact with the file system on the computer.
 It provides functions for reading and writing files,
 creating and deleting directories, and more.

#(2)b
Process creation: spawning new processes
keywords = ['exec', 'spawn', 'fork', 'thread', 'process', 'child_process']
#exec -> execute, used to run cmd commands on the device, including creation of new processes.

#spawn -> The spawn keyword in JavaScript is used to start a new process in Node.js.
 It creates a new process and runs a specified command in that process.

#fork -> The fork method in the child_process module in Node.js is used to create a new
 Node.js process that is a child of the current process. Unlike the spawn method,
 which creates a new process and runs a separate command, the fork method creates
 a new process that runs the same code as the parent process.

#child_process -> The child_process module in Node.js is a module for creating and controlling
 child processes in a Node.js application. It provides a way to start new processes,
 run shell commands, and manage the communication between a Node.js process and its child processes.

(2)c
Network access: sending or receiving data
keywords = ['send', 'export', 'upload' ,'post', 'Ajax', 'XMLHttpRequest', 'submit']
#send -> we use send keyweord because when it comes to outward comminicaton, we expect to receive data,
but it is very very unlikely that we will transfer data out from the device.
thus we marked 'send' keyword

(3)(a) Cryptographic functionality
keywords = ['crypto', 'mining']
mining: The process of finding a hash that meets certain criteria in a cryptocurrency network.

(3)(b) Data encoding using encodeURIComponent etc.
keywords = ['encodeURIComponent', 'querystring', 'qs', 'base64', 'btoa', 'atob', 'Buffer', 'JSON.stringify']

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
 object to a JSON string. JSON is a widely used format for encoding data structures and exchanging data between client and server.



(3)(c) Dynamic code generation using eval, Function, etc.
keywords = ['eval', 'Function']
#eval -> a function that is used to dynamically execute the code defined in the string code.
# Function -> Function constructor: This allows you to dynamically create a new function
 and execute it. The Function constructor takes a string of code as its
  argument and returns a reference to a new function that can be executed.

(4) Use of package installation scripts
keywords = ['preinstall', 'postinstall', 'npm install']
#In npm, pre-install and post-install are scripts that can
 be defined in the scripts section of the package.json file.
 These scripts are executed before and after the installation of packages, respectively.
"""

file_name = 'js_code_example'
root_node = parse_file(file_name)
  
def search_PII(root_node) -> None:
    """
    TODO:
    * current situation: have only two keywords
    * what to improve: have more keywords after the data exploration
    """
    logging.info("start func: search_PII")

    keywords = ['screenshot', ['keypress', 'POST'], 'creditcard', 'cookies', 'passwords', 'appData']
    # Traverse the syntax tree and check for the specific line of code
    sub_keywords = {} # {index of the sublist in keywords: keyword, [words that found]}
    # for each sublist in keywords, add the index and the keyword
    for index, keyword in enumerate(keywords):
      if type(keyword) == list:
        sub_keywords[index] = [keyword, []]

    if search_keyword_in_code(root_node, keywords, sub_keywords):
        print("Line found!")
    else:
        print("Line not found.")
        
        
def search_minified_code(directory_path):
    is_minified = extract_is_minified_feature(directory_path)
    print(is_minified)
    
if __name__ == '__main__':
    #search_PII(root_node)
    directory_path = 'amalfi-artifact/data/packages/package/lib'
    search_minified_code(directory_path)