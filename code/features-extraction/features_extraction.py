
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

file_name = 'js_code_example'
root_node = parse_file(file_name)
  
def search_PII(root_node) -> None:
    """
    TODO:
    * current situation: have only two keywords
    * what to improve: have more keywords after the data exploration
    """
    logging.info("start func: search_PII")
    '''#(1)
    creditcard numbers, passwords, and cookies
    keywords = ['phone,creditcard,cookies,passwords,appData]
    '''

    '''#(2)a
    File-system access: reading and writing files
    keywords = ['read','write','file', 'require('fs')']

    #(2)b
    Process creation: spawning new processes
    keywords = ['read','write','file']

    (2)c
    Process creation: spawning new processes
    keywords = ['child_process','fork','exec']

    (3)(a) Cryptographic functionality
    keywords = ['crypto']

    (3)(b) Data encoding using encodeURIComponent etc.
    keywords = ['encodeURIComponent', 'querystring', 'qs', 'base64', 'btoa', 'atob', 'Buffer', 'JSON.stringify']

    (3)(c) Dynamic code generation using eval, Function, etc.
    keywords = ['eval', 'Function']

    (4) Use of package installation scripts
    keywords = ['npm install']

    (5) Presence of minified code (to avoid detection) or binary files (such as binary executables)
    keywords = ['Buffer']
    '''
    keywords = ['screenshot', ['keypress', 'POST']]
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
        
        
def check_if_minified(directory_path):
    is_minified = extract_is_minified_feature(directory_path)
    print(is_minified)
    
if __name__ == '__main__':
    # search_PII(root_node)
    # check_if_minified(directory_path)