
from search_in_file import parse_file, search_keyword_in_code
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
    logging.info("start func: search_PII")
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
        
search_PII(root_node)