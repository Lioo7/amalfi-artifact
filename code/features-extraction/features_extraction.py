
from search_in_file import parse_file, search_keyword_in_code

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
    keywords = ['screenshot']
    # Traverse the syntax tree and check for the specific line of code

    if search_keyword_in_code(root_node, keywords):
        print("Line found!")
    else:
        print("Line not found.")
        
search_PII(root_node)