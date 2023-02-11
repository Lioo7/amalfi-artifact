from tree_sitter import Language, Parser
from typing import Literal
import logging
import csv

"""
TODO:
* current situation: supports only JS
* what to improve: have to add a support to TS as well
"""
# Use the Language.build_library method to compile these into a library that's usable from Python. 
# This function will return immediately if the library has already been compiled since the last time its source code was modified
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
    logging.debug(f"start func: parse_file")
    # Open the file using the open() function, specifying the mode as 'r' for reading.
    file = open(file_name, 'r')
    # Read the contents of the file using the read() method
    code = file.read()
    # Parse the file and get the syntax tree
    tree = parser.parse(bytes(code, 'utf-8'))
    root_node = tree.root_node
    return root_node

def search_keyword_in_code(root_node, keywords, sub_keywords)->bool:
  """
  TODO:
  * current situation: the function stoping after the function find the first match
  * what to improve: have to add the function the ability to count the number of occurrences of all keywords
  """
  logging.debug(f"start func: search_keyword_in_code")
  found = False
  
  for child in root_node.children:
    # search if the child in one of the keywords
    logging.debug(f"child: {child.text.decode()}")
    if child.text.decode() in keywords:
        found = True
        logging.info(f"keyword found!\nThe keyword that found is: {child.text.decode()}")
        break
    # search if the child in one of the sub keywords
    elif found == False:
      for inner_keyword in sub_keywords.values():
        # logging.debug(f"second loop, inner_keyword: {inner_keyword}")
        if child.text.decode() in inner_keyword[0]:
          logging.info(f"sub keyword found!\nThe keyword that found is: {child.text.decode()}")
          inner_keyword[1].append(child.text.decode())
          if inner_keyword[1] == inner_keyword[0]:
            logging.info(f"The entire sub keyword was found!\n{inner_keyword[1]} == {inner_keyword[0]}")
            found = True
            break
    # recursion 
    if found == False:
        logging.debug("calling recursion")
        found = search_keyword_in_code(child, keywords, sub_keywords)
        if found:
            break
  
  logging.debug(f"results of search_keyword_in_code: {found}")
  return found

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
    logging.debug("start func: bitwise_operation")
    
    if len(list1) != len(list2):
        raise ValueError("Both lists must have the same length")
    if operation not in ['&', '|', '^']:
        raise ValueError("Invalid operation")

    operation_dict = {'&': '&', '|': '|', '^': '^'}
    operation = operation_dict[operation]
    result = [eval(f"{a} {operation} {b}") for a, b in zip(list1, list2)]
    return result

def general_search(root_node,keywords) -> Literal[1, 0]:
    logging.debug("start func: general_search")

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
    logging.debug("start func: extract_package_details")

    name, version = package_name.split('-v-')
    return (name, version)

import csv

def write_dict_to_csv(dict_data, csv_file, method='w') -> None:
    """
    Writes the values of a dictionary to a CSV file.

    Parameters:
        dict_data (dict): The dictionary to be written to the CSV file.
        csv_file (str): The path to the CSV file.
        method (str, optional): The method to use when opening the CSV file.
            'w' for write (default), 'a' for append.

    Returns:
        None
    """
    logging.debug("start func: write_dict_to_csv")

    headers = ['package','version','PII','file_sys_access','file_process_creation',
        'network_access','cryptographic_functionality', 'data_encoding',
        'dynamic_code_generation','package_installation', 'is_minified_code','label']

    with open(csv_file, method, newline='') as f:
        writer = csv.writer(f)
        if method == 'w':
            writer.writerow(headers)
        for values in dict_data.values():
            writer.writerow(values)

