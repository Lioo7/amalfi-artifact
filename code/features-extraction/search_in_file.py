from tree_sitter import Language, Parser
import logging

LOGֹ_FORMAT = "%(levelname)s, time: %(asctime)s , line: %(lineno)d- %(message)s "
# create and configure logger
logging.basicConfig(
    filename="features-extraction-logging.log", level=logging.DEBUG, filemode="w"
)
logger = logging.getLogger()

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
    logging.info(f"start func: parse_file")
    # Open the file using the open() function, specifying the mode as 'r' for reading.
    file = open(file_name, 'r')
    # Read the contents of the file using the read() method
    code = file.read()
    # Parse the file and get the syntax tree
    tree = parser.parse(bytes(code, 'utf-8'))
    root_node = tree.root_node
    return root_node

def search_keyword_in_code_draft(root_node, keywords, sub_keywords)->bool:
  """
  TODO:
  * current situation: the function stoping after the function find the first match
  * what to improve: have to add the function the ability to count the number of occurrences of all keywords
  """
  logging.info(f"start func: search_keyword_in_code")
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
        found = search_keyword_in_code_draft(child, keywords, sub_keywords)
        if found:
            break
  
  logging.debug(f"results of search_keyword_in_code: {found}")
  return found


def search_keyword_in_code(root_node, keywords):
  """
  TODO:
  * current situation: the function stoping after the function find the first match
  * what to improve: have to add the function the ability to count the number of occurrences of all keywords
  """
  logging.info(f"start func: search_keyword_in_code")
  
  for child in root_node.children:
    # search if the child in one of the keywords
    logging.debug(f"child: {child.text.decode()}")
    for tpl in keywords:
      if child.text.decode() == tpl[0]:
          #found = True
          tpl[2] = 1
          logging.info(f"keyword found!\nThe keyword that found is: {child.text.decode()}")
          #break

    logging.debug("calling recursion")
    search_keyword_in_code(child, keywords)

  return keywords
