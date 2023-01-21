from tree_sitter import Language, Parser

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
    # Open the file using the open() function, specifying the mode as 'r' for reading.
    file = open(file_name + '.js', 'r')
    # Read the contents of the file using the read() method
    code = file.read()
    # Parse the file and get the syntax tree
    tree = parser.parse(bytes(code, 'utf-8'))
    root_node = tree.root_node
    return root_node

def search_keyword_in_code(root_node, search_string):
    found = False
    for child in root_node.children:
        if child.text.decode() == search_string:
            found = True
            break
        else:
            found = search_keyword_in_code(child, search_string)
            if found:
                break
    return found
