import os
import logging
from typing import Literal


def extract_is_has_no_content(directory_path: str) -> Literal[1, 0]:
    """
    The function takes in a directory path as input and returns 1 if the directory does not contain any '.js' or '.ts' files, and 0 otherwise.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns 1 if the directory does not contain any '.js' or '.ts' files and 0 otherwise.
    
    """
    logging.debug("start func: extract_is_has_no_content")
        
    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                continue
            else:
                return 0
        
    return 1
