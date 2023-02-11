import os
import math
from typing import Literal
import logging

def calculate_entropy(data) -> float | Literal[0]:
    """
    Calculates the entropy of the input data.

    Parameters:
        data (bytes): binary data to calculate the entropy for.

    Returns:
        entropy (float): the entropy of the input data.
    """
    
    logging.info("start func: calculate_entropy")

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

def extract_is_minified_feature(directory_path) -> Literal[1, 0]:
    """
    Extracts the is_minified feature from the files in the directory.

    Parameters:
        directory_path (str): the path to the directory to extract features from.

    Returns:
        is_minified (int): 1 if the code is minified, 0 otherwise.
    """
    
    logging.info("start func: extract_is_minified_feature")
    
    # Store the entropy values of each file in the directory
    entropy_values = []

    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            logging.debug(f'filename: {filename}')
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                logging.debug('ignore')
                continue
            
            # Construct the file path for each file
            file_path = os.path.join(dirpath, filename)
            # Read the contents of the file as binary data
            with open(file_path, "rb") as f:
                data = f.read()
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
        AVG_ENTROPY_THRESHOLD = 4.6
        STD_DEV_ENTROPY_THRESHOLD = 0.5
        if avg_entropy > AVG_ENTROPY_THRESHOLD and std_dev_entropy > STD_DEV_ENTROPY_THRESHOLD:
            is_minified = 1          
    
    logging.info(f'avg_entropy: {avg_entropy}')
    logging.info(f'std_dev_entropy: {std_dev_entropy}')
    logging.info(f'is_minified: {is_minified}')
    return is_minified


