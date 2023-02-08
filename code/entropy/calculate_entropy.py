import collections
import math
import codecs

def calculate_entropy(code, encoding):
    decoded_code = codecs.decode(code, encoding)
    symbols = list(decoded_code)
    symbol_counts = collections.Counter(symbols)
    total_symbols = len(symbols)
    probabilities = [count / total_symbols for count in symbol_counts.values()]
    entropy = sum([-probability * math.log2(probability) for probability in probabilities])
    return entropy

# Calculate the entropy of the original code
with open("original.py", "rb") as original_file:
    original_code = original_file.read()
original_entropy = calculate_entropy(original_code, "utf-8")

# Calculate the entropy of the minified code
with open("minified.py", "rb") as minified_file:
    minified_code = minified_file.read()
minified_entropy = calculate_entropy(minified_code, "utf-8")

# Compare the entropies
if minified_entropy > original_entropy:
    print("The minified code has a higher entropy than the original code.")
else:
    print("The original code has a higher entropy than the minified code.")
