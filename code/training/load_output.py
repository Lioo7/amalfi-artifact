import pickle

file = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/code/training/output.bin'

with open(file, "rb") as f:
    obj = pickle.load(f)
    
print(obj)