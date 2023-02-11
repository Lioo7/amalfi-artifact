import pandas as pd

file = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/versions_extra.csv'

# Read the CSV file into a DataFrame
df = pd.read_csv(file)

# Group the data by the "Package" column
grouped = df.groupby("Package")

# Create a dictionary for each package
packages = {}
for name, group in grouped:
    package = {}
    for index, row in group.iterrows():
        version = row["Version"]
        date = row["Date"]
        package[version] = date
    packages[name] = package

# The `packages` dictionary now contains the desired information
print(packages)
