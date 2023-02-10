#! /usr/bin/env python

import hashlib
import json
import os
import sys


def hash_package(root):
    """
    Compute an md5 hash of all files under root, visiting them in deterministic order.
    `package.json` files are stripped of their `name` and `version` fields.
    """
    m = hashlib.md5()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            m.update(f"{os.path.relpath(path, root)}\n".encode("utf-8"))
            if filename == "package.json":
                pkg = json.load(open(path))
                pkg["name"] = ""
                pkg["version"] = ""
                m.update(json.dumps(pkg, sort_keys=True).encode("utf-8"))
            else:
                with open(path, "rb") as f:
                    m.update(f.read())
    return m.hexdigest()


def add_hash_to_file(root_dir) -> None:
    """
    This function calculates the hash of the packages and saves it to a CSV file named hash.csv.

    Args:
        root_dir: The full path to the directory that contains the packages

    Returns:
        None
    """
    full_path = "/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data"
    file_name = "hash.csv"
    hash_path = full_path + "/" + file_name

    # Load the existing hashes into a list
    hashes = []
    if os.path.exists(hash_path):
        with open(hash_path, "r") as file:
            for line in file:
                hashes.append(line.strip())

    # Write new hashes to the file
    with open(hash_path, "a") as file:
        for folder in os.listdir(root_dir):
            folder_path = os.path.join(root_dir, folder)
            if os.path.isdir(folder_path):
                hash = hash_package(folder_path)
                if hash not in hashes:
                    file.write(f"{hash}\n")
                    hashes.append(hash)
  


if __name__ == "__main__":
    root_dir = "/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/training_data/benign" 
    add_hash_to_file(root_dir)
    # if len(sys.argv) < 2:
    #     print(f"Usage: {sys.argv[0]} <package directory>", file=sys.stderr)
    #     print(f"  Prints an md5 hash of all files in the given package directory, ignoring package name and version.", file=sys.stderr)
    #     sys.exit(1)
    # print(hash_package(sys.argv[1]))
