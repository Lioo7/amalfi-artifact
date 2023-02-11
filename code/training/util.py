import os
import csv
from datetime import datetime

def parse_date(timestamp):
    """
    Convert a timestamp string to a datetime object.

    Args:
    timestamp (str): Timestamp string in the format "%Y-%m-%dT%H:%M:%S.%fZ".

    Returns:
    datetime: The datetime object representing the timestamp.
    """
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")

def version_date(versions, feature_dir):
    """
    Get the date of a specific version.

    Args:
    versions (dict): A dictionary where the keys are strings representing package directories
                     and the values are dictionaries with version strings as keys and dates as values.
    feature_dir (str): A string representing the path to a specific feature directory.

    Returns:
    datetime: The date of the specific version. Returns None if the version is not found.
    """
    # Extract the package directory and version directory from the feature_dir path
    package_dir = os.path.dirname(feature_dir)
    version_dir = os.path.basename(feature_dir)
    
    # If the package directory is not in the versions dictionary, read the versions.csv file and store the data
    if package_dir not in versions:
        version_dates = {}
        with open(os.path.join(package_dir, "versions.csv"), "r") as versions_file:
            for row in csv.reader(versions_file):
                version, timestamp = row
                date = parse_date(timestamp)
                version_dates[version] = date
        versions[package_dir] = version_dates

    # Return the date for the specific version directory, or None if the version is not found
    return versions[package_dir][version_dir] if version_dir in versions[package_dir] else None
