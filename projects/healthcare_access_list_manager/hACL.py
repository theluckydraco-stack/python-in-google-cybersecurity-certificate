# Healthcare Access List Manager
# This script manages the allow list for healthcare access. It also logs changes to an audit log with timestamps.
#this serves as a place to practice more with the healthcare script, make and break stuff.

from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent #means the current location of the script py file, it's parent folder
DATA_DIR = BASE_DIR / "data" # concatenating "data_test" directory to the BASE_DIR path to include where it's located


#now for the file paths

ALLOW_LIST_PATH = DATA_DIR / "allow_list.txt"
REMOVE_LIST_PATH = DATA_DIR / "remove_list.txt"
ADD_LIST_PATH = DATA_DIR / "add_list.txt"
AUDIT_LOG_PATH = DATA_DIR / "audit_log.txt"
ACCESS_REVIEW_NOTES_PATH = DATA_DIR / "access_review_notes.txt"
EMPLOYEE_ACCESS_PATH = DATA_DIR / "employee_access.csv"
SUBNET_POLICY_PATH = DATA_DIR / "subnet_policy.txt"

# to know to check if files are present before running script

required_files = [ALLOW_LIST_PATH, REMOVE_LIST_PATH, ADD_LIST_PATH, AUDIT_LOG_PATH]
all_files_present = True
for file in required_files:
    if file.exists():
        print(f"Filename: {file.name} found")
    else:
        print(f"ERROR: Filename: {file.name} is missing.")
        all_files_present = False
    
if not all_files_present:
    print("One or more file missing. Exiting...")
    exit()

    
# (1) Defining functions needed on files:

# (a) Function to read a file and return its contents as a list
"""This function takes a file path as input and attempts to open the specified file in read mode.
If the file is found, it reads the contents of the file,
splits it into a list of lines, and returns this list. 
If the file is not found, it prints an error message indicating that the file could not be found and that data cannot be read.
"""

def read_file(file_path):
    try:
        with open(file_path, "r") as file:
            return file.read().split()
    except FileNotFoundError:
        print(f"ERROR: File {file_path} not found. Unable to read file.")
        return []




# (b) for writing to files
"""It takes a file path and a list of IP addresses as input.
then attempts to open the specified file in write mode and writes the IP addresses to the file,
each on a new line. If the file is not found, it prints an error message
indicating that the file could not be found and that data cannot be written.
"""
def write_file(file_path, updated_list):
    try:
        with open(file_path, "w") as file:
            file.write("\n".join(updated_list))
    except FileNotFoundError:
        print(f"File {file_path} not found. Unable to write file.")

# (c) to log changes to audit_log.txt
"""The function takes the file path of the audit log and lists of
removed, added, absent, and skipped IPs as input.
It formats these lists into a readable string format
and appends an entry to the audit log with a timestamp. 
The entry includes details of the changes made to the access list,
such as which IPs were removed, added, skipped (due to being duplicates), and absent (expected but not found).
This helps maintain a record of all modifications for auditing purposes.
"""
def append_audit_log(file_path, removed_ips, added_ips, invalid_ips):


    removed_text = ",".join(removed_ips)
    added_text = ",".join(added_ips)
    invalid_text = ",".join(invalid_ips) #skipped due to being invalid

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") #to get current timestamp in a readable format

    with open(file_path, "a") as file:
        file.write(f"{timestamp} | Removed IPs: {removed_text} | Added IPs: {added_text} | Invalid IPs: {invalid_text}\n")

# (d) a function to validate IP addresses in a list and separate valid and invalid ones
"""This function takes a list of IP addresses as input
and checks each IP address for validity.
It splits the IP address into its four octets and checks if each octet is a number between 0 and 255. 
If an IP address is valid, it is added to the valid_ips list;
if it is invalid, it is added to the invalid_ips list.
The function returns both lists for further processing.
"""
def validate_ip_list(ip_list, audit_log_path):
    valid_ips = []
    invalid_ips = []
    for ip in ip_list:
        parts = ip.split(".")
        if len(parts) != 4:
            invalid_ips.append(ip)
            continue
        is_valid = True
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                is_valid = False
                break
        if is_valid:
            valid_ips.append(ip)
        else:
            invalid_ips.append(ip)
    #logging invalid_ips as skipped_ips
    append_audit_log(audit_log_path, [], [], invalid_ips)
    print("List validated. Invalid IPs have been skipped and logged")
    ip_list[:] = valid_ips
    return ip_list
        
        
# (e) a function to detect and remove duplicate ips
"""This function iterates through the list of IP addresses and uses a set to track seen IPs.
If an IP is encountered that has already been seen,
it is considered a duplicate and is not added to the unique_ips list.
A message is printed for each duplicate detected and removed.
"""
def remove_duplicate(ip_list):
    unique_ips = []
    seen = set()
    for ip in ip_list:
        if ip not in seen:
            unique_ips.append(ip)
            seen.add(ip)
        else:
            print("Duplicate IP(s) detected and removed") #note: I decided not to log or print out duplicates to avoid exposing duplicate IPs from inputs.
    ip_list[:] = unique_ips
    return ip_list




# defining a function to update the allowlist by revoking some ips, or adding some if an add list is provided, then log the changes.
def update_allow_list(allow_file, remove_file, add_file=None):
    allow_list = read_file(allow_file)
    remove_list = read_file(remove_file)
    if add_file != None:
        add_list = read_file(add_file)
        
        add_list = remove_duplicate(add_list)
        add_list = validate_ip_list(add_list, AUDIT_LOG_PATH)
    else:
        add_list = []

    print("Original allow list count:", len(allow_list))

    allow_list = validate_ip_list(allow_list, AUDIT_LOG_PATH)
    allow_list = remove_duplicate(allow_list)

    remove_list = validate_ip_list(remove_list, AUDIT_LOG_PATH)
    remove_list = remove_duplicate(remove_list)

    updated_ips = []
    removed_ips = []
    added_ips = []

    for ip in remove_list:
        if ip in allow_list:
            removed_ips.append(ip)
            allow_list.remove(ip)
        else:
            print(f"{ip} does not exist in the allowlist")
    updated_ips = allow_list.copy()
    for ip in add_list:
        if ip not in allow_list:
            updated_ips.append(ip)
            added_ips.append(ip)
        else:
            continue #note: I decided not to log or print out skipped IPs from the add list because it'd expose the content of the allow_list
    
    if len(removed_ips) == 0 and len(added_ips) == 0:
        print("No changes were made, the allowlist is up to date")
    else:
        write_file(allow_file, updated_ips)
        append_audit_log(AUDIT_LOG_PATH, removed_ips, added_ips, [])

        print("Updated allowlist count:", len(updated_ips))
        print("Blacklisted IPs found and removed:", len(removed_ips))
        print("New IPs added to the allowlist:", len(added_ips))
        print()
        print("Request completed, please review audit log for more details")

if __name__ == "__main__":
    update_allow_list(ALLOW_LIST_PATH, REMOVE_LIST_PATH, ADD_LIST_PATH) # this will add new IPs and remove the ones in the remove list.

        
