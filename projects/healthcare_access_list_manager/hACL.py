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


# to know to check if files are present before running script

def check_required_files(required_files):
    
    all_files_present = True
    for file in required_files:
        if file.exists():
            print(f"Filename: {file.name} found")
        else:
            print(f"ERROR: Filename: {file.name} is missing.")
            all_files_present = False
    return all_files_present

    
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
def append_audit_log(file_path, removed_ips, added_ips, invalid_ips, duplicate_count=0):


    removed_text = ",".join(removed_ips)
    added_text = ",".join(added_ips)
    invalid_text = ",".join(invalid_ips) 
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") #to get current timestamp in a readable format

    log_entry = (f"{timestamp} | Removed IPs: {removed_text} | "
                 f"Added IPs: {added_text} | Invalid IPs: {invalid_text} | "
                 f"Duplicate Count: {duplicate_count}\n"
    )

    with open(file_path, "a") as file:
        file.write(log_entry)

# (d) a function to validate IP addresses in a list and separate valid and invalid ones
"""This function takes a list of IP addresses as input
and checks each IP address for validity.
It splits the IP address into its four octets and checks if each octet is a number between 0 and 255. 
If an IP address is valid, it is added to the valid_ips list;
if it is invalid, it is added to the invalid_ips list.
The function returns both lists for further processing.
"""
def validate_ip_list(ip_list):
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
    return valid_ips, invalid_ips
        

# (e) a function to detect and remove duplicate ips
"""This function iterates through the list of IP addresses and uses a set to track seen IPs.
If an IP is encountered that has already been seen,
it is considered a duplicate and is not added to the unique_ips list.
A message is printed for each duplicate detected and removed.
"""
def remove_duplicate(ip_list):
    unique_ips = []
    duplicate_count = 0
    seen = set()
    for ip in ip_list:
        if ip not in seen:
            unique_ips.append(ip)
            seen.add(ip)
        else:
            duplicate_count += 1
    if duplicate_count > 0:
        print("Duplicate IP(s) detected and removed") #note: I decided not to log or print out duplicates to avoid exposing duplicate IPs from inputs.
    return unique_ips, duplicate_count


# defining a function to update the allowlist by revoking some ips, or adding some if an add list is provided, then log the changes.
def update_allow_list(allow_file, remove_file, add_file=None):
    #1. Read original files   
    original_allow_list = read_file(allow_file)
    remove_list = read_file(remove_file)
    if add_file is not None:
        add_list = read_file(add_file)   
    else:
        add_list = []

    print("Original allow list count:", len(original_allow_list))
    #2. validate all three lists
    valid_allow_list, invalid_allow_ips = validate_ip_list(original_allow_list)
    valid_remove_list, invalid_remove_ips = validate_ip_list(remove_list)
    valid_add_list, invalid_add_ips = validate_ip_list(add_list)

    #3. remove duplicates and count them
    clean_allow_list, allow_duplicate_count = remove_duplicate(valid_allow_list)
    clean_remove_list, remove_duplicate_count = remove_duplicate(valid_remove_list)
    clean_add_list, add_duplicate_count = remove_duplicate(valid_add_list)


    ## We now have a clean version of all three lists: clean_allow_list, clean_remove_list, clean_add_list

    # Combining audit details (invalid_ips and duplicate counts)
    invalid_ips = invalid_allow_ips + invalid_remove_ips + invalid_add_ips

    duplicate_count = (
        allow_duplicate_count
        + remove_duplicate_count
        + add_duplicate_count
    )

    allow_list = clean_allow_list.copy()
    removed_ips = []
    added_ips = []

    for ip in clean_remove_list:
        if ip in allow_list:
            removed_ips.append(ip)
            allow_list.remove(ip)
        else:
            print(f"IP address: {ip} does not exist in the allowlist")
    
    for ip in clean_add_list:
        if ip not in allow_list:
            allow_list.append(ip)
            added_ips.append(ip)
        else:
            continue 
    allow_list_was_cleaned = clean_allow_list != original_allow_list
    if removed_ips or added_ips or allow_list_was_cleaned:
        write_file(allow_file, allow_list)
    if removed_ips or added_ips or invalid_ips or duplicate_count or allow_list_was_cleaned:
        append_audit_log(AUDIT_LOG_PATH, removed_ips, added_ips, invalid_ips, duplicate_count)

        print("Updated allowlist count:", len(allow_list))
        print("Blacklisted IPs found and removed:", len(removed_ips))
        print("New IPs added to the allowlist:", len(added_ips))
        print()
        print("Request completed, please review audit log for more details")
    else:
        print("No changes were made, the allowlist is up to date")

if __name__ == "__main__":
    required_files = [ALLOW_LIST_PATH, REMOVE_LIST_PATH, ADD_LIST_PATH]

    if not check_required_files(required_files):
        print("One or more file missing. Exiting...")
        exit()
    AUDIT_LOG_PATH.touch(exist_ok=True)
    update_allow_list(ALLOW_LIST_PATH, REMOVE_LIST_PATH, ADD_LIST_PATH)
