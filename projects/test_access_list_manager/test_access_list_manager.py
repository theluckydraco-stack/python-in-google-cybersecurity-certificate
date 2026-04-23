from datetime import datetime
ALLOW_LIST_IP_PATH = "data/allow_list.txt"
REMOVE_LIST_IP_PATH = "data/remove_list.txt"
AUDIT_LOG_PATH = "data/audit_log.txt"

def read_ip_file(file_path):
    with open(file_path, "r") as file:
        return file.read().split()

def write_ip_file(file_path, ip_list):
    with open(file_path, "w") as file:
        file.write("\n".join(ip_list))

def append_audit_log(file_path, removed_ips):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(file_path, "a") as file:
        file.write(f"{timestamp} | Removed IPs: {', '.join(removed_ips)}\n")

def update_allow_list(allow_list_file, remove_list_file):
    allow_list = read_ip_file(allow_list_file)
    remove_list = read_ip_file(remove_list_file)

    removed_ips = []
    updated_ips = []
    original_count = len(allow_list)

    for ip in allow_list:
        if ip in remove_list:
            removed_ips.append(ip)
        else:
            updated_ips.append(ip)
    
    if len(removed_ips) == 0:
        print("No IPs were removed. Allow list is up to date.")
        return
    write_ip_file(allow_list_file, updated_ips)
    append_audit_log(AUDIT_LOG_PATH, removed_ips)

    print("Original allow list count:", original_count)
    print("IPs removed:", len(removed_ips))
    print("Updated allow list count:", len(updated_ips))
    print("Removed IPs:", removed_ips)
    print()  # readability spacer
    

update_allow_list(ALLOW_LIST_IP_PATH, REMOVE_LIST_IP_PATH) 