# practice.py


# 1) Failure rate calculator (New concept learned)
def calculate_failure(total_attempts, failed_attempts):
    rate = failed_attempts / total_attempts
    print("Rate of failure so far is:", rate)
    return rate

    if total_attempts == 0:
        print("No attempts made yet. Failure rate cannot be calculated.")
        return None
    if failed_attempts > total_attempts:
        print("Error: Failed attempts cannot exceed total attempts.")
        return None

# 2) Reading rate calculator
def reading_rate(number_of_days, days_read):
    rate = days_read / number_of_days
    print("Your rate of reading is:", rate)
    return rate


# Failure calculation
print("#1")
fail_rate = calculate_failure(100, 28)

if fail_rate > 0.30:
    print("Rate is above 30%. Do something about it.")
else:
    print("Rate is below 30%. You're okay for now.")

print()  # blank line for readability


# Reading rate calculation
print("#2")
lockin_rate = reading_rate(115, 30)

if lockin_rate < 0.50:
    print("Awful, brother. Lock in harder. Wasted zero days this month. MINIMUM.")
else:
    print("Nailing it man!")

print() # blank line for readability
 
# 3) creating more functions to work with a list of "failed login attempts per month" to prepare it for analysis (New concept learned)
print("#3")

def analyze_logins(username, current_day_logins, average_day_logins):
    print("Current day login total for", username, "is", current_day_logins)
    print("Average logins per day for", username, "is", average_day_logins)

    # Calculate the ratio of the logins made on the current day to the logins made on an average day, storing in a variable named `login_ratio`

    login_ratio = current_day_logins / average_day_logins

    # Return the ratio

    return login_ratio

login_analysis = analyze_logins("ejones", 18, 3)

# Alert condition: if today's logins are > 3x the average
if login_analysis > 3:
    print("Alert! This account has more login activity than normal.")
else:
    print("Login activity within expected range.")
    
print() # blank line for readability

# 4) STRINGS + TYPE CASTING + SLICING (New concept learned)
print("#4")

#  A) Type casting: int -> str 
employee_id = 4186
print(type(employee_id))  # <class 'int'>

employee_id = str(employee_id)
print(type(employee_id))  # <class 'str'>


#  B) Length checks + updating the string 
# Goal: ensure employee_id meets length requirement (>= 5)

if len(employee_id) < 5:
    print("This employee ID has less than five digits. It does not meet length requirements.")

print(employee_id)  # before update

if len(employee_id) < 5:
    employee_id = employee_id + "E"

print(employee_id)  # after update


print()  # readability spacer


#  C) Indexing and slicing strings 
device_id = "r262c36"

# 4th character (index 3)
print(device_id[3])

# 1st through 3rd characters (index 0 to 2). NOTE: end index is not included.
print(device_id[0:3])


print()  # readability spacer


#  D) URL slicing using .index() 
url = "https://exampleURL1.com"

# protocol + "://"
print(url[0:8])  # "https://"

# find where ".com" starts
ind = url.index(".com")
print(ind)  # index position of ".com"

# extract domain extension
print(url[ind:ind + 4])  # ".com"

# extract website name between protocol and ".com"
print(url[8:ind])  # "exampleURL1"

print()  # readability spacer

# 5) LISTS + MEMBERSHIP + INDEX MAPPING (New concept learned)
print("#5")
approved_users = ["elarson", "bmoreno", "tshah", "sgilmore", "eraab"]
approved_devices = ["8rp2k75", "hl0s5o1", "2ye3lzg", "4n482ts", "a307vir"]

# Indexing or Synchronization (user + device at the same position)
print("user at index 3:", approved_users[3])
print("device at index 3:", approved_devices[3])

print()

# Add a new approved user + device
new_user = "gesparza"
new_device = "3rcv4w6"
approved_users.append(new_user)
approved_devices.append(new_device)

print("updated users:", approved_users)
print("updated devices:", approved_devices)

print()

# Remove a user + device (employee left)
removed_user = "tshah"
removed_device = "2ye3lzg"
approved_users.remove(removed_user)
approved_devices.remove(removed_device)

print("users after removal:", approved_users)
print("devices after removal:", approved_devices)

print()

# Membership check (impersonation example)
username = "sgiglmore"  # typo/impersonation example
if username in approved_users:
    print(username, "is approved to access the system.")
else:
    print(username, "is NOT approved to access the system.")

print()

# Find a user's assigned device using index mapping
username = "sgilmore"
ind = approved_users.index(username)
print("index of", username, "is", ind)
print("assigned device is:", approved_devices[ind])

print()

# Wrap the access check into a function
# Remember the approved devices and devices:
# approved_users = ["elarson", "bmoreno", "tshah", "sgilmore", "eraab"] 
# approved_devices = ["8rp2k75", "hl0s5o1", "2ye3lzg", "4n482ts", "a307vir]

def login(username, device_id):
    if username not in approved_users:
        print("The username", username, "is not approved to access the system.")
        return

    ind = approved_users.index(username)
    assigned_device = approved_devices[ind]

    if device_id == assigned_device:
        print("The user", username, "is approved, and", device_id, "is their assigned device.")
    else:
        print("The user", username, "is approved, but", device_id, "is not their assigned device.")

login("bmoreno", "hl0s5o1")
login("elarson", "r2s5r9g")
login("abernard", "4n482ts")  

print()  # readability spacer

# 6) REGEX + LOG ANALYSIS (New concept learned)

import re

print("#6")

# A) Extract device IDs that start with "r15" to check for a specific model of device that may be vulnerable to a known exploit

devices = (
    "r262c36 67bv8fy 41j1u2e r151dm4 1270t3o 42dr56i r15xk9h "
    "2j33krk 253be78 ac742a1 r15u9q5 zh86b2l ii286fq 9x482kt "
    "6oa6m6u x3463ac i4l56nq g07h55q 081qc9t r159r1u"
)

device_pattern = r"r15\w+"
matching_devices = re.findall(device_pattern, devices)

print("Devices starting with r15:", matching_devices)

print()


# B) Extract IP addresses from log file and filter out invalid ones

log_file = (
    "eraab 2022-05-10 6:03:41 192.168.152.148 \n"
    "iuduike 2022-05-09 6:46:40 192.168.22.115 \n"
    "smartell 2022-05-09 19:30:32 192.168.190.178 \n"
    "arutley 2022-05-12 17:00:59 1923.1689.3.24 \n"
    "rjensen 2022-05-11 0:59:26 192.168.213.128 \n"
    "aestrada 2022-05-09 19:28:12 1924.1680.27.57 \n"
    "asundara 2022-05-11 18:38:07 192.168.96.200 \n"
    "dkot 2022-05-12 10:52:00 1921.168.1283.75 \n"
    "abernard 2022-05-12 23:38:46 19245.168.2345.49 \n"
    "cjackson 2022-05-12 19:36:42 192.168.247.153 \n"
    "jclark 2022-05-10 10:48:02 192.168.174.117 \n"
    "alevitsk 2022-05-08 12:09:10 192.16874.1390.176 \n"
    "jrafael 2022-05-10 22:40:01 192.168.148.115 \n"
    "yappiah 2022-05-12 10:37:22 192.168.103.10654 \n"
    "daquino 2022-05-08 7:02:35 192.168.168.144"
)

# Improved IP pattern (1–3 digits per octet) to filter out invalid IP addresses
ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

valid_ip_addresses = re.findall(ip_pattern, log_file)

print("Extracted IP addresses:", valid_ip_addresses)

print()


# C) Comparing extracted IPs against a flagged list of IPs that have been associated with suspicious activity to determine if any of the logins require further analysis

flagged_addresses = [
    "192.168.190.178",
    "192.168.96.200",
    "192.168.174.117",
    "192.168.168.144"
]

for address in valid_ip_addresses:
    if address in flagged_addresses:
        print("The IP address", address, "has been flagged for further analysis.")
    else:
        print("The IP address", address, "does not require for further analysis.")