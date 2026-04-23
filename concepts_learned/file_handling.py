#Importing and parse a text file (New concept learned)

# 1) File handling with open() + with (read, append, write)

login_data = """username,ip_address,time,date
tshah,192.168.92.147,15:26:08,2022-05-10
dtanaka,192.168.98.221,9:45:18,2022-05-09
tmitchel,192.168.110.131,14:13:41,2022-05-11
daquino,192.168.168.144,7:02:35,2022-05-08
eraab,192.168.170.243,1:45:14,2022-05-11
jlansky,192.168.238.42,1:07:11,2022-05-11
acook,192.168.52.90,9:56:48,2022-05-10
asundara,192.168.58.217,23:17:52,2022-05-12
jclark,192.168.214.49,20:49:00,2022-05-10
cjackson,192.168.247.153,19:36:42,2022-05-12
jclark,192.168.197.247,14:11:04,2022-05-12
apatel,192.168.46.207,17:39:42,2022-05-10
mabadi,192.168.96.244,10:24:43,2022-05-12
iuduike,192.168.131.147,17:50:00,2022-05-11
abellmas,192.168.60.111,13:37:05,2022-05-10
gesparza,192.168.148.80,6:30:14,2022-05-11
cgriffin,192.168.4.157,23:04:05,2022-05-09
alevitsk,192.168.210.228,8:10:43,2022-05-08
eraab,192.168.24.12,11:29:27,2022-05-11
jsoto,192.168.25.60,5:09:21,2022-05-09
"""

login_file_path = "data/login.txt"
allow_list_path = "data/allow_list.txt"

# Writing the login data to a file (w)
with open(login_file_path, "w") as file:
    file.write(login_data)

# Read the file back (r)
with open(login_file_path, "r") as file:
    text = file.read()

print(text)
print(text.split("\n"))  # split into parts by line
print()  # readability spacer


# Append a missing log entry (a)
missing_entry = "jrafael,192.168.243.140,4:56:27,2022-05-09\n"

with open(login_file_path, "a") as file:
    file.write(missing_entry)

with open(login_file_path, "r") as file:
    updated_text = file.read()

print(updated_text)

print()  # readability spacer


# Write an allow list file (w) then read it back (r)
ip_addresses = (
    "192.168.218.160 192.168.97.225 192.168.145.158 192.168.108.13 "
    "192.168.60.153 192.168.96.200 192.168.247.153 192.168.3.252 "
    "192.168.116.187 192.168.15.110 192.168.39.246"
)

print(allow_list_path)
print(ip_addresses)

with open(allow_list_path, "w") as file:
    file.write(ip_addresses)

with open(allow_list_path, "r") as file:
    allow_list_text = file.read()

print(allow_list_text)

print()  # readability spacer


# 2a) Updating an allow list file by removing revoked IP addresses (New concept learned)

print("#2a")

remove_list = ["192.168.97.225", "192.168.158.170", "192.168.201.40", "192.168.58.57"]

print(allow_list_path)
print(remove_list)

with open(allow_list_path, "r") as file:
    ip_addresses = file.read().split()

updated_ips = [ip for ip in ip_addresses if ip not in remove_list]

with open(allow_list_path, "w") as file:
    file.write(" ".join(updated_ips))

print(updated_ips)
remove_list_path = "data/remove_list"
updated_ips_path = "data/updated_ips"

print()  # readability spacer


# 2b) Putting the same logic into a reusable function

print("#2b")


def update_allow_list(file_path, revoked_ips):
    with open(file_path, "r") as file:
        ip_addresses = file.read().split()

    updated_ips = [ip for ip in ip_addresses if ip not in revoked_ips]

    with open(file_path, "w") as file:
        file.write(" ".join(updated_ips))

    return updated_ips


updated_ips = update_allow_list(allow_list_path, remove_list)
print(updated_ips)
