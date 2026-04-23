##Scenario
# I'm given a log file string and each line contains username IP_address status and my job is to:
# 1.	Extract usernames and IPs using regex
# 2.	Count FAILED attempts per user
# 3.	Flag any user with 3 or more FAILED attempts
# 4.	Print a clean report

log_data = """kaz 192.168.1.10 SUCCESS
segun 192.168.1.11 FAILED
segun 192.168.1.11 FAILED
john 192.168.1.15 SUCCESS
segun 192.168.1.11 FAILED
kazeem 192.168.1.10 FAILED
kazeem 192.168.1.10 FAILED
kazeem 192.168.1.10 FAILED
"""
# 1.	Extract usernames and IPs using regex

import re

ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
user_pattern = r"(se\w+|j\w+|k\w+)"
status_pattern = r"(SUCCESS|FAILED)"

ip_addresses = re.findall(ip_pattern, log_data)
usernames = re.findall(user_pattern, log_data)
login_status = re.findall(status_pattern, log_data)

print("IPs:", ip_addresses)
print("Usernames:", usernames)
print("Status:", login_status)


# 2 & 3.	Count FAILED attempts per user. Flag any user with 3 or more FAILED attempts
print()
log_list = log_data.strip().split("\n")

print("Log list:", log_list)
print()


failed_counts = {}

for log in log_list:
    parts = log.split()
    username = parts[0]
    ip = parts[1]
    login_status = parts[2] 
    if login_status == "FAILED":
        if username not in failed_counts:
            failed_counts[username] = 1
        else:
            failed_counts[username] += 1
print(failed_counts)            



for user, count in failed_counts.items():
    print("User", user, "login attempt failed", count, "times")
    
    if count >= 3:
        print("ALERT: Possible brute-force attack detected for user:", user)

# more practice on dictionaries
failed_logins = ["segun", "john", "segun", "segun", "mary", "john"]

failed_count = {}
for user in failed_logins:
    if user not in failed_count:
        failed_count[user] = 1
    else:
        failed_count[user] += 1

for user, count in failed_count.items():
    if count >= 3:
        print("alert: brute forces attack on user:", user)
        print(user, "attempt to login failed", count, "times")
#more
devices = {
    "segun": "device01",
    "john": "device02",
    "mary": "device03"
}

print("assigned device for Mr. John is", devices["john"])


# Pathlib, OS, and Argparse exercises.
from pathlib import Path
import os
import argparse


