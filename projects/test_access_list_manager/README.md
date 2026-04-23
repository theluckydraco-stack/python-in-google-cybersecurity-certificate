# Test Access List Manager

A Python script I built to practice automating access control tasks.
It manages a list of approved IP addresses for a restricted subnet
by cross-checking it against a removal list and updating it automatically.

> This is the beginner version of this project. A more detailed version
> with additional concepts exists in the Healthcare Access List Manager.

## What it does
- Reads approved IPs from an allow list file
- Checks them against a list of IPs to revoke
- Removes flagged IPs and saves the updated list
- Records every removal in an audit log with the time it happened

## How to run
Make sure you're inside the Projects/test_access_list_manager folder, then run:
```bash
python3 test_access_list_manager.py
```