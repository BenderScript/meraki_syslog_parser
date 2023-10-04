import re
import random
import os


def anonymize_mac(log_entry, mac_dict):
    """
    Replace all MAC addresses in a log entry with randomly generated ones.

    Args:
        log_entry (str): The log entry to anonymize.
        mac_dict (dict): A dictionary mapping original MAC addresses to their anonymized versions.

    Returns:
        str: The anonymized log entry.
    """
    mac_address_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
    return re.sub(mac_address_pattern, lambda match: generate_random_mac(match, mac_dict), log_entry)


def generate_random_mac(match, mac_dict):
    """
    Generate a random MAC address for a given match.

    Args:
        match (re.Match): The regex match object for the MAC address.
        mac_dict (dict): A dictionary mapping original MAC addresses to their anonymized versions.

    Returns:
        str: The randomly generated MAC address.
    """
    old_mac = match.group()
    if old_mac not in mac_dict:
        mac_dict[old_mac] = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
    return mac_dict[old_mac]


def read_log_entries(file_path):
    """
    Read all log entries from a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        list: A list of log entries.
    """
    with open(file_path, 'r') as file:
        return [line.rstrip() for line in file.readlines()]


def write_log_entries(file_path, log_entries):
    """
    Write all log entries to a file.

    Args:
        file_path (str): The path to the file.
        log_entries (list): A list of log entries.
    """
    with open(file_path, 'w') as file:
        file.write("\n".join(log_entries))


mac_dict = {}
file_path = 'meraki_firewall.log'  # replace with your file path
log_entries = read_log_entries(file_path)

for i, log_entry in enumerate(log_entries):
    log_entries[i] = anonymize_mac(log_entry, mac_dict)

new_file_path = os.path.splitext(file_path)[0] + '_mac_rand.log'
write_log_entries(new_file_path, log_entries)
