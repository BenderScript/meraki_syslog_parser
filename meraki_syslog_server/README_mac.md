# MAC Address Anonymizer
This script anonymizes all MAC addresses in a given log file. It replaces each unique MAC address with a randomly generated one and writes the anonymized logs to a new file.

## Usage

Replace 'meraki_events.log' with the path to your log file.
Run the script. It will create a new file with the same name as your original file but with _mac_rand.log appended to the name. This new file contains the anonymized logs.

## Functions
- `anonymize_mac(log_entry, mac_dict)`: Replace all MAC addresses in a log entry with randomly generated ones.
- `generate_random_mac(match, mac_dict)`: Generate a random MAC address for a given match.
- `read_log_entries(file_path)`: Read all log entries from a file.
- `write_log_entries(file_path, log_entries)`: Write all log entries to a file.

## Dependencies
This script requires Python 3 and uses the re, random, and os modules from the Python Standard Library. No additional installation is necessary.

## Notes

The same approach can be used to anonymize IP addresses