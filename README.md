# Meraki MX Syslog Parser

This Python script provides functions to parse different types of logs: URL logs, firewall logs, and event logs. Each function uses regular expressions to extract relevant information from a log entry and returns a dictionary with the parsed data.

The Syslog server was configured following the guide here: https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Server_Overview_and_Configuration

Meraki Syslog samples can be found here: https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Event_Types_and_Log_Samples

## How to generate logs

I created this simple script to scrape the top 100 websites. You can run on a machine behind the Meraki MX, and it will generate a lot of Syslog.

https://github.com/repenno/top_100

## Functions

- `parse_url_log(log_entry: str) -> dict`: Parses URL logs.
- `parse_firewall_log(log_entry: str) -> dict`: Parses firewall logs.
- `parse_event_log(log_entry: str) -> dict`: Parses event logs.


## Regular Expressions Used

Let's break down the regular expressions used in the script:

1. **parse_url_log method:**

   The regular expression pattern used in this method is designed to match URL log entries. Here's a breakdown of the pattern:

   - `(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`: This part of the pattern matches the date. `\w{3}` matches any word character (equal to [a-zA-Z0-9_]) exactly 3 times, which corresponds to the three-letter abbreviation for the day of the week (Mon, Tue, etc.). `\s+` matches any whitespace character (spaces, tabs, line breaks) one or more times. `\d{1,2}` matches any digit (equal to [0-9]) between 1 and 2 times, which corresponds to the day of the month (1-31). `\d{2}:\d{2}:\d{2}` matches the time in HH:MM:SS format.
   
   - `(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`: This part of the pattern matches an IP address. `\d{1,3}` matches any digit between 1 and 3 times, which corresponds to each octet of an IP address (0-255). The `\.` matches a literal dot.

   - `(?P<id>\d+\.\d+)`: This part of the pattern matches an ID that consists of one or more digits, a dot, and one or more digits.

   - `(?P<user>\w+)`: This part of the pattern matches a username that consists of one or more word characters.

   - `(?P<type>\w+)`: This part of the pattern matches a type that consists of one or more word characters.

   - `src=(?P<src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)`: This part of the pattern matches a source IP address and port. The structure is similar to the IP address pattern above, but with `:\d+` at the end to match the port number.

   - `dst=(?P<dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)`: This part of the pattern matches a destination IP address and port. The structure is similar to the source IP address and port pattern above.

   - `mac=(?P<mac>[0-9A-Fa-f:]{17})`: This part of the pattern matches a MAC address. `[0-9A-Fa-f:]` matches any digit or letter from A to F (in either uppercase or lowercase) or a colon. `{17}` specifies that this pattern should be exactly 17 characters long to match a MAC address format.

   - `agent='(?P<agent>.+?)'`: This part of the pattern matches a user agent string enclosed in single quotes.

   - `request:\s+(?P<request>\w+\s+\w+://.+)`: This part of the pattern matches a request method and URL.


2. **parse_firewall_log method:**

   The regular expression pattern used in this method is designed to match firewall log entries. It's similar to the URL log entry pattern but includes additional fields specific to firewall logs such as protocol, sport (source port), dport (destination port), and pattern.


3. **parse_event_log method:**

   The regular expression pattern used in this method is designed to match event log entries. It's similar to the previous patterns but includes additional fields specific to event logs such as event_type, url, category (optional), server, and client_mac.

Each group in these patterns is named using `?P<name>`, which makes it easier to extract specific pieces of information from a log entry.

## Simple Usage

```python
    fw_log_entry = "Oct  2 21:22:43 192.168.128.1 1 1696306963.825147405 satosugu firewall src=fe80::cde:941e:d4ef:3d22 dst=ff02::fb protocol=udp sport=5353 dport=5353 pattern: 1 all"
    parsed_log = MerakiMXSyslogParser.parse_firewall_log(fw_log_entry)
    print(parsed_log)

    url_log_entry = "Oct  2 21:18:42 192.168.128.1 1 1696306722.864107379 satosugu urls src=192.168.128.3:58754 dst=192.229.211.108:80 mac=0C:4D:E9:BE:F4:B2 agent='Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0' request: POST http://ocsp.digicert.com/"
    parsed_log = MerakiMXSyslogParser.parse_url_log(url_log_entry)
    print(parsed_log)

    event_log_entry = "Oct  2 21:09:28 192.168.128.1 1 1696306168.009553886 satosugu events content_filtering_block url='https://youtube.com/...' category0='User-defined Blacklist' server='192.178.50.78:443' client_mac='0C:4D:E9:BE:F4:B2'"
    parsed_log = MerakiMXSyslogParser.parse_event_log(event_log_entry)
    print(parsed_log)

    event_log_entry = "Oct  2 21:12:00 192.168.128.1 1 1696306320.822027826 satosugu events content_filtering_block url='https://xvideos.com/...' server='185.88.181.2:443' client_mac='0C:4D:E9:BE:F4:B2'"
    parsed_log = MerakiMXSyslogParser.parse_event_log(event_log_entry)
    print(parsed_log)

```

## Output

The output of each function is a dictionary with the parsed data from the log entry.

```python
{'date': 'Oct  2 21:22:43', 'ip': '192.168.128.1', 'id': '1696306963.825147405', 'user': 'satosugu', 'type': 'firewall', 'src': 'fe80::cde:941e:d4ef:3d22', 'dst': 'ff02::fb', 'protocol': 'udp', 'sport': '5353', 'dport': '5353', 'pattern': '1 all'}
{'date': 'Oct  2 21:18:42', 'ip': '192.168.128.1', 'id': '1696306722.864107379', 'user': 'satosugu', 'type': 'urls', 'src': '192.168.128.3:58754', 'dst': '192.229.211.108:80', 'mac': '0C:4D:E9:BE:F4:B2', 'agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0', 'request': 'POST http://ocsp.digicert.com/'}
{'date': 'Oct  2 21:09:28', 'ip': '192.168.128.1', 'id': '1696306168.009553886', 'user': 'satosugu', 'type': 'events', 'event_type': 'content_filtering_block', 'url': 'https://youtube.com/...', 'category': 'User-defined Blacklist', 'server': '192.178.50.78:443', 'client_mac': '0C:4D:E9:BE:F4:B2'}
{'date': 'Oct  2 21:12:00', 'ip': '192.168.128.1', 'id': '1696306320.822027826', 'user': 'satosugu', 'type': 'events', 'event_type': 'content_filtering_block', 'url': 'https://xvideos.com/...', 'category': None, 'server': '185.88.181.2:443', 'client_mac': '0C:4D:E9:BE:F4:B2'}
```

## Requirements

This script requires Python's built-in `re` module for regular expressions.

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

