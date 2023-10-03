# -*- coding: utf-8 -*-
"""Main module."""
from meraki_syslog_parser.meraki_mx_syslog_parser import MerakiMXSyslogParser

if __name__ == "__main__":

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
