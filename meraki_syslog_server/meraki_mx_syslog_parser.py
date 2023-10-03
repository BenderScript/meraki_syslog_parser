import re


class MerakiMXSyslogParser:
    """
    A class used to parse Meraki MX Syslog logs.

    ...

    Methods
    -------
    parse_url_log(log_entry: str) -> dict:
        Parses a URL log entry.

    parse_firewall_log(log_entry: str) -> dict:
        Parses a firewall log entry.

    parse_event_log(log_entry: str) -> dict:
        Parses an event log entry.
    """

    @classmethod
    def parse_url_log(cls, log_entry):
        """
        Parses a URL log entry.

        Parameters
        ----------
        log_entry : str
            The log entry to be parsed.

        Returns
        -------
        dict
            A dictionary containing the parsed data if the log entry matches the pattern, None otherwise.
        """
        pattern = (
            r"(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,"
            r"3})\s+\d\s+(?P<id>\d+\.\d+)\s+(?P<user>\w+)\s+(?P<type>\w+)\s+src=(?P<src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,"
            r"3}:\d+)\s+dst=(?P<dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)\s+mac=(?P<mac>[0-9A-Fa-f:]{"
            r"17})\s+agent='(?P<agent>.+?)'\s+request:\s+(?P<request>\w+\s+\w+://.+)")
        match = re.search(pattern, log_entry)
        if match:
            return match.groupdict()
        else:
            return None

    @classmethod
    def parse_firewall_log(cls, log_entry):
        """
        Parses a firewall log entry.

        Parameters
        ----------
        log_entry : str
            The log entry to be parsed.

        Returns
        -------
        dict
            A dictionary containing the parsed data if the log entry matches the pattern, None otherwise.
        """
        pattern = (
            r"(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d\s+("
            r"?P<id>\d+\.\d+)\s+(?P<user>\w+)\s+(?P<type>\w+)\s+src=(?P<src>.+?)\s+dst=(?P<dst>.+?)\s+protocol=("
            r"?P<protocol>\w+)\s+sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+)\s+pattern:\s+(?P<pattern>.+)")
        match = re.search(pattern, log_entry)
        if match:
            return match.groupdict()
        else:
            return None

    @classmethod
    def parse_event_log(cls, log_entry):
        """
        Parses an event log entry.

        Parameters
        ----------
        log_entry : str
            The log entry to be parsed.

        Returns
        -------
        dict
            A dictionary containing the parsed data if the log entry matches the pattern, None otherwise.
        """

        pattern = (
            r"(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d\s+("
            r"?P<id>\d+\.\d+)\s+(?P<user>\w+)\s+(?P<type>\w+)\s+(?P<event_type>\w+)\s+url='(?P<url>.+?)'("
            r"?:\s+category0='(?P<category>.+?)')?\s+server='(?P<server>.+?)'\s+client_mac='(?P<client_mac>["
            r"0-9A-Fa-f:]{17})'")

        match = re.search(pattern, log_entry)

        if match:
            return match.groupdict()

        else:
            return None
