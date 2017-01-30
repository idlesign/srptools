

class SRPException(Exception):
    """Base srptool exception class."""


class SRPClientException(SRPException):
    """Client session srp exception."""


class SRPServerException(SRPException):
    """Server session srp exception."""
