

class SRPException(Exception):
    """Base srptools exception class."""


class SRPClientException(SRPException):
    """Client session srp exception."""


class SRPServerException(SRPException):
    """Server session srp exception."""
