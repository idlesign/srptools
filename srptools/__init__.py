from .context import SRPContext
from .client import SRPClientSession
from .server import SRPServerSession
from .exceptions import SRPException
from .utils import hex_from_b64


VERSION = (1, 0, 1)

try:
    from importlib.metadata import version as _v
    __version__ = _v(__name__)
except Exception:
    __version__ = ".".join(str(v) for v in VERSION)

try:
    from importlib.metadata import version as _v
    __version__ = _v(__name__)
except Exception:
    __version__ = ".".join(str(v) for v in VERSION)