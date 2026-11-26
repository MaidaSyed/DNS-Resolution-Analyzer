"""Do53, DoT and DoH clients (F4, F5)."""
from .common import QueryResult
from .do53 import Do53Client
from .doh import DoHClient
from .dot import DoTClient

__all__ = ["QueryResult", "Do53Client", "DoTClient", "DoHClient"]