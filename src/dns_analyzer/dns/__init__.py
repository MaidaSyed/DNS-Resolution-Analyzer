"""DNS message encoding/decoding (F1)."""
from .codec import (
    DNSEncodeError, DNSError, DNSFormatError, Message, decode_name,
    encode_name, make_query, normalize_name,
)
from .records import (
    Edns, Flags, MxData, Opcode, Question, RClass, Rcode, ResourceRecord,
    RType, SoaData, rcode_to_text, text_to_type, type_to_text,
)

__all__ = [
    "DNSEncodeError", "DNSError", "DNSFormatError", "Message", "decode_name",
    "encode_name", "make_query", "normalize_name", "Edns", "Flags", "MxData",
    "Opcode", "Question", "RClass", "Rcode", "ResourceRecord", "RType",
    "SoaData", "rcode_to_text", "text_to_type", "type_to_text",
]
