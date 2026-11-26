"""
records.py - Plain data types for DNS.

This file only describes WHAT a DNS message contains (types, flags, records).
All wire-format logic (bytes <-> objects) lives in codec.py.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class RType(enum.IntEnum):
    """Record TYPE / QTYPE values (RFC 1035, 3596, 6891)."""
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    OPT = 41      # EDNS0 pseudo-record (RFC 6891)
    ANY = 255


class RClass(enum.IntEnum):
    IN = 1
    CH = 3
    ANY = 255


class Opcode(enum.IntEnum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2


class Rcode(enum.IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


def _enum_name(enum_cls: type[enum.IntEnum], value: int, prefix: str) -> str:
    try:
        return enum_cls(value).name
    except ValueError:
        return f"{prefix}{value}"      # RFC 3597 style, e.g. TYPE99


def type_to_text(value: int) -> str:
    return _enum_name(RType, value, "TYPE")


def class_to_text(value: int) -> str:
    return _enum_name(RClass, value, "CLASS")


def rcode_to_text(value: int) -> str:
    return _enum_name(Rcode, value, "RCODE")


def opcode_to_text(value: int) -> str:
    return _enum_name(Opcode, value, "OPCODE")


def text_to_type(text: str) -> int:
    """'aaaa' -> 28, 'TYPE99' -> 99. Used by the CLI."""
    t = text.strip().upper()
    if t in RType.__members__:
        return int(RType[t])
    if t.startswith("TYPE") and t[4:].isdigit():
        return int(t[4:])
    raise ValueError(f"unknown record type: {text!r}")


@dataclass
class Flags:
    """
    The 16-bit flags word of the DNS header (RFC 1035 section 4.1.1):

      15  14-11   10  9   8   7   6  5   4   3-0
      QR  Opcode  AA  TC  RD  RA  Z  AD  CD  RCODE

    `rcode` here is only the low 4 bits; the full value may be extended by
    EDNS0 (see Message.rcode).
    """
    qr: bool = False
    opcode: int = 0
    aa: bool = False
    tc: bool = False
    rd: bool = False
    ra: bool = False
    ad: bool = False
    cd: bool = False
    rcode: int = 0

    def to_int(self) -> int:
        return (
            (int(self.qr) << 15)
            | ((self.opcode & 0xF) << 11)
            | (int(self.aa) << 10)
            | (int(self.tc) << 9)
            | (int(self.rd) << 8)
            | (int(self.ra) << 7)
            | (int(self.ad) << 5)
            | (int(self.cd) << 4)
            | (self.rcode & 0xF)
        )

    @classmethod
    def from_int(cls, value: int) -> "Flags":
        return cls(
            qr=bool(value & 0x8000),
            opcode=(value >> 11) & 0xF,
            aa=bool(value & 0x0400),
            tc=bool(value & 0x0200),
            rd=bool(value & 0x0100),
            ra=bool(value & 0x0080),
            ad=bool(value & 0x0020),
            cd=bool(value & 0x0010),
            rcode=value & 0xF,
        )

    def to_text(self) -> str:
        names = ("qr", "aa", "tc", "rd", "ra", "ad", "cd")
        return " ".join(n for n in names if getattr(self, n))


@dataclass
class Question:
    name: str
    qtype: int = RType.A
    qclass: int = RClass.IN

    def __str__(self) -> str:
        return f"{self.name} {class_to_text(self.qclass)} {type_to_text(self.qtype)}"


@dataclass
class SoaData:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


@dataclass
class MxData:
    preference: int
    exchange: str


@dataclass
class ResourceRecord:
    """
    One resource record. `rdata` is already decoded into a Python value:

      A / AAAA          -> str   ("10.10.3.30")
      NS / CNAME / PTR  -> str   (a domain name, "ns1.example.test.")
      MX                -> MxData
      SOA               -> SoaData
      TXT               -> tuple[str, ...]
      anything else     -> bytes (raw, RFC 3597 "unknown type")
    """
    name: str
    rtype: int
    ttl: int
    rdata: Any
    rclass: int = RClass.IN

    def __str__(self) -> str:
        return (f"{self.name} {self.ttl} {class_to_text(self.rclass)} "
                f"{type_to_text(self.rtype)} {rdata_to_text(self.rtype, self.rdata)}")


def rdata_to_text(rtype: int, rdata: Any) -> str:
    if isinstance(rdata, SoaData):
        return (f"{rdata.mname} {rdata.rname} {rdata.serial} {rdata.refresh} "
                f"{rdata.retry} {rdata.expire} {rdata.minimum}")
    if isinstance(rdata, MxData):
        return f"{rdata.preference} {rdata.exchange}"
    if rtype == RType.TXT:
        return " ".join(f'"{s}"' for s in rdata)
    if isinstance(rdata, (bytes, bytearray)):
        return f"\\# {len(rdata)} {bytes(rdata).hex()}"
    return str(rdata)


@dataclass
class Edns:
    """
    EDNS0 OPT pseudo-record (RFC 6891). On the wire it is stored inside the
    Additional section, but it is not a real record, so we keep it separate.

      CLASS field -> sender's UDP payload size
      TTL field   -> ext_rcode (8 bits) | version (8 bits) | DO flag + 15 zero bits
    """
    udp_payload_size: int = 1232
    ext_rcode: int = 0
    version: int = 0
    do: bool = False
    options: list[tuple[int, bytes]] = field(default_factory=list)