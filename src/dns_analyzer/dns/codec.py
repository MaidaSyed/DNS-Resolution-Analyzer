"""
codec.py - DNS wire format (RFC 1035) encoder and decoder, built on struct.

    Message.to_bytes()          object -> bytes   (what we put in a UDP packet)
    Message.from_bytes(data)    bytes  -> object  (what we get back)

Message layout on the wire:

    +-----------------+  12 bytes: ID, flags, 4 section counts
    | Header          |
    +-----------------+
    | Question  (QD)  |  name + QTYPE + QCLASS
    | Answer    (AN)  |  resource records
    | Authority (NS)  |  resource records (referrals live here)
    | Additional(AR)  |  resource records (glue + EDNS0 OPT live here)
    +-----------------+

All integers are big-endian ("network byte order"), hence "!" in struct formats.
"""
from __future__ import annotations

import secrets
import socket
import struct
from dataclasses import dataclass, field

from .records import (
    Edns, Flags, MxData, Question, RClass, ResourceRecord, RType, SoaData,
    opcode_to_text, rcode_to_text, type_to_text,
)

HEADER_LEN = 12
MAX_LABEL_LEN = 63            # one label: at most 63 bytes
MAX_NAME_LEN = 255            # whole name in wire form: at most 255 bytes
MAX_POINTER_OFFSET = 0x3FFF   # a compression pointer has only 14 bits of offset


class DNSError(Exception):
    """Base class for all codec errors."""


class DNSFormatError(DNSError):
    """Received bytes are not a valid DNS message."""


class DNSEncodeError(DNSError):
    """We were asked to build something that cannot be encoded."""


# --------------------------------------------------------------------------
# Domain names
# --------------------------------------------------------------------------
def normalize_name(name: str) -> str:
    """'WWW.Example.TEST' -> 'www.example.test.'  ('' or '.' -> '.')."""
    name = name.strip().lower()
    return name if name.endswith(".") else name + "."


def _split_labels(name: str) -> list[str]:
    """Validate a name and return its labels ('www.example.test.' -> 3 labels)."""
    name = normalize_name(name)
    if name == ".":
        return []
    labels = name[:-1].split(".")
    wire_len = 1                                   # the final zero byte
    for label in labels:
        if not label:
            raise DNSEncodeError(f"empty label in name {name!r}")
        if not label.isascii():
            raise DNSEncodeError(f"non-ASCII label in {name!r} (use punycode)")
        if len(label) > MAX_LABEL_LEN:
            raise DNSEncodeError(f"label longer than 63 bytes in {name!r}")
        wire_len += len(label) + 1
    if wire_len > MAX_NAME_LEN:
        raise DNSEncodeError(f"name longer than 255 bytes: {name!r}")
    return labels


def encode_name(name: str) -> bytes:
    """
    Uncompressed name: each label is <length byte><bytes>, ended by a zero byte.
    'www.example.test.' -> 03 'www' 07 'example' 04 'test' 00
    """
    out = bytearray()
    for label in _split_labels(name):
        out.append(len(label))
        out += label.encode("ascii")
    out.append(0)
    return bytes(out)


def decode_name(buf: bytes, offset: int) -> tuple[str, int]:
    """
    Read a possibly-compressed name starting at `offset`.
    Returns (name, offset of the first byte AFTER the name in the original
    position). Names come back lower-case with a trailing dot.

    Compression (RFC 1035 4.1.4): a length byte whose top two bits are 11 is
    really a 14-bit pointer to an earlier place in the message where the rest
    of the name continues. Only the first pointer matters for "where do I
    continue reading", which is what `end` tracks.

    Safety: we only accept pointers that go strictly BACKWARDS. That makes
    infinite pointer loops (a classic attack on DNS parsers) impossible.
    """
    labels: list[str] = []
    pos = offset
    end: int | None = None          # where parsing resumes after this name
    wire_len = 1
    while True:
        if pos >= len(buf):
            raise DNSFormatError("name runs past end of message")
        length = buf[pos]
        if (length & 0xC0) == 0xC0:                       # compression pointer
            if pos + 1 >= len(buf):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | buf[pos + 1]
            if end is None:
                end = pos + 2
            if pointer >= pos:
                raise DNSFormatError("compression pointer does not point backwards")
            pos = pointer
            continue
        if length & 0xC0:                                 # 01 or 10: reserved
            raise DNSFormatError("reserved label type")
        pos += 1
        if length == 0:                                   # root label: done
            break
        if pos + length > len(buf):
            raise DNSFormatError("label runs past end of message")
        wire_len += length + 1
        if wire_len > MAX_NAME_LEN:
            raise DNSFormatError("name longer than 255 bytes")
        labels.append(buf[pos:pos + length].decode("latin-1").lower())
        pos += length
    if end is None:
        end = pos
    return (".".join(labels) + "." if labels else "."), end


class _Writer:
    """
    Byte buffer that can compress names while writing them.

    `_seen` remembers where each name suffix was first written. When the same
    suffix appears again we emit a 2-byte pointer instead of repeating it:
    'example.test.' written once, later 'www.example.test.' = 03 www + pointer.
    """

    def __init__(self, compress: bool = True) -> None:
        self.buf = bytearray()
        self.compress = compress
        self._seen: dict[str, int] = {}

    def write_name(self, name: str) -> None:
        labels = _split_labels(name)           # validates too
        for i, label in enumerate(labels):
            suffix = ".".join(labels[i:])
            if self.compress and suffix in self._seen:
                self.buf += struct.pack("!H", 0xC000 | self._seen[suffix])
                return
            if len(self.buf) <= MAX_POINTER_OFFSET:
                self._seen[suffix] = len(self.buf)
            self.buf.append(len(label))
            self.buf += label.encode("ascii")
        self.buf.append(0)


# --------------------------------------------------------------------------
# Resource-record data (RDATA)
# --------------------------------------------------------------------------
def _write_rdata(w: _Writer, rtype: int, rdata) -> None:
    try:
        if rtype == RType.A:
            w.buf += socket.inet_pton(socket.AF_INET, rdata)
        elif rtype == RType.AAAA:
            w.buf += socket.inet_pton(socket.AF_INET6, rdata)
        elif rtype in (RType.NS, RType.CNAME, RType.PTR):
            w.write_name(rdata)
        elif rtype == RType.MX:
            w.buf += struct.pack("!H", rdata.preference)
            w.write_name(rdata.exchange)
        elif rtype == RType.SOA:
            w.write_name(rdata.mname)
            w.write_name(rdata.rname)
            w.buf += struct.pack("!5I", rdata.serial, rdata.refresh,
                                 rdata.retry, rdata.expire, rdata.minimum)
        elif rtype == RType.TXT:
            for text in rdata:
                raw = text.encode("utf-8")
                if len(raw) > 255:
                    raise DNSEncodeError("TXT string longer than 255 bytes")
                w.buf.append(len(raw))
                w.buf += raw
        else:
            w.buf += bytes(rdata)
    except (OSError, struct.error, AttributeError, TypeError) as exc:
        raise DNSEncodeError(f"bad rdata for type {type_to_text(rtype)}: {rdata!r}") from exc


def _need(buf: bytes, offset: int, count: int, what: str) -> None:
    if offset + count > len(buf):
        raise DNSFormatError(f"message too short while reading {what}")


def _read_rdata(rtype: int, buf: bytes, start: int, rdlength: int):
    """
    Decode RDATA. We need the WHOLE message `buf` (not just the rdata slice)
    because names inside NS/CNAME/SOA/MX can use compression pointers that
    point anywhere earlier in the message.
    """
    end = start + rdlength
    if rtype == RType.A:
        if rdlength != 4:
            raise DNSFormatError("A record rdata must be 4 bytes")
        return socket.inet_ntop(socket.AF_INET, buf[start:end])
    if rtype == RType.AAAA:
        if rdlength != 16:
            raise DNSFormatError("AAAA record rdata must be 16 bytes")
        return socket.inet_ntop(socket.AF_INET6, buf[start:end])
    if rtype in (RType.NS, RType.CNAME, RType.PTR):
        name, nxt = decode_name(buf, start)
        if nxt != end:
            raise DNSFormatError("name rdata length mismatch")
        return name
    if rtype == RType.MX:
        if rdlength < 3:
            raise DNSFormatError("MX rdata too short")
        (pref,) = struct.unpack_from("!H", buf, start)
        name, nxt = decode_name(buf, start + 2)
        if nxt != end:
            raise DNSFormatError("MX rdata length mismatch")
        return MxData(pref, name)
    if rtype == RType.SOA:
        mname, pos = decode_name(buf, start)
        rname, pos = decode_name(buf, pos)
        if pos + 20 != end:
            raise DNSFormatError("SOA rdata length mismatch")
        return SoaData(mname, rname, *struct.unpack_from("!5I", buf, pos))
    if rtype == RType.TXT:
        parts, pos = [], start
        while pos < end:
            size = buf[pos]
            pos += 1
            if pos + size > end:
                raise DNSFormatError("TXT string overruns rdata")
            parts.append(buf[pos:pos + size].decode("utf-8", errors="replace"))
            pos += size
        return tuple(parts)
    return bytes(buf[start:end])          # unknown type: keep raw bytes


# --------------------------------------------------------------------------
# Whole-record helpers
# --------------------------------------------------------------------------
def _write_rr(w: _Writer, rr: ResourceRecord) -> None:
    w.write_name(rr.name)
    w.buf += struct.pack("!HHI", rr.rtype, rr.rclass, rr.ttl)
    length_pos = len(w.buf)
    w.buf += b"\x00\x00"                           # RDLENGTH placeholder
    _write_rdata(w, rr.rtype, rr.rdata)
    struct.pack_into("!H", w.buf, length_pos, len(w.buf) - length_pos - 2)


def _write_opt(w: _Writer, edns: Edns) -> None:
    ttl = (edns.ext_rcode << 24) | (edns.version << 16) | (0x8000 if edns.do else 0)
    w.buf.append(0)                                # owner name: root
    w.buf += struct.pack("!HHI", RType.OPT, edns.udp_payload_size, ttl)
    options = b"".join(struct.pack("!HH", code, len(data)) + data
                       for code, data in edns.options)
    w.buf += struct.pack("!H", len(options)) + options


def _parse_rr(buf: bytes, offset: int):
    """Returns (ResourceRecord | Edns, next_offset)."""
    name, offset = decode_name(buf, offset)
    _need(buf, offset, 10, "record header")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", buf, offset)
    offset += 10
    _need(buf, offset, rdlength, "record data")
    if rtype == RType.OPT:
        if name != ".":
            raise DNSFormatError("OPT record must be owned by the root name")
        edns = Edns(udp_payload_size=rclass, ext_rcode=(ttl >> 24) & 0xFF,
                    version=(ttl >> 16) & 0xFF, do=bool(ttl & 0x8000))
        pos, end = offset, offset + rdlength
        while pos < end:
            if pos + 4 > end:
                raise DNSFormatError("truncated EDNS option header")
            code, size = struct.unpack_from("!HH", buf, pos)
            pos += 4
            if pos + size > end:
                raise DNSFormatError("EDNS option overruns OPT rdata")
            edns.options.append((code, bytes(buf[pos:pos + size])))
            pos += size
        return edns, end
    rdata = _read_rdata(rtype, buf, offset, rdlength)
    return ResourceRecord(name, rtype, ttl, rdata, rclass), offset + rdlength


# --------------------------------------------------------------------------
# Message
# --------------------------------------------------------------------------
@dataclass
class Message:
    id: int = 0
    flags: Flags = field(default_factory=Flags)
    questions: list[Question] = field(default_factory=list)
    answers: list[ResourceRecord] = field(default_factory=list)
    authorities: list[ResourceRecord] = field(default_factory=list)
    additionals: list[ResourceRecord] = field(default_factory=list)
    edns: Edns | None = None

    @property
    def rcode(self) -> int:
        """Full response code: 4 header bits plus 8 EDNS0 extension bits."""
        return ((self.edns.ext_rcode << 4) if self.edns else 0) | self.flags.rcode

    def to_bytes(self, compress: bool = True) -> bytes:
        if not 0 <= self.id <= 0xFFFF:
            raise DNSEncodeError("message id must fit in 16 bits")
        w = _Writer(compress)
        arcount = len(self.additionals) + (1 if self.edns else 0)
        w.buf += struct.pack("!HHHHHH", self.id, self.flags.to_int(),
                             len(self.questions), len(self.answers),
                             len(self.authorities), arcount)
        for q in self.questions:
            w.write_name(q.name)
            w.buf += struct.pack("!HH", q.qtype, q.qclass)
        for rr in (*self.answers, *self.authorities, *self.additionals):
            _write_rr(w, rr)
        if self.edns:
            _write_opt(w, self.edns)
        return bytes(w.buf)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        """
        Parse a message. If the TC (truncated) bit is set the sender cut the
        message short, so a parse error part-way through is tolerated and we
        return whatever was readable; the caller only needs the TC bit to
        know it must retry over TCP.
        """
        if len(data) < HEADER_LEN:
            raise DNSFormatError("message shorter than the 12-byte header")
        msg_id, flag_bits, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
        msg = cls(id=msg_id, flags=Flags.from_int(flag_bits))
        offset = HEADER_LEN
        try:
            for _ in range(qd):
                name, offset = decode_name(data, offset)
                _need(data, offset, 4, "question")
                qtype, qclass = struct.unpack_from("!HH", data, offset)
                offset += 4
                msg.questions.append(Question(name, qtype, qclass))
            for count, target in ((an, msg.answers), (ns, msg.authorities),
                                  (ar, msg.additionals)):
                for _ in range(count):
                    item, offset = _parse_rr(data, offset)
                    if isinstance(item, Edns):
                        if target is not msg.additionals or msg.edns is not None:
                            raise DNSFormatError("misplaced or duplicate OPT record")
                        msg.edns = item
                    else:
                        target.append(item)
        except (DNSFormatError, struct.error) as exc:
            if not msg.flags.tc:
                raise DNSFormatError(str(exc)) from exc
        return msg

    def to_text(self) -> str:
        """dig-like dump, handy for debugging and for the viva."""
        lines = [f";; id={self.id} opcode={opcode_to_text(self.flags.opcode)} "
                 f"rcode={rcode_to_text(self.rcode)} flags: {self.flags.to_text()}"]
        if self.edns:
            lines.append(f";; EDNS: version {self.edns.version}, "
                         f"udp {self.edns.udp_payload_size}, do={int(self.edns.do)}")
        lines.append(";; QUESTION")
        lines += [f"{q}" for q in self.questions]
        for title, records in (("ANSWER", self.answers),
                               ("AUTHORITY", self.authorities),
                               ("ADDITIONAL", self.additionals)):
            if records:
                lines.append(f";; {title}")
                lines += [str(rr) for rr in records]
        return "\n".join(lines)


def make_query(name: str, qtype: int = RType.A, *, rd: bool = False,
               edns: bool = True, udp_payload_size: int = 1232,
               msg_id: int | None = None) -> Message:
    """
    Build a standard query.
    rd=False -> iterative query (talking to root/TLD/authoritative servers).
    rd=True  -> recursive query (asking a resolver to do the work for us).
    The random ID (from the `secrets` module) makes blind spoofing harder.
    """
    return Message(
        id=secrets.randbelow(0x10000) if msg_id is None else msg_id,
        flags=Flags(rd=rd),
        questions=[Question(normalize_name(name), qtype, RClass.IN)],
        edns=Edns(udp_payload_size=udp_payload_size) if edns else None,
    )
