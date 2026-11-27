"""Unit tests for the DNS codec (F1). Run with:  pytest tests/test_codec.py -v"""
import struct

import pytest

from dns_analyzer.dns import (
    DNSEncodeError, DNSFormatError, Edns, Flags, Message, MxData, Question,
    ResourceRecord, RType, SoaData, decode_name, encode_name, make_query,
    normalize_name, text_to_type,
)


# ---------------------------------------------------------------- names ----
def test_normalize_name():
    assert normalize_name("WWW.Example.TEST") == "www.example.test."
    assert normalize_name("") == "."
    assert normalize_name(".") == "."


def test_encode_name_exact_bytes():
    assert encode_name("www.example.test.") == (
        b"\x03www\x07example\x04test\x00")
    assert encode_name(".") == b"\x00"


def test_encode_name_rejects_bad_names():
    with pytest.raises(DNSEncodeError):
        encode_name("a..b.")                       # empty label
    with pytest.raises(DNSEncodeError):
        encode_name("x" * 64 + ".test.")           # label > 63
    with pytest.raises(DNSEncodeError):
        encode_name(".".join(["a" * 60] * 5) + ".")  # name > 255
    with pytest.raises(DNSEncodeError):
        encode_name("bücher.test.")                 # non-ASCII


def test_decode_name_plain_and_lowercases():
    wire = b"\x03WWW\x04Test\x00"
    assert decode_name(wire, 0) == ("www.test.", len(wire))


def test_decode_name_with_compression_pointer():
    # offset 0: 'example.test.'   offset 14: 'www' + pointer to offset 0
    wire = encode_name("example.test.") + b"\x03www\xc0\x00"
    name, nxt = decode_name(wire, 14)
    assert name == "www.example.test."
    assert nxt == len(wire)            # parsing resumes right after the pointer


def test_decode_name_rejects_pointer_loop_and_forward_pointer():
    with pytest.raises(DNSFormatError):
        decode_name(b"\xc0\x00", 0)                # points at itself
    with pytest.raises(DNSFormatError):
        decode_name(b"\xc0\x05" + b"\x00" * 6, 0)  # points forward


def test_decode_name_rejects_truncated_and_reserved():
    with pytest.raises(DNSFormatError):
        decode_name(b"\x05ab", 0)                  # label runs off the end
    with pytest.raises(DNSFormatError):
        decode_name(b"\x03www", 0)                 # no terminating zero
    with pytest.raises(DNSFormatError):
        decode_name(b"\x40abc\x00", 0)             # reserved label type 01


# --------------------------------------------------------------- header ----
def test_flags_roundtrip_all_bits():
    for value in (0x0000, 0x0100, 0x8180, 0x8583, 0x0200, 0x8400, 0x81B0, 0xFFBF):
        assert Flags.from_int(value).to_int() == value


def test_flags_fields():
    f = Flags.from_int(0x8583)        # QR AA RD RA, RCODE=3 (NXDOMAIN)
    assert (f.qr, f.aa, f.rd, f.ra, f.tc, f.rcode) == (True, True, True, True, False, 3)


# ---------------------------------------------------------------- query ----
def test_query_exact_bytes_without_edns():
    q = make_query("example.com", RType.A, rd=True, edns=False, msg_id=0x1234)
    assert q.to_bytes() == bytes.fromhex(
        "1234 0100 0001 0000 0000 0000"
        "076578616d706c6503636f6d00 0001 0001".replace(" ", ""))


def test_query_exact_bytes_with_edns():
    q = make_query("example.com", RType.A, rd=True, msg_id=0x1234)
    assert q.to_bytes() == bytes.fromhex(
        "123401000001000000000001"                 # header, ARCOUNT=1
        "076578616d706c6503636f6d0000010001"       # question
        "00" "0029" "04d0" "00000000" "0000")      # OPT: root, type 41, 1232, ttl 0, rdlen 0


def test_make_query_defaults_are_iterative():
    q = make_query("www.example.test")
    assert q.flags.rd is False and q.flags.qr is False
    assert q.questions == [Question("www.example.test.", RType.A, 1)]
    assert 0 <= q.id <= 0xFFFF


def test_query_roundtrip():
    q = make_query("www.example.test", RType.AAAA, rd=True)
    assert Message.from_bytes(q.to_bytes()) == q


# ------------------------------------------------------ handmade response --
def build_response_bytes() -> bytes:
    """A response written byte-by-byte so the decoder is tested independently."""
    header = struct.pack("!HHHHHH", 0xBEEF, 0x8580, 1, 1, 0, 0)  # QR AA RD RA
    question = encode_name("www.example.test.") + struct.pack("!HH", 1, 1)
    answer = (b"\xc0\x0c"                              # name = pointer to offset 12
              + struct.pack("!HHIH", 1, 1, 300, 4)
              + bytes([10, 10, 3, 30]))
    return header + question + answer


def test_decode_handmade_response_with_compression():
    msg = Message.from_bytes(build_response_bytes())
    assert msg.id == 0xBEEF
    assert msg.flags.qr and msg.flags.aa
    assert msg.questions[0].name == "www.example.test."
    rr = msg.answers[0]
    assert (rr.name, rr.rtype, rr.ttl, rr.rdata) == (
        "www.example.test.", RType.A, 300, "10.10.3.30")


# -------------------------------------------------------------- roundtrip --
def sample_message() -> Message:
    return Message(
        id=7,
        flags=Flags(qr=True, aa=True, rd=True, ra=True),
        questions=[Question("www.example.test.", RType.A)],
        answers=[
            ResourceRecord("www.example.test.", RType.CNAME, 60, "web.example.test."),
            ResourceRecord("web.example.test.", RType.A, 60, "10.10.3.30"),
            ResourceRecord("web.example.test.", RType.AAAA, 60, "2001:db8::1"),
        ],
        authorities=[
            ResourceRecord("example.test.", RType.NS, 3600, "ns1.example.test."),
            ResourceRecord("example.test.", RType.SOA, 3600, SoaData(
                "ns1.example.test.", "admin.example.test.", 2026112101, 7200, 900, 1209600, 300)),
        ],
        additionals=[
            ResourceRecord("ns1.example.test.", RType.A, 3600, "10.10.3.30"),
            ResourceRecord("example.test.", RType.MX, 300, MxData(10, "mail.example.test.")),
            ResourceRecord("example.test.", RType.TXT, 300, ("hello world", "second")),
            ResourceRecord("x.example.test.", 99, 5, b"\x01\x02\x03"),   # unknown type
        ],
        edns=Edns(udp_payload_size=1232, do=True, options=[(10, b"\x01" * 8)]),
    )


@pytest.mark.parametrize("compress", [True, False])
def test_full_message_roundtrip(compress):
    msg = sample_message()
    assert Message.from_bytes(msg.to_bytes(compress=compress)) == msg


def test_compression_makes_message_smaller():
    msg = sample_message()
    assert len(msg.to_bytes(compress=True)) < len(msg.to_bytes(compress=False))


def test_compressed_output_uses_pointer_for_repeated_suffix():
    msg = Message(questions=[Question("www.example.test.")],
                  answers=[ResourceRecord("www.example.test.", RType.A, 1, "1.2.3.4")])
    wire = msg.to_bytes()
    # answer owner name is just a pointer to offset 12 (start of the question)
    assert b"\xc0\x0c" in wire
    assert wire.count(b"\x07example") == 1


# ------------------------------------------------------------------ EDNS ---
def test_edns_fields_roundtrip_and_extended_rcode():
    msg = Message(id=1, flags=Flags(qr=True, rcode=0x0),
                  edns=Edns(udp_payload_size=4096, ext_rcode=1, version=0, do=True,
                            options=[(8, b"abc"), (10, b"")]))
    back = Message.from_bytes(msg.to_bytes())
    assert back.edns == msg.edns
    assert back.rcode == 16            # ext_rcode 1 << 4 | 0 (BADVERS)
    assert back.additionals == []      # OPT is not left in the normal list


def test_duplicate_opt_is_rejected():
    wire = Message(id=1, edns=Edns()).to_bytes()
    opt = wire[12:]                                # the 11-byte OPT record
    bad = bytearray(wire + opt)
    struct.pack_into("!H", bad, 10, 2)            # ARCOUNT = 2
    with pytest.raises(DNSFormatError):
        Message.from_bytes(bytes(bad))


# ----------------------------------------------------------- bad input ----
def test_short_message_rejected():
    with pytest.raises(DNSFormatError):
        Message.from_bytes(b"\x00" * 11)


def test_truncated_record_rejected_when_tc_not_set():
    wire = build_response_bytes()[:-2]            # chop the end of the A rdata
    with pytest.raises(DNSFormatError):
        Message.from_bytes(wire)


def test_truncated_record_tolerated_when_tc_set():
    wire = bytearray(build_response_bytes()[:-2])
    struct.pack_into("!H", wire, 2, 0x8780 | 0x0000)   # QR AA TC RD RA
    msg = Message.from_bytes(bytes(wire))
    assert msg.flags.tc is True
    assert msg.questions[0].name == "www.example.test."
    assert msg.answers == []                      # unreadable part dropped


def test_inflated_counts_rejected():
    wire = bytearray(build_response_bytes())
    struct.pack_into("!H", wire, 6, 50)           # claim 50 answers
    with pytest.raises(DNSFormatError):
        Message.from_bytes(bytes(wire))


def test_a_record_wrong_length_rejected():
    wire = bytearray(build_response_bytes())
    wire[-5] = 5                                  # RDLENGTH 4 -> 5, then runs past end
    with pytest.raises(DNSFormatError):
        Message.from_bytes(bytes(wire))


def test_bad_rdata_on_encode():
    msg = Message(answers=[ResourceRecord("a.test.", RType.A, 1, "not-an-ip")])
    with pytest.raises(DNSEncodeError):
        msg.to_bytes()


def test_text_helpers():
    assert text_to_type("aaaa") == 28
    assert text_to_type("TYPE99") == 99
    with pytest.raises(ValueError):
        text_to_type("bogus")
    assert "www.example.test. 60 IN CNAME web.example.test." in sample_message().to_text()
