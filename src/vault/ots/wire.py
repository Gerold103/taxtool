"""Encoding primitives of the proof format, as in the reference
implementation's serialize.py.

Integers are unsigned LEB128: seven payload bits per byte, low bits
first, the high bit set while more bytes follow. Byte strings are a
varuint length followed by the bytes. A Reader walks a buffer and
raises FormatError on anything short or out of range, so that no
higher layer has to check lengths itself.
"""

from vault.errors import VaultError

LEB128_BITS = 7
LEB128_PAYLOAD = 0x7F
LEB128_CONTINUE = 0x80
# Nine bytes carry 63 bits; the reference refuses longer integers.
MAX_VARUINT_BYTES = 9


class FormatError(VaultError):
    """Bytes that are not a valid OpenTimestamps proof."""


def varuint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & LEB128_PAYLOAD
        value >>= LEB128_BITS
        if value:
            out.append(byte | LEB128_CONTINUE)
        else:
            out.append(byte)
            return bytes(out)


def varbytes(data: bytes) -> bytes:
    return varuint(len(data)) + data


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        chunk = self.data[self.pos : self.pos + count]
        if len(chunk) != count:
            raise FormatError(
                f"truncated: wanted {count} bytes at offset {self.pos}"
            )
        self.pos += count
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def varuint(self) -> int:
        value = 0
        for shift in range(0, LEB128_BITS * MAX_VARUINT_BYTES, LEB128_BITS):
            byte = self.byte()
            value |= (byte & LEB128_PAYLOAD) << shift
            if not byte & LEB128_CONTINUE:
                return value
        raise FormatError(f"varuint longer than {MAX_VARUINT_BYTES} bytes")

    def varbytes(self, max_length: int, min_length: int = 0) -> bytes:
        length = self.varuint()
        if not min_length <= length <= max_length:
            raise FormatError(f"byte string of length {length} out of range")
        return self.take(length)

    def done(self) -> bool:
        return self.pos == len(self.data)
