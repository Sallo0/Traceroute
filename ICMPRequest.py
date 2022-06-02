from random import choices


def _random_byte_message(size):
    sequence = choices(
        b'abcdefghijklmnopqrstuvwxyz'
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        b'1234567890', k=size)
    return bytes(sequence)


class ICMPRequest:
    __slots__ = '_destination', '_id', '_sequence', '_payload', \
                '_payload_size', '_ttl', '_time'

    def __init__(self, destination, id, sequence, payload=None, payload_size=56, ttl=64):

        if payload:
            payload_size = len(payload)

        self._destination = destination
        self._id = id & 0xffff
        self._sequence = sequence & 0xffff
        self._payload = payload
        self._payload_size = payload_size
        self._ttl = ttl
        self._time = 0

    @property
    def destination(self):
        return self._destination

    @property
    def id(self):
        return self._id

    @property
    def sequence(self):
        return self._sequence

    @property
    def payload(self):
        return self._payload or _random_byte_message(self._payload_size)

    @property
    def payload_size(self):
        return self._payload_size

    @property
    def ttl(self):
        return self._ttl

    @property
    def time(self):
        return self._time
