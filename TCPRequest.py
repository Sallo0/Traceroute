from scapy.layers.inet import TCP
from scapy.layers.inet6 import IP
from random import choices
from time import time

from scapy.packet import Raw
from scapy.sendrecv import sr1


def _random_byte_message(size):
    sequence = choices(
        b'abcdefghijklmnopqrstuvwxyz'
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        b'1234567890', k=size)
    return bytes(sequence)

class TCPRequest:
    __slots__ = '_time_to_live', '_address', '_port', \
                '_size', '_packet', '_timeout', '_time'

    def __init__(self, address, time_to_live, port, size, timeout):
        self._address = address
        self._time_to_live = time_to_live
        self._port = port
        self._size = size
        self._timeout = timeout
        self._time = time()
        self._packet = self._build_tcp_request()

    def _build_tcp_request(self):
        ip = IP(dst=self._address, ttl=self._time_to_live)
        tcp = TCP(dport=self._port, flags='S')
        packet = ip / tcp / Raw(_random_byte_message(self._size))
        return packet

    @staticmethod
    def _get_time(reply):
        seconds = time() - reply.time
        return seconds

    def send_tcp_request(self):
        reply = sr1(self._packet, verbose=0, timeout=self._timeout)
        if reply is not None:
            reply.reply_time = self._get_time(reply)
        return reply

    @property
    def time(self):
        return self._time
