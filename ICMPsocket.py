import socket
from time import time
from struct import pack, unpack
from ICMPReply import ICMPReply


class ICMPv4Socket:
    __slots__ = '_sock', '_address', '_port'

    _IP_VERSION = 4
    _ICMP_HEADER_OFFSET = 20
    _ICMP_HEADER_REAL_OFFSET = 20

    _ICMP_CODE_OFFSET = _ICMP_HEADER_OFFSET + 1
    _ICMP_CHECKSUM_OFFSET = _ICMP_HEADER_OFFSET + 2
    _ICMP_ID_OFFSET = _ICMP_HEADER_OFFSET + 4
    _ICMP_SEQUENCE_OFFSET = _ICMP_HEADER_OFFSET + 6
    _ICMP_PAYLOAD_OFFSET = _ICMP_HEADER_OFFSET + 8

    _ICMP_ECHO_REQUEST = 8
    _ICMP_ECHO_REPLY = 0

    def __init__(self, address=None, port=0):
        self._address = address
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if address:
            self._sock.bind((address, port))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()


    def _set_ttl(self, ttl):
        self._sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_TTL,
            ttl)

    def _checksum(self, data):
        sum = 0
        data += b'\x00'
        for i in range(0, len(data) - 1, 2):
            sum += (data[i] << 8) + data[i + 1]
            sum = (sum & 0xffff) + (sum >> 16)
        sum = ~sum & 0xffff
        return sum

    def _create_ICMP_packet(self, id, sequence, payload):
        checksum = 0
        header = pack('!2B3H', self._ICMP_ECHO_REQUEST, 0, checksum,
                      id, sequence)
        checksum = self._checksum(header + payload)
        header = pack('!2B3H', self._ICMP_ECHO_REQUEST, 0, checksum,
                      id, sequence)
        return header + payload

    def _parse_reply(self, packet, source, current_time):
        bytes_received = len(packet) - self._ICMP_HEADER_OFFSET
        if len(packet) < self._ICMP_CHECKSUM_OFFSET:
            return None
        type, code = unpack('!2B', packet[
                                   self._ICMP_HEADER_OFFSET:
                                   self._ICMP_CHECKSUM_OFFSET])
        if type != self._ICMP_ECHO_REPLY:
            packet = packet[self._ICMP_PAYLOAD_OFFSET:]
        id, sequence = unpack('!2H', packet[
                                     self._ICMP_ID_OFFSET:
                                     self._ICMP_PAYLOAD_OFFSET])

        return ICMPReply(
            source=source,
            family=self._IP_VERSION,
            id=id,
            sequence=sequence,
            type=type,
            code=code,
            bytes_received=bytes_received,
            time=current_time)

    def send(self, request):
        sock_destination = socket.getaddrinfo(
            port=0,
            host=request.destination,
            family=self._sock.family)[0][4]
        self._address = request.destination
        packet = self._create_ICMP_packet(
            id=request.id,
            sequence=request.sequence,
            payload=request.payload)
        self._set_ttl(request.ttl)
        request._time = time()
        self._sock.sendto(packet, sock_destination)

    def receive(self, request=None, timeout=2):
        self._sock.settimeout(timeout)
        while True:
            response = self._sock.recvfrom(1024)
            current_time = time()
            packet = response[0]
            source = response[1][0]
            reply = self._parse_reply(
                packet=packet,
                source=source,
                current_time=current_time)
            if (reply and not request or
                    reply and request.id == reply.id and
                    request.sequence == reply.sequence):
                return reply

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None


#   Echo Request and Echo Reply messages                     RFC 4443
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |     Code      |           Checksum            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           Identifier          |        Sequence Number        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Data ...
#   +-+-+-+-+-
#
