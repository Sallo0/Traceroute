from collections import Counter, defaultdict
from os import getpid
from threading import Lock
from time import sleep

from scapy.all import socket

from ICMPRequest import ICMPRequest
from ICMPsocket import ICMPv4Socket
from TCPRequest import TCPRequest
from WrongAddressException import WrongAddressException

_lock_id = Lock()
_current_id = getpid()


def _unique_identifier():
    global _current_id
    with _lock_id:
        _current_id += 1
        _current_id &= 0xFFFF
        return _current_id


def _parse_ping_reply(reply, target_address):
    host_reached = False
    if len(reply[1]) == 0:
        return None, host_reached
    routes_count = Counter(pair[1] for pair in reply[1])
    sum_times = defaultdict(int)
    for pair in reply[1]:
        sum_times[pair[1]] += pair[0]
    mean_times = {}
    for ip in sum_times.keys():
        mean_times[ip] = float(
            "{:.2f}".format(sum_times[ip] / routes_count[ip])
        )
        if mean_times[ip] < 1:
            mean_times[ip] = "<1"
        else:
            mean_times[ip] = str(mean_times[ip])
    if target_address in mean_times.keys():
        host_reached = True
    return mean_times, host_reached


def _format_parsed_reply(ttl, parsed_reply):
    if parsed_reply is None:
        return "{ttl}\t{:12s}\t{:12s} Превышен интервал ожидания для запроса".format(
            "*", "*", ttl=ttl
        )
    formatted_string = "{ttl}\t".format(ttl=ttl)
    for ip in parsed_reply:
        formatted_string += "{:12s}\t{:5s} ms\t".format(ip, parsed_reply[ip])
    return formatted_string


def _ping(
    address,
    count=4,
    interval_s=1,
    timeout_s=2,
    time_to_live=30,
    payload_size=64,
    isTCP=False,
    port=0,
):
    id = _unique_identifier()
    packets_sent = 0
    replies = []
    for sequence in range(count):
        if sequence > 0:
            sleep(interval_s)
        if isTCP:
            reply = _tcp_ping(
                address, time_to_live, port, payload_size, timeout_s
            )
            if reply is not None:
                replies.append(reply)
        else:
            reply = _icmp_ping(
                address, id, sequence, time_to_live, payload_size, timeout_s
            )
            if reply is not None:
                replies.append(reply)
        packets_sent += 1
    return packets_sent, replies


def _tcp_ping(address, time_to_live, port, payload_size, timeout):
    request = TCPRequest(address, time_to_live, port, payload_size, timeout)
    reply = request.send_tcp_request()
    if reply is not None:
        round_trip_time = (reply.time - request.time) * 1000
        return round_trip_time, reply.src


def _icmp_ping(address, id, sequence, time_to_live, payload_size, timeout):
    request = ICMPRequest(
        destination=address,
        id=id,
        sequence=sequence,
        ttl=time_to_live,
        payload_size=payload_size,
    )
    with ICMPv4Socket() as sock:
        try:
            sock.send(request)
            reply = sock.receive(request, timeout)
            round_trip_time = (reply.time - request.time) * 1000
            return round_trip_time, reply.source
        except socket.timeout:
            pass
        except TimeoutError:
            pass


def traceroute(
    address,
    requests,
    wait_before_send_s,
    wait_timeout_s,
    max_time_to_live,
    data_size,
    TCP,
    port,
):
    check_address_for_correctness(address, port)
    check_input_for_correctness(
        requests,
        wait_before_send_s,
        wait_timeout_s,
        max_time_to_live,
        data_size,
    )
    host_reached = False
    ttl = 1
    while not host_reached and ttl <= max_time_to_live:
        reply = _ping(
            address,
            count=requests,
            interval_s=wait_before_send_s,
            timeout_s=wait_timeout_s,
            time_to_live=ttl,
            payload_size=data_size,
            isTCP=TCP,
            port=port,
        )
        parsed_reply, host_reached = _parse_ping_reply(reply, address)
        print(_format_parsed_reply(ttl, parsed_reply))
        ttl += 1


def check_input_for_correctness(
    requests, wait_before, timeout, ttl, data_size
):
    if requests <= 0:
        raise ValueError("Should be at least 1 request")
    if wait_before < 0 or timeout < 0 or data_size < 0:
        raise ValueError("Params should be non-negative")
    if ttl <= 0:
        raise ValueError("TTL should be at least 1")


def check_address_for_correctness(address, port):
    parts = address.split(".")
    if len(parts) != 4:
        raise WrongAddressException(f"Wrong address length of {address}")
    for part in parts:
        try:
            if int(part) < 1 or int(part) > 255:
                raise WrongAddressException(
                    f"Wrong address {part} in {address}"
                )
        except ValueError:
            raise WrongAddressException(
                f"Address {address} must consist of numbers"
            )
    if port < 0 or port > 65536:
        raise WrongAddressException("Port should be between 0 and 65536")
