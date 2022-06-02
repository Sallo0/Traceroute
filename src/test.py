import unittest
from struct import pack
from unittest import mock

from scapy import packet
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

import ICMPReply
import ICMPRequest
import ICMPsocket
import TCPRequest
import Traceroute
from WrongAddressException import WrongAddressException


class testingTCPRequest(unittest.TestCase):
    def setUp(self):
        self.tcp_packet = TCPRequest.TCPRequest("0.0.0.0", 10, 0, 0, 1)._packet

    def test_tcp_request_packet_has_3_layers(self):
        self.assertEqual(len(self.tcp_packet.layers()), 3)

    def test_tcp_request_packet_layers_are_ip_tcp_raw(self):
        self.assertEqual(self.tcp_packet.layers(), [IP, TCP, Raw])

    def test_correct_packet_length(self):
        tcp_packet_with_payload = TCPRequest.TCPRequest("0.0.0.0", 10, 0, 10, 1)._packet
        self.assertEqual(len(self.tcp_packet), 40)
        self.assertEqual(len(tcp_packet_with_payload), 50)

    def test_correct_arguments_are_in_packet(self):
        self.assertEqual(self.tcp_packet[IP].dst, "0.0.0.0")
        self.assertEqual(self.tcp_packet[TCP].dport, 0)
        self.assertEqual(self.tcp_packet[IP].ttl, 10)

    @mock.patch("TCPRequest.TCPRequest.send_tcp_request", return_value=packet.Packet)
    def test_tcp_reply(self, reply_mock):
        request = TCPRequest.TCPRequest("0.0.0.0", 10, 0, 0, 1)
        reply = request.send_tcp_request()
        reply.src = mock.Mock(return_value="0.0.0.0.").return_value
        self.assertEqual(reply.src, "0.0.0.0.")


class testingICMPRequest(unittest.TestCase):
    def setUp(self):
        self.ICMPRequest = ICMPRequest.ICMPRequest("0.0.0.0", 1, 1, None, 20, 10)
        self.ICMPRequest_with_payload = ICMPRequest.ICMPRequest("0.0.0.0", 1, 1, b"somebytestring", 100, 10)
        self.ICMPReply_type3 = ICMPReply.ICMPReply("", "", "", "", 3, "", "", "")
        self.ICMPReply_type11 = ICMPReply.ICMPReply("", "", "", "", 11, "", "", "")
        self.ICMPReply_type_not_0_or_others = ICMPReply.ICMPReply("", "", "", "", 1, "", "", "")
        self.ICMPSocket = ICMPsocket.ICMPv4Socket()

    def test_correct_payload(self):
        self.assertEqual(self.ICMPRequest.payload_size, 20)
        self.assertEqual(self.ICMPRequest_with_payload.payload_size, len(b"somebytestring"))
        self.assertEqual(self.ICMPRequest_with_payload.payload, b"somebytestring")

    def test_correct_id(self):
        self.assertEqual(self.ICMPRequest.id, 1)

    def test_correct_sequence(self):
        self.assertEqual(self.ICMPRequest.sequence, 1)

    def test_raise_for_status(self):
        self.assertRaises(ConnectionResetError, self.ICMPReply_type3.raise_for_status)
        self.assertRaises(TimeoutError, self.ICMPReply_type11.raise_for_status)
        self.assertRaises(OSError, self.ICMPReply_type_not_0_or_others.raise_for_status)

    def test_checksum(self):
        header = pack("!2B3H", 8, 0, 0, 1, 1)
        checksum = self.ICMPSocket._checksum(header + b"somebytestring")
        self.assertEqual(60420, checksum)

    def test_create_packet(self):
        packet = self.ICMPSocket._create_ICMP_packet(1, 1, b"somebytestring")
        self.assertEqual(packet, b"\x08\x00\xec\x04\x00\x01\x00\x01somebytestring")

    # def test_incorrect_sending(self):
    #     self.assertRaises(OSError, self.ICMPSocket.send, self.ICMPRequest)

    @mock.patch("socket.socket.recvfrom")
    def test_receive(self, mock_response):
        mock_response.return_value = (
            b"E\xc0\x00`\xf8\xda\x00\x00@\x01\xfd\x8d\xc0\xa8\x01\x01\xc0\xa8\x01#\x0b\x00\xf4\xff\x00\x00\x00\x00E\x00\x00Dj\xaf\x00\x00\x01\x01}/\xc0\xa8\x01#\x08\x08\x08\x08\x08\x00 12\x19\x00\x0009cPeyrNquUOinsyjLOVMax6z8KvFCzMLXYItEwV",
            ("192.168.1.1", 0),
        )
        a = self.ICMPSocket.receive()
        self.assertEqual(a.id, 12825)
        self.assertEqual(a.source, "192.168.1.1")
        self.assertEqual(a.sequence, 0)
        self.assertEqual(a.type, 11)


class testingTraceroute(unittest.TestCase):
    @mock.patch("Traceroute._ping")
    def test_traceroute_ping_amount(self, mock_ping):
        mock_ping.return_value = (
            3,
            [(1.0027885437011719, "192.168.1.1"), (0.0, "192.168.1.1"), (0.9977817535400391, "192.168.1.1")],
        )
        Traceroute.traceroute("8.8.8.8", 3, 0, 2, 40, 40, False, 0)
        self.assertEqual(mock_ping.call_count, 40)

    @mock.patch("Traceroute._ping")
    def test_traceroute_end(self, mock_ping):
        mock_ping.return_value = (
            3,
            [(1.0027885437011719, "8.8.8.8"), (0.0, "8.8.8.8"), (0.9977817535400391, "8.8.8.8")],
        )
        Traceroute.traceroute("8.8.8.8", 3, 0, 2, 40, 40, False, 0)
        self.assertEqual(mock_ping.call_count, 1)

    @mock.patch("Traceroute._tcp_ping")
    def test_tcp_ping_declaration(self, mock_ping):
        mock_ping.return_value = " "
        Traceroute._ping("8.8.8.8", 3, 0, 2, 40, 40, True, 0)
        self.assertEqual(mock_ping.call_count, 3)

    @mock.patch("Traceroute._tcp_ping")
    def test_icmp_ping_tcp_declaration(self, mock_ping):
        mock_ping.return_value = " "
        Traceroute._ping("8.8.8.8", 3, 0, 2, 40, 40, False, 0)
        self.assertEqual(mock_ping.call_count, 0)

    def test_parse_reply(self):
        reply = (3, [])
        mean_time, host_reached = Traceroute._parse_ping_reply(reply, "8.8.8.8")
        self.assertEqual(mean_time, None)
        self.assertEqual(host_reached, False)

    def test_parse_reply_time(self):
        reply = (3, [(10, "8.8.8.8"), (20, "8.8.8.8"), (60, "8.8.8.8")])
        mean_time, host_reached = Traceroute._parse_ping_reply(reply, "9.9.9.9")
        self.assertLessEqual(float(mean_time["8.8.8.8"]) - 30, 0.00001)

    def test_different_ips_and_times(self):
        reply = (3, [(10, "8.8.8.8"), (20, "10.10.10.10")])
        mean_time, host_reached = Traceroute._parse_ping_reply(reply, "9.9.9.9")
        self.assertLessEqual(float(mean_time["8.8.8.8"]) - 30, 0.00001)
        self.assertLessEqual(float(mean_time["10.10.10.10"]) - 30, 0.00001)

    def test_simple_host_reached(self):
        reply = (3, [(10, "8.8.8.8")])
        mean_time, host_reached = Traceroute._parse_ping_reply(reply, "8.8.8.8")
        self.assertEqual(host_reached, True)

    def test_harder_host_reached(self):
        reply = (3, [(10, "9.9.9.9"), (10, "8.8.8.8")])
        mean_time, host_reached = Traceroute._parse_ping_reply(reply, "8.8.8.8")
        self.assertEqual(host_reached, True)

    def test_format_reply(self):
        reply = (3, [(10, "9.9.9.9"), (10, "8.8.8.8")])
        parsed_reply, _ = Traceroute._parse_ping_reply(reply, "8.8.8.8")
        formatted_reply = Traceroute._format_parsed_reply(1, parsed_reply)
        self.assertEqual(formatted_reply, "1	9.9.9.9     	10.0  ms	8.8.8.8     	10.0  ms	")

    def test_format_none_reply(self):
        formatted_reply = Traceroute._format_parsed_reply(1, None)
        self.assertEqual(formatted_reply, "1	*           	*            Превышен интервал ожидания для запроса")


class WrongAddressTests(unittest.TestCase):
    def test_correct_address(self):
        Traceroute.check_address_for_correctness("8.8.8.8")
        self.assertTrue(True)

    def test_wrong_diapason(self):
        self.assertRaises(WrongAddressException, Traceroute.check_address_for_correctness, "256.8.8.8")
        self.assertRaises(WrongAddressException, Traceroute.check_address_for_correctness, "8.0.8.8")

    def test_wrong_length(self):
        self.assertRaises(WrongAddressException, Traceroute.check_address_for_correctness, "8.8.8")

    def test_wrong_format(self):
        self.assertRaises(WrongAddressException, Traceroute.check_address_for_correctness, "8.8.text.8")
