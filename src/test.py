import unittest
from struct import pack
from unittest import mock

from scapy import packet
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

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


class testingTraceroute(unittest.TestCase):
    @mock.patch("Traceroute._tcp_ping")
    def test_tcp_ping_declaration(self, mock_ping):
        mock_ping.return_value = " "
        Traceroute._ping("8.8.8.8", 3, 0, 2, 40, 40, 0)
        self.assertEqual(mock_ping.call_count, 3)

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
        Traceroute.check_address_for_correctness("8.8.8.8", 0)
        self.assertTrue(True)

    def test_wrong_diapason(self):
        self.assertRaises(WrongAddressException, Traceroute.check_address_for_correctness, "256.8.8.8", 0)
        self.assertRaises(WrongAddressException, Traceroute.check_address_for_correctness, "8.0.8.8", 0)

    def test_wrong_length(self):
        self.assertRaises(WrongAddressException, Traceroute.check_address_for_correctness, "8.8.8", 0)

    def test_wrong_format(self):
        self.assertRaises(WrongAddressException, Traceroute.check_address_for_correctness, "8.8.text.8", 0)
