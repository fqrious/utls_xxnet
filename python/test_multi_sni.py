import sys, os
import time
from unittest import TestCase
import socket
import struct
from asn1crypto.x509 import Certificate

current_path = os.path.dirname(os.path.abspath(__file__))
root_path = os.path.abspath(os.path.join(current_path, os.path.pardir))
build_path = os.path.join(root_path, 'build', "lib.macosx-10.9-x86_64-cpython-310")
sys.path.append(build_path)

from pyutls import (

    #  ssl connection functions
    new_ssl_connection,
    ssl_connection_write,
    ssl_connection_read,
    ssl_connection_close,
    ssl_connection_h2_support,
    ssl_connection_closed,
    ssl_connection_do_handshake,
    ssl_connection_leaf_cert,
    ssl_connection_set_block_max,
    #  context functions
    new_ssl_context,
    new_ssl_context_from_bytes,
    # others functions
    close_go_handle
)
import utils


class TestTLS(TestCase):
    CERT_DELIM = b"|!|!|"

    def setUp(self):
        tls_ver = 772
        self.ctx = new_ssl_context(tls_ver, True)

    def connect_tcp(self, ip_str):
        ip_str = utils.to_str(ip_str)

        ip, port = utils.get_ip_port(ip_str)
        if isinstance(ip, str):
            ip = utils.to_bytes(ip)

        sock = socket.socket(socket.AF_INET if b':' not in ip else socket.AF_INET6)

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
        # Close the connection with a TCP RST instead of a TCP FIN.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))

        # resize socket receive buffer ->64 above to improve browser related application performance
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.connect_receive_buffer)
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.connect_send_buffer)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        # sock.settimeout(self.timeout)
        return sock

    def get_peercertificates(self, s):
        cert_bytes = ssl_connection_leaf_cert(s)
        cert_arr = cert_bytes.split(self.CERT_DELIM)
        certs = tuple(map(Certificate.load, cert_arr))

        cert = certs[0]
        try:
            altName = cert.subject_alt_name_value.native
            common_name = cert.subject.native["common_name"]
        except:
            altName = []
            common_name = ""

        self.peer_cert = {
            "cert": cert,
            "issuer_commonname": cert.issuer.human_friendly,
            "commonName": common_name,
            "altName": altName
        }
        self.domain = common_name
        return self.peer_cert

    def wrap(self, ip_str, sni):
        s, fd = new_ssl_connection(self.ctx, ip_str, sni)
        print(f"sock:{s} fd:{fd}")
        ssl_connection_do_handshake(s)
        cert = self.get_peercertificates(s)
        print(f"cert: {cert['altName']}")

    def test_multi_sni(self):
        t1 = self.wrap("141.101.121.155:443", "www.chargecommission.autos")  # good
        # t2 = self.wrap("141.101.121.155:443", "www.kitchenleader.beauty")
        # t2 = self.wrap("172.67.200.110:443", "www.servicecarpet.autos")  # Timeout
        time.sleep(1)
        t2 = self.wrap("104.27.15.167:443", "www.servicecarpet.autos")   # good
        # time.sleep(5)
        # t1 = self.wrap("104.27.15.167:443", "www.personalposition.autos")  # good
