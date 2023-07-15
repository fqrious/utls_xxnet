import sys, os
import pyutls
import codecs, random
from pyutls.pyutls_wrap import SSLConnection, SSLContext
from logging import getLogger
# import h2.connection, h2.events
import requests, socket
from http.client import HTTPConnection
from requests.adapters import HTTPAdapter
from requests.packages.urllib3 import PoolManager, HTTPConnectionPool


logger = getLogger(__name__)
logger = None

curl_hex = "1603010200010001fc03039b72af275b37da871055d2988b00f9c4d98a15c068bd7270c8ec68eb0b5056bc20abb125ce53c8c46023a2a30bfe94b8ff5ce1f8167e8368a979f2b8937849993b003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100017500000014001200000f7777772e6578616d706c652e636f6d000b000403000102000a00160014001d0017001e00190018010001010102010301040010000b000908687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d0020a4b1c882803406b54c4956f6dec05ee7953d785fb6a7b64557d12a6d03ef243d001500b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
packet2 = codecs.decode(curl_hex, 'hex')
curl_1_1_context = SSLContext.from_bytes(logger, packet2)


#sock = SSLConnection(curl_1_1_context, None)

class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, **kw):
        self.poolmanager = MyPoolManager(num_pools=connections,
                                         maxsize=maxsize, **kw)

class MyPoolManager(PoolManager):
    def _new_pool(self, scheme, host, port, **kw):
        # Important!
        # if scheme == 'http' and host == my_host and port == my_port:
        #print(self.connection_pool_kw)   
        return MyHTTPConnectionPool(host, port)
        #return super(PoolManager, self)._new_pool(self, scheme, host, port)


class MyHTTPConnectionPool(HTTPConnectionPool):
    def _new_conn(self):
        self.num_connections += 1
        return MyHTTPConnection(host=self.host,
                            port=self.port,
                            #strict=self.strict)
                            )

class MyHTTPConnection(HTTPConnection):
    def connect(self):
        """Connect to the host and port specified in __init__."""
        # Original
        #self.sock = socket.create_connection((self.host, self.port),
        #                                    self.timeout, self.source_address)
        # Important!
        #self.sock = my_socket
        print("new tls client")
        random_context = SSLContext(None, support_http2=False)
        self.sock = SSLConnection(random_context, None, f'{self.host}:{self.port}', self.host)
        #self.sock.sendall = self.sock.send
        #self.sock._decref_socketios = lambda:None
        if self._tunnel_host:
            self._tunnel()


s = requests.Session()
s.mount('https://', MyAdapter())
resp = s.get("https://icanhazip.com")
resp = s.get("https://google.com")
print(resp)
