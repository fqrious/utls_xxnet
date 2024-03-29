import sys, os
import pyutls
import codecs, random
from pyutls_wrap import SSLConnection, SSLContext
from logging import getLogger
import h2.connection
import h2.events


logger = getLogger(__name__)
TIMEOUT = 5

# SERVER_ADDRESS = "2a00:1450:4009:820::101e"
SERVER_ADDRESS = "www.bing.com:443"

def test_wrap(ctx, name):
    print("=============>", name, "<=============")
    sock = SSLConnection(ctx, None, SERVER_ADDRESS, b"www.bing.com")
    # h2support = pyutls.ssl_connection_h2_support(sock)
    # print("Before Handshake, H2 Support =>", h2support)
    sock.blockmax = TIMEOUT/2
    sock.do_handshake()
    sock.settimeout(TIMEOUT)
    h2support = sock.is_support_h2()
    print("After Handshake, H2 Support =>", h2support)
    cert_bytes = sock.get_cert()
    print("Cert", cert_bytes)
    # if h2support:
    #     # print("h2 connection not implemented")
    #     write_h2(sock)
    #     return
    # sock = sslsock(sock, name)
    write(sock, h2support)

    

def write(sock, is_h2):
    # try:
        if is_h2:
            return write_h2(sock)
        sock.send(b"HEAD / HTTP/1.1\r\nHost: www.bing.com\r\n\r\n")
        out =  sock.recv(5)
        out +=  sock.recv(5000)
        print(len(out), out)
    # except TimeoutError as e:
    #     print("error:", e, file=sys.stderr)
    

def write_h2(sock):
    s = sock
    s.sendall = s.send

    c = h2.connection.H2Connection()
    c.initiate_connection()
    sock.send(c.data_to_send())

    headers = [
        (':method', 'HEAD'),
        (':path', '/'),
        (':authority', 'www.bing.com'),
        (':scheme', 'https'),
    ]
    c.send_headers(1, headers, end_stream=True)
    s.sendall(c.data_to_send())

    body = b''
    response_stream_ended = False
    while not response_stream_ended:
        # read raw data from the socket
        data = s.recv(1024*65536)
        if not data:
            break

        # feed raw data into h2, and process resulting events
        events = c.receive_data(data)
        for event in events:
            print(event)
            if isinstance(event, h2.events.DataReceived):
                # update flow control so the server doesn't starve us
                c.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                # more response body data received
                body += event.data
            if isinstance(event, h2.events.StreamEnded):
                # response body completed, let's exit the loop
                response_stream_ended = True
                break
        # send any pending data to the server
        s.sendall(c.data_to_send())

    print("Response fully received:")
    # print(body.decode())

    # tell the server we are closing the h2 connection
    c.close_connection()
    s.sendall(c.data_to_send())

def  test_wrap_all():
    curl_hex = "1603010200010001fc03039b72af275b37da871055d2988b00f9c4d98a15c068bd7270c8ec68eb0b5056bc20abb125ce53c8c46023a2a30bfe94b8ff5ce1f8167e8368a979f2b8937849993b003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100017500000014001200000f7777772e6578616d706c652e636f6d000b000403000102000a00160014001d0017001e00190018010001010102010301040010000b000908687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d0020a4b1c882803406b54c4956f6dec05ee7953d785fb6a7b64557d12a6d03ef243d001500b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    packet = codecs.decode("1603010200010001fc03034e7b309f8179598f97b0add0a541583bc75324fa0e5c9c61f50e0e8012e8364f20a82353f273ec45d46b1bc8983d7ed611d82b4f4957b34fb0a5b3c141533b71c00022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00350100019100000010000e00000b6578616d706c652e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00203aa102ca6f5644cbebdd5252bc3122ef48876ec476acb140913a88645a92402e001700410407f790903a02131e2354a4acdd37a0591ef7c626292afb03800666c65272a8726103da947ef38a27891e025ec409758625c954ea5ec19cc460c59f6d9aa86120002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c000240010015008b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "hex")
    chrome_context  = SSLContext.from_bytes(logger, packet)
    packet2 = codecs.decode(curl_hex, 'hex')
    curl_1_1_context = SSLContext.from_bytes(logger, packet2)
    test_wrap(curl_1_1_context, "curl_1.1_context")
    test_wrap(chrome_context,  "chrome_context")
    for i in range(3):
        # support_h2 = random.choice([True, False])
        support_h2 = True
        randomized_context = SSLContext(logger, support_http2=support_h2)
        test_wrap(randomized_context,  f"randomized_context_#{i}")
    # test_wrap(chrome_context,  "chrome_context")


    SSLContext.from_bytes(logger, hex=curl_hex)

import selectors
def iowait(self, event=selectors.EVENT_READ):
        # if event == selectors.EVENT_READ:
        #     import select
        #     while True:
        #         readable, _, _ = select.select([self], [], [])
        #         if readable:
        #             return True
        selector = selectors.DefaultSelector()
        select_key = selector.register(self.fileno(), event)
        events = selector.select(self.timeout)
        selector.unregister(select_key.fd)
        return events
class sslsock():
    def __init__(self, sock, context_name) -> None:
         super().__init__()
         self.sock = sock
         self.context_name = context_name
         self.count = 1
         self.count2 = 1
        #  self.fileno = sock.fileno
    # def __getattribute__(self, __name: str):
    #     if hasattr(self, __name):
    #         return super().__getattribute__(__name)
    #     return getattr(self.sock, __name)
    def send(self, *args):
        self.count2 += 1
        e = iowait(self.sock, selectors.EVENT_WRITE)
        if len(args[0]) == 0:
            return 0
        print("write >>>", self.count2, e, len(args[0]))
        if not e:
            raise TimeoutError('write')
        return self.sock.send(*args)
    def recv(self, *args):
        self.count += 1
        e = iowait(self.sock)
        
        print("read >>>", self.count, e, os.get_blocking(self.sock.fileno()), self.context_name)
        if not e:
            raise TimeoutError('read')
        return self.sock.recv(*args)


def test_wrap_default():
    import ssl, socket
    SERVER_NAME, SERVER_PORT = "www.bing.com", 443
    # generic socket and ssl configuration
    socket.setdefaulttimeout(TIMEOUT)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['http/1.1'])

    # open a socket to the server and initiate TLS/SSL
    s = socket.create_connection((SERVER_NAME, SERVER_PORT))
    s = ctx.wrap_socket(s, server_hostname=SERVER_NAME)
    write(s, False)
# test1()
# test2()

test_wrap_all()
# test_wrap_default()
# test_wrap_default()
