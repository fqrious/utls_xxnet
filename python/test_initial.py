import pyutls
import codecs
from pyutls_wrap import SSLConnection, SSLContext
from logging import getLogger
import h2.connection
import h2.events


logger = getLogger(__name__)

def test1():
    ctx  = pyutls.new_ssl_context(772)
    sock = pyutls.new_ssl_connection(ctx, "www.google.com:443", "www.google.com")
    print("writing...")
    pyutls.ssl_connection_write(sock, b"HEAD / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
    print("reading...")
    out = pyutls.ssl_connection_read(sock, 1000)
    print(len(out), out)

def test2():
    packet = codecs.decode("1603010200010001fc03034e7b309f8179598f97b0add0a541583bc75324fa0e5c9c61f50e0e8012e8364f20a82353f273ec45d46b1bc8983d7ed611d82b4f4957b34fb0a5b3c141533b71c00022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00350100019100000010000e00000b6578616d706c652e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00203aa102ca6f5644cbebdd5252bc3122ef48876ec476acb140913a88645a92402e001700410407f790903a02131e2354a4acdd37a0591ef7c626292afb03800666c65272a8726103da947ef38a27891e025ec409758625c954ea5ec19cc460c59f6d9aa86120002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c000240010015008b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "hex")
    print(type(packet), packet[0])
    ctx  = pyutls.new_ssl_context_from_bytes(True, False, packet)
    sock = pyutls.new_ssl_connection(ctx, "www.google.com:443", "www.google.com")
    # h2support = pyutls.ssl_connection_h2_support(sock)
    # print("Before Handshake, H2 Support =>", h2support)
    print("writing...")
    pyutls.ssl_connection_write(sock, b"HEAD / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")

    h2support = pyutls.ssl_connection_h2_support(sock)
    print("After Handshake, H2 Support =>", h2support)

    # closed = pyutls.ssl_connection_close(sock) #close
    # print("Closed =>", closed)
    closed = pyutls.ssl_connection_closed(sock) #close
    print("Closed =>", closed)
    print("reading...")
    out = pyutls.ssl_connection_read(sock, 1000)
    print(len(out), out)

def test_wrap(ctx, name):
    print("=============>", name, "<=============")
    sock = SSLConnection(ctx, None, "www.google.com:443", b"www.google.com")
    # h2support = pyutls.ssl_connection_h2_support(sock)
    # print("Before Handshake, H2 Support =>", h2support)
    
    sock.do_handshake()
    h2support = sock.is_support_h2()
    print("After Handshake, H2 Support =>", h2support)
    cert_bytes = sock.get_cert()
    print("Cert", cert_bytes)
    if h2support:
        # print("h2 connection not implemented")
        write_h2(sock)
        return
    write(sock)
    write(sock)

    

def write(sock):
    print("writing...")
    sock.send(b"HEAD / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
    print("reading...")
    # out = pyutls.ssl_connection_read(sock, 1000)
    out =  sock.recv(5000)
    print(len(out), out)

def write_h2(sock):
    s = sock
    s.sendall = s.send

    c = h2.connection.H2Connection()
    c.initiate_connection()
    sock.send(c.data_to_send())

    headers = [
        (':method', 'HEAD'),
        (':path', '/'),
        (':authority', 'www.google.com'),
        (':scheme', 'https'),
    ]
    c.send_headers(1, headers, end_stream=True)
    s.sendall(c.data_to_send())

    body = b''
    response_stream_ended = False
    while not response_stream_ended:
        # read raw data from the socket
        data = s.recv(65536 * 1024)
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
    print(body.decode())

    # tell the server we are closing the h2 connection
    c.close_connection()
    s.sendall(c.data_to_send())

def  test_wrap_both():
    curl_hex = "1603010200010001fc03039b72af275b37da871055d2988b00f9c4d98a15c068bd7270c8ec68eb0b5056bc20abb125ce53c8c46023a2a30bfe94b8ff5ce1f8167e8368a979f2b8937849993b003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100017500000014001200000f7777772e6578616d706c652e636f6d000b000403000102000a00160014001d0017001e00190018010001010102010301040010000b000908687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d0020a4b1c882803406b54c4956f6dec05ee7953d785fb6a7b64557d12a6d03ef243d001500b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    packet = codecs.decode("1603010200010001fc03034e7b309f8179598f97b0add0a541583bc75324fa0e5c9c61f50e0e8012e8364f20a82353f273ec45d46b1bc8983d7ed611d82b4f4957b34fb0a5b3c141533b71c00022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00350100019100000010000e00000b6578616d706c652e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00203aa102ca6f5644cbebdd5252bc3122ef48876ec476acb140913a88645a92402e001700410407f790903a02131e2354a4acdd37a0591ef7c626292afb03800666c65272a8726103da947ef38a27891e025ec409758625c954ea5ec19cc460c59f6d9aa86120002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c000240010015008b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "hex")
    chrome_context  = SSLContext.from_bytes(logger, packet)
    packet2 = codecs.decode(curl_hex, 'hex')
    curl_1_1_context = SSLContext.from_bytes(logger, packet2)
    test_wrap(curl_1_1_context, "curl_1.1_context")
    test_wrap(chrome_context,  "chrome_context")


    SSLContext.from_bytes(logger, hex=curl_hex)

def test_wrap_default():
    import ssl, socket
    SERVER_NAME, SERVER_PORT = "www.google.com", 443
    # generic socket and ssl configuration
    socket.setdefaulttimeout(15)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])

    # open a socket to the server and initiate TLS/SSL
    s = socket.create_connection((SERVER_NAME, SERVER_PORT))
    s = ctx.wrap_socket(s, server_hostname=SERVER_NAME)
    write_h2(s)
# test1()
# test2()

test_wrap_both()
# test_wrap_default()