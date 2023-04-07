import pyutls
import codecs

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

# test1()
test2()