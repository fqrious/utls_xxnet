import pyutls


ctx  = pyutls.new_ssl_context(772)
sock = pyutls.new_ssl_connection(ctx, "www.google.com:443", "www.google.com")
print("writing...")
pyutls.ssl_connection_write(sock, b"HEAD / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
print("reading...")
out = pyutls.ssl_connection_read(sock, 1000)
print(len(out), out)