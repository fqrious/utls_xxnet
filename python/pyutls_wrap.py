# this wrap has a close callback.
# Which is used by ip manager
#  ip manager keep a connection number counter for every ip.

import os
import socket
import selectors
import threading
import codecs
from asn1crypto.x509 import Certificate

import utils

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
    ssl_connection_set_timeout,
    #  context functions
    new_ssl_context,
    new_ssl_context_from_bytes,

    # others functions
    close_go_handle
)


class HandleObject:
    _handle = 0

    def __init__(self, handle):
        self._handle = handle

    @property
    def handle(self):
        return self._handle

    def __del__(self):
        if self.handle != 0:
            close_go_handle(self.handle)

    def run(self, fn, *args, **kwargs):
        return fn(self.handle, *args, **kwargs)


class SSLContext(HandleObject):
    ALLOW_BLUNT_MIMICRY = True
    ALWAYS_PAD = False

    def __init__(self, logger, ca_certs=None, cipher_suites=None, support_http2=True, protocol=None, handle=None):
        self.logger = logger
        if not handle:
            self.context = self
            self.support_http2 = support_http2
            tls_ver = 772
            handle = new_ssl_context(tls_ver, support_http2)
        HandleObject.__init__(self, handle)

    @classmethod
    def from_bytes(cls, logger, raw_bytes: bytes = None, hex: str = None):
        if hex:
            raw_bytes = codecs.decode(hex, "hex")
        handle = new_ssl_context_from_bytes(cls.ALLOW_BLUNT_MIMICRY, cls.ALWAYS_PAD, raw_bytes)
        obj = cls(logger, handle=handle)
        return obj

    def supported_protocol(self):
        return "TLS 1.3"

    def support_alpn_npn(self):
        return "alpn"


class SSLConnection(HandleObject):
    _on_close = None
    CERT_DELIM = b"|!|!|"
    timeout = 0
    @staticmethod
    def formatP_ip_str(ip_str):
        ip, port = utils.get_ip_port(ip_str)
        ip = utils.to_str(ip)
        if ":" in ip:
            ip = '[' + ip + ']'
        return f'{ip}:{port}'

    socket_closed = False

    def __init__(self, context: SSLContext, sock, ip_str=None, sni=None, on_close=None):
        self._lock = threading.Lock()
        self._context = context
        self._sock = sock
        self.ip_str = self.formatP_ip_str(ip_str)
        self.sni = utils.to_str(sni)
        if not sni:
            self.sni = " "
        self._makefile_refs = 0
        self._on_close = on_close
        self.peer_cert = None
        self.socket_closed = False
        self.running = True
        self._connection = None
        
        self.wrap()

    def wrap(self):
        try:
            handle, fd = new_ssl_connection(self._context.handle, self.ip_str, self.sni)
        except Exception as e:
            if "no route to host" in e.args[0]:
                raise socket.error

            self._context.logger.exception("wrap %s e:%r", self.ip_str, e)
            raise e

        # os.set_blocking(fd, False)
        # newfd = os.dup(fd)
        self._fileno = fd
        HandleObject.__init__(self, handle)


    def __iowait(self, event=selectors.EVENT_READ):
        selector = selectors.DefaultSelector()
        select_key = selector.register(self.fileno(), event)
        events = selector.select(self.timeout)
        selector.unregister(select_key.fd)
        return events

    @property
    def is_closed(self):
        if not self.socket_closed:
            self.socket_closed = ssl_connection_closed(self.handle)
        return self.socket_closed

    def do_handshake(self):
        events = self.__iowait(selectors.EVENT_WRITE)
        if not events:
            raise TimeoutError("Handshake timed out after %s seconds"%self.timeout)
        return self.run(ssl_connection_do_handshake)

    def is_support_h2(self):
        return ssl_connection_h2_support(self.handle)

    def setblocking(self, block):
        self._context.logger.debug("%s setblocking: %d", self.ip_str, block)
        # already non blocking
        return

    def get_cert(self):
        if self.peer_cert:
            return self.peer_cert
        certs = self.get_peercertificates()
        # self._context.logger.debug("Got %d certificates, using leaf cert with index 0", len(certs))

        cert = certs[0]
        try:
            altName = cert.subject_alt_name_value.native
        except:
            altName = []

        self.peer_cert = {
            "cert": cert,
            "issuer_commonname": cert.issuer.human_friendly,
            "commonName": "",
            "altName": altName
        }
        return self.peer_cert

    def get_peercertificates(self):
        cert_bytes = self.run(ssl_connection_leaf_cert)
        cert_arr = cert_bytes.split(self.CERT_DELIM)
        return tuple(map(Certificate.load, cert_arr))

    def send(self, data, flags=0):
        # if len(data) == 0:
        #     return 0
        events = self.__iowait(selectors.EVENT_WRITE)
        if not events:
            raise TimeoutError("Write timed out after %s seconds"%self.timeout)
        return ssl_connection_write(self.handle, data)

    def recv(self, bufsiz, flags=0):
        if out := ssl_connection_read(self.handle, bufsiz, no_wait=True): #attempt to read what's left in buffer without blocking
            return out
        events = self.__iowait(selectors.EVENT_READ)
        if not events:
            raise TimeoutError("Read timed out after %s seconds"%self.timeout)
        return ssl_connection_read(self.handle, bufsiz)

    def recv_into(self, buf, nbytes=None):
        if not nbytes:
            nbytes = len(buf)

        dat = self.recv(nbytes)
        n = len(dat)
        buf[:n] = dat
        return n

    def read(self, bufsiz, flags=0):
        return self.recv(bufsiz, flags)

    def write(self, buf, flags=0):
        return self.send(buf, flags)

    def close(self):
        ret = None
        with self._lock:
            self.running = False
            if not self.socket_closed:
                if self.handle:
                    ret = ssl_connection_close(self.handle)

                self.socket_closed = True
                if self._on_close:
                    self._on_close(self.ip_str)
        return ret

    def __del__(self):
        self.close()

    def settimeout(self, t):
        if not self.running:
            return

        if self.timeout != t:
            self._context.logger.debug("settimeout %d", t)
            # self.run(ssl_connection_set_timeout, t, t)
            self.timeout = t

        # if self.timeout != t:
        #     # self._context.logger.debug("settimeout %d", t)
        #     self._sock.settimeout(t)
        #     self.timeout = t

    def makefile(self, mode='r', bufsize=-1):
        self._makefile_refs += 1
        return socket._fileobject(self, mode, bufsize, close=True)

    def fileno(self):
        return self._fileno


class SSLCert:
    def __init__(self, cert):
        """
            Returns a (common name, [subject alternative names]) tuple.
        """
        self.x509 = cert
