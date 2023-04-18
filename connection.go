package main

import (
	"net"
	"os"
	"time"

	tls "github.com/refraction-networking/utls"
)

type FD int

func (fd FD) FDtoConn() (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "any_name")
	defer f.Close()
	return net.FileConn(f)
}

type SSLConnection struct {
	conn         *tls.UConn
	ctx          *SSLContext
	sock         net.Conn
	address      string
	sni          string
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func NewSSLConnection(ctx *SSLContext, sockfd FD, address, sni string) (*SSLConnection, error) {
	// sock, err := sockfd.FDtoConn()
	sock, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	self := &SSLConnection{
		ctx:          ctx,
		sock:         sock,
		address:      address,
		sni:          sni,
		readTimeout:  0,
		writeTimeout: 0,
	}

	if err = self.wrap(); err != nil {
		return nil, err
	}
	return self, nil
}

func (sc *SSLConnection) wrap() error {
	sc.ctx.config.ServerName = sc.sni

	conn, err := sc.ctx.WrapSocket(sc.sock)
	if err != nil {
		return err
	}
	sc.conn = conn
	return nil
}

func (sc *SSLConnection) Recv(bufsize uint32) ([]byte, error) {
	if sc.readTimeout != 0 {
		sc.conn.SetReadDeadline(time.Now().Add(sc.readTimeout))
	}
	data := make([]byte, bufsize)
	length, err := sc.conn.Read(data)
	return data[:length], err
}

func (sc *SSLConnection) RecvNoWait(bufsize uint32) ([]byte, error) {
	sc.conn.SetReadDeadline(time.Now())
	data := make([]byte, bufsize)
	length, err := sc.conn.Read(data)
	if err != nil {
		length = 0
	}
	sc.conn.SetReadDeadline(time.Time{})
	return data[:length], nil
}

func (sc *SSLConnection) Send(buf []byte) (int, error) {
	// data := make([]byte, bufsize)
	if sc.writeTimeout != 0 {
		sc.conn.SetWriteDeadline(time.Now().Add(sc.writeTimeout))
	}
	return sc.conn.Write(buf)
}
