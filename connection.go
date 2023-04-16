package main

import (
	"net"
	"os"

	tls "github.com/refraction-networking/utls"
)

type FD int

func (fd FD) FDtoConn() (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "any_name")
	defer f.Close()
	return net.FileConn(f)
}

type SSLConnection struct {
	conn    *tls.UConn
	ctx     *SSLContext
	sock    net.Conn
	address string
	sni     string
}

func NewSSLConnection(ctx *SSLContext, sockfd FD, address, sni string) (*SSLConnection, error) {
	// sock, err := sockfd.FDtoConn()
	sock, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	self := &SSLConnection{
		ctx:     ctx,
		sock:    sock,
		address: address,
		sni:     sni,
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
	data := make([]byte, bufsize)
	length, err := sc.conn.Read(data)
	return data[:length], err
}

func (sc *SSLConnection) Send(buf []byte) (int, error) {
	// data := make([]byte, bufsize)
	return sc.conn.Write(buf)
}
