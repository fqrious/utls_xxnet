package main

import (
	"fmt"
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
	conn      *tls.UConn
	ctx       *SSLContext
	sock      net.Conn
	address   string
	sni       string
	failAfter time.Duration
}

func NewSSLConnection(ctx *SSLContext, sockfd FD, address, sni string) (*SSLConnection, error) {
	// sock, err := sockfd.FDtoConn()
	sock, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	self := &SSLConnection{
		ctx:       ctx,
		sock:      sock,
		address:   address,
		sni:       sni,
		failAfter: time.Second * time.Duration(5),
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
	fmt.Println("Will Fail After:", sc.failAfter.Seconds())
	if sc.failAfter != 0 {
		defer sc.resetDeadlines()
		sc.conn.SetReadDeadline(time.Now().Add(sc.failAfter))
	}
	return sc.recv(bufsize)
}
func (sc *SSLConnection) resetDeadlines() {
	// sc.conn.SetReadDeadline(time.Time{})
	// sc.conn.SetWriteDeadline(time.Time{})
}

func (sc *SSLConnection) recv(bufsize uint32) ([]byte, error) {
	data := make([]byte, bufsize)
	length, err := sc.conn.Read(data)
	return data[:length], err
}

func (sc *SSLConnection) RecvNoWait(bufsize uint32) ([]byte, error) {
	defer sc.resetDeadlines()
	sc.conn.SetDeadline(time.Now().Add(time.Millisecond * 1))
	data, _ := sc.recv(bufsize)
	return data, nil
}

func (sc *SSLConnection) Send(buf []byte) (int, error) {
	// data := make([]byte, bufsize)
	if sc.failAfter != 0 {
		defer sc.resetDeadlines()
		sc.conn.SetWriteDeadline(time.Now().Add(sc.failAfter))
	}
	return sc.conn.Write(buf)
}
