package main

import (
	"net"
	"os"

	tls "github.com/refraction-networking/utls"
)

type SSLContext struct {
	spec   *tls.ClientHelloSpec
	config *tls.Config
}

var ()

func (ctx *SSLContext) SetCA(ca os.File) {
	panic("Not Implemented")
}

func (ctx *SSLContext) WrapSocket(socket net.Conn) (*tls.UConn, error) {
	conn := tls.UClient(socket, ctx.config, tls.HelloCustom)
	err := conn.ApplyPreset(ctx.spec)
	conn.Handshake()
	return conn, err
}

func NewSSLContext(protocol uint16) (*SSLContext, error) {
	spec, _ := tls.UTLSIdToSpec(tls.HelloAndroid_11_OkHttp)
	spec.TLSVersMax = protocol
	spec.TLSVersMin = tls.VersionTLS10
	return &SSLContext{
		spec:   &spec,
		config: &tls.Config{},
	}, nil
}
