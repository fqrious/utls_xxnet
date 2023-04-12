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
	// conn.Handshake()
	return conn, err
}

func NewSSLContext(protocol uint16) (*SSLContext, error) {
	spec, _ := tls.UTLSIdToSpec(tls.HelloChrome_100)
	spec.TLSVersMax = protocol
	spec.TLSVersMin = tls.VersionTLS10
	return newSSLContext(&spec), nil
}

func newSSLContext(spec *tls.ClientHelloSpec) *SSLContext {
	return &SSLContext{
		spec:   spec,
		config: &tls.Config{},
	}
}

func NewSSLContextFromHelloBytes(hello []byte, allow_blunt_mimicry, always_pad bool) (*SSLContext, error) {
	// fmt.Printf("\nFp Hash: %x\n", md5.New().Sum(hello))
	// fmt.Println("Allow Blunt: ", allow_blunt_mimicry)
	// fmt.Println("Always Pad:  ", always_pad)
	f := &tls.Fingerprinter{
		AllowBluntMimicry: allow_blunt_mimicry,
		AlwaysAddPadding:  always_pad,
	}
	spec, err := f.FingerprintClientHello(hello)
	if err != nil {
		return nil, err
	}
	return newSSLContext(spec), nil
}
