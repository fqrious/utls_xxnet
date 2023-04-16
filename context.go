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

func NewSSLContext(protocol uint16, with_alpn bool) (*SSLContext, error) {
	var spec tls.ClientHelloSpec
	if with_alpn {
		spec, _ = tls.UTLSIdToSpec(tls.HelloRandomizedALPN)
	} else {
		spec, _ = tls.UTLSIdToSpec(tls.HelloRandomizedNoALPN)
	}
	spec.TLSVersMax = protocol
	spec.TLSVersMin = tls.VersionTLS10
	return newSSLContext(&spec), nil
}

// func setVersMax(spec tls.ClientHelloSpec, ver uint16){
// // 	spec.TLSVersMax = ver
// // 	for _, ext := range spec.Extensions{
// // 		if ext2, ok := ext.(*tls.SupportedVersionsExtension); ok{
// // 			ext2.Versions = make
// // 		}
// // 	}
// 	r, _ := tls.NewRoller()
// 	r.
// }

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
