package main

/*
// #cgo pkg-config: python-3.10
// #cgo CFLAGS: -I/usr/include/python3.10 -Wno-error -Wno-implicit-function-declaration -Wno-int-conversion
// #cgo LDFLAGS: -L/usr/lib -lpython3.10 -lcrypt -ldl  -lm -lm

#include <stdlib.h>
#include "cgo.h"

// for duplicate_fd
#include <fcntl.h>
#include <unistd.h>

ssize_t duplicate_fd(ssize_t fd);

PyObject* ssl_connection_return(ssize_t handle, ssize_t fd);

*/
import "C"
import (
	"bytes"
	"fmt"
	"net"
	"unsafe"
)

var (
	CERT_DELIM = []byte("|!|!|")
)

//export build_bytes
func build_bytes(b []byte) *C.PyObject {
	if len(b) <= 0 {
		panic("string too large")
	}
	p := C.malloc(C.size_t(len(b)))
	defer C.free(p)
	sliceHeader := struct {
		p   unsafe.Pointer
		len int
		cap int
	}{p, len(b) + 1, len(b) + 1}
	b_temp := *(*[]byte)(unsafe.Pointer(&sliceHeader))
	copy(b_temp, b) // to be removed since python actually copies the memory
	val := (*C.char)(p)
	return C.PyBytes_FromStringAndSize(val, C.Py_ssize_t(len(b)))
}

//export build_bytes_no_copy
func build_bytes_no_copy(b []byte) *C.PyObject {
	// b_temp := *(*[]byte)(unsafe.Pointer(&sliceHeader))
	// copy(b_temp, b) // to be removed since python actually copies the memory
	data := unsafe.SliceData(b)
	val := (*C.char)(unsafe.Pointer(data))
	return C.PyBytes_FromStringAndSize(val, C.Py_ssize_t(len(b)))
	// return nil
}

func pointer_as_slice[T any](p unsafe.Pointer, length int) []T {
	sliceHeader := struct {
		p   unsafe.Pointer
		len int
		cap int
	}{p, length, length}
	return *(*[]T)(unsafe.Pointer(&sliceHeader))
}

// func slice_as_pointer[T any](x []T) {
// 	unsafe.Pointer(x)
// }

func py2go_bytes(pybuf *C.PyObject, shouldCopy bool) []byte {
	var (
		bufptr *C.char
		length C.Py_ssize_t
	)
	C.PyBytes_AsStringAndSize(pybuf, &bufptr, &length)
	pybuf_slice := pointer_as_slice[byte](unsafe.Pointer(bufptr), int(length))
	if shouldCopy {
		buf := make([]byte, length)
		copy(buf, pybuf_slice)
		return buf
	}
	return pybuf_slice
}

type PyObject *C.PyObject

func CreateBytes() []byte {
	return []byte("Hello")
}

func handleError(e error) {
	if e != nil {
		estr := C.CString(e.Error())
		defer C.free(unsafe.Pointer(estr))
		C.PyErr_SetString(C.PyExc_RuntimeError, estr)
	}
}

//export PyInit_ss
// func PyInit_ss() *C.PyObject {
// 	m := C.pymodule_def()
// 	return m
// }

//export go_new_ssl_connection
func go_new_ssl_connection(ctxptr uintptr, address, sni *C.char) *C.PyObject {
	ctx := Handle[*SSLContext](ctxptr).Value()
	s, err := NewSSLConnection(ctx, 0, C.GoString(address), C.GoString(sni))
	if err != nil {
		handleError(err)
		return nil
	}
	fd := duplicate_fd((s.conn.GetUnderlyingConn()))
	if fd != 0 {
		handle := NewHandle[any](s).Ptr()
		return C.ssl_connection_return(C.ssize_t(handle), fd)
	}
	return nil
}

func duplicate_fd(conn net.Conn) C.ssize_t {
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		handleError(err)
		return 0
	}
	defer f.Close()
	return C.duplicate_fd(C.ssize_t(f.Fd()))

}

//export go_ssl_connection_read
func go_ssl_connection_read(cptr uintptr, size uint32) *C.PyObject {
	c := Handle[*SSLConnection](cptr).Value()
	bytes, err := c.Recv(size)
	if err != nil {
		handleError(err)
		return nil
	}
	return build_bytes_no_copy(bytes)
}

//export go_ssl_connection_write
func go_ssl_connection_write(cptr uintptr, pybuf *C.PyObject) C.long {
	buf := py2go_bytes(pybuf, false)
	c := Handle[*SSLConnection](cptr).Value()
	bytes_written, err := c.Send(buf)
	if err != nil {
		handleError(err)
		return 0
	}
	return C.long(bytes_written)
}

//export go_ssl_connection_do_handshake
func go_ssl_connection_do_handshake(cptr uintptr) bool {
	c := Handle[*SSLConnection](cptr).Value()
	err := c.conn.Handshake()
	if err != nil {
		handleError(err)
		return false
	}
	return true
}

//export go_ssl_connection_h2_support
func go_ssl_connection_h2_support(cptr uintptr) bool {
	c := Handle[*SSLConnection](cptr).Value()
	state := c.conn.ConnectionState()
	if !state.HandshakeComplete {
		handleError(fmt.Errorf("handshake not complete"))
		return false
	}
	return state.NegotiatedProtocol == "h2"
}

//export go_ssl_connection_get_cert
func go_ssl_connection_get_cert(cptr uintptr) *C.PyObject {
	c := Handle[*SSLConnection](cptr).Value()
	state := c.conn.ConnectionState()
	if !state.HandshakeComplete {
		handleError(fmt.Errorf("handshake not complete"))
		return nil
	}
	if len(state.PeerCertificates) == 0 {
		handleError(fmt.Errorf("len(peer_certificates) is 0"))
		return nil
	}
	certs := state.PeerCertificates
	// leaf_cert := certs[0]
	// return build_bytes_no_copy(leaf_cert.Raw)

	// subject := cert.Subject.String()
	// commonName := cert.Subject.CommonName
	// issuer := cert.Issuer.String()
	// issuerName := cert.Issuer.CommonName
	// altNames := cert.DNSNames
	// ret_list := []string{subject, commonName, issuer, issuerName, strings.Join(altNames, ";!")}
	// return build_bytes([]byte(strings.Join(ret_list, "|!")))
	certs_raws := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		certs_raws = append(certs_raws, cert.Raw)
	}
	return build_bytes_no_copy(bytes.Join(certs_raws, CERT_DELIM))

}

//export go_ssl_connection_close
func go_ssl_connection_close(cptr uintptr, close_context bool) bool {
	connptr := Handle[*SSLConnection](cptr)
	defer connptr.Delete() // clean up handle file
	c := connptr.Value()

	err := c.conn.Close()
	if err != nil {
		handleError(err)
		return false
	}
	return true
}

//export go_ssl_connection_closed
func go_ssl_connection_closed(cptr uintptr) bool {
	connptr := Handle[*SSLConnection](cptr)
	// check if handle is valid
	if valid := connptr.Valid(); !valid {
		return true
	}
	// _ = connptr.Value()
	return false
}

//export go_delete_handle
func go_delete_handle(hptr uintptr) bool {
	handle := Handle[any](hptr)
	handle.Delete()
	return true
}

//export go_new_ssl_context
func go_new_ssl_context(protocol uint16, with_alpn bool) uintptr {
	ctx, err := NewSSLContext(protocol, with_alpn)
	if err != nil {
		handleError(err)
		return 0
	}
	return NewHandle[any](ctx).Ptr()
}

//export go_new_ssl_context_from_bytes
func go_new_ssl_context_from_bytes(hello_bytes *C.PyObject, blunt, always_pad bool) uintptr {
	// C.INCREF(hello_bytes)
	// defer C.DECREF(hello_bytes)
	hello := py2go_bytes(hello_bytes, false)
	ctx, err := NewSSLContextFromHelloBytes(hello, blunt, always_pad)
	if err != nil {
		handleError(err)
		return 0
	}
	return uintptr(NewHandle[any](ctx))
}

//export go_clear_handle
func go_clear_handle(hptr uintptr) {
	Handle[any](hptr).Delete()
}

func init2() {

	/////////
	// ctx := go_new_ssl_context(tls.VersionTLS13)
	// c := go_new_ssl_connection(ctx, C.CString("google.com:443"), C.CString("www.google.com"))
	// send_buf := build_bytes([]byte("HEAD / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
	// go_ssl_connection_write(c, send_buf)
	// pybuf := go_ssl_connection_read(c, 1024)
	// buf := py2go_bytes(pybuf, true)
	// fmt.Println("<==========> Response <==========>", "\n", string(buf))

}

func main() {

	/////////
	// ctx := go_new_ssl_context(tls.VersionTLS13)
	// c := go_new_ssl_connection(ctx, C.CString("google.com:443"), C.CString("www.google.com"))
	// send_buf := build_bytes([]byte("yes"))
	// go_ssl_connection_write(c, send_buf)
	// pybuf := go_ssl_connection_read(c, 1024)
	// buf := py2go_bytes(pybuf, true)
	// fmt.Println("<==========> Response <==========>", "\n", string(buf))

}
