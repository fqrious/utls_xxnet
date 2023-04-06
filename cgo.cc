#include <iostream>


extern "C"{

#include <Python.h>
#include "cgo.h"
// #include "ss.h"

// struct PyModuleDef moduledef = {
// 		PyModuleDef_HEAD_INIT,
// 		"name",
// 		NULL,
// 		-1,
// 		_pyutls_functions,
// 	};
typedef size_t GoPtr;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
extern GoPtr go_new_ssl_connection(GoPtr ctxptr, const char* address, const char* sni);
extern PyObject* go_ssl_connection_read(GoPtr cptr, GoUint32 size);
extern long int go_ssl_connection_write(GoPtr cptr, PyObject* pybuf);
extern GoPtr go_new_ssl_context(GoUint16 protocol);
extern void go_clear_handle(GoPtr hptr);


static PyObject * new_ssl_connection(PyObject *self, PyObject *args)
{
    const char *address, *sni;
    GoPtr ctxptr;
    if (!PyArg_ParseTuple(args, "nss", &ctxptr, &address, &sni))
        return NULL;
    auto sts = go_new_ssl_connection(ctxptr, address, sni);
    return PyLong_FromLong(sts);
}

static PyObject * new_ssl_context(PyObject *self, PyObject *args)
{
    uint16_t protocol;
    if (!PyArg_ParseTuple(args, "H", &protocol))
        return NULL;
    auto ctx = go_new_ssl_context(protocol);
    return PyLong_FromLong(ctx);
}

static PyObject * ssl_connection_read(PyObject *self, PyObject *args)
{
    int read_size;
    GoPtr ctxptr;
    if (!PyArg_ParseTuple(args, "ni", &ctxptr, &read_size))
        return NULL;
    auto bytes = go_ssl_connection_read(ctxptr, read_size);
    return bytes;
}

static PyObject * ssl_connection_write(PyObject *self, PyObject *args)
{
    PyObject * bytes;
    GoPtr ctxptr;
    if (!PyArg_ParseTuple(args, "nS", &ctxptr, &bytes))
        return NULL;
    auto len = go_ssl_connection_write(ctxptr, bytes);
    return PyLong_FromLong(len);
}


static PyMethodDef functions[] = {
	{"new_ssl_connection", new_ssl_connection, METH_VARARGS, "Create a new socket"},
	{"ssl_connection_read", ssl_connection_read, METH_VARARGS, "Read bytesize from SSLConnwction"},
	{"ssl_connection_write", ssl_connection_write, METH_VARARGS, "Write bytes to SSLConnwction"},
	{"new_ssl_context", new_ssl_context, METH_VARARGS, "Create a new SSLContext"},
	{NULL, NULL, 0, NULL},
};
// static moduledef = new PyModuleDef {
// 		PyModuleDef_HEAD_INIT,
// 		"name",
// 		NULL,
// 		-1,
// 		functions,
// 	};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_pyutls",
    NULL,
    -1,
    functions,
};
PyObject* pymodule_def()
{
	return PyModule_Create(&moduledef);
}


PyObject* PyInit_pyutls(void){
	return pymodule_def();
}

}

