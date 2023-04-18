#include <iostream>

extern "C"
{

#include <Python.h>
#include "cgo.h"
#include "safepy.h"
#include "_cgo_export.h"


#include <stdbool.h>

static inline void INCREF(PyObject* obj){
	Py_XINCREF(obj);
}

static inline void DECREF(PyObject* obj){
	Py_XDECREF(obj);
}

inline PyObject* py_bool_from_bool(bool truth){
	if (truth)
        Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

    typedef size_t GoHandle;
    static PyObject* PyUTLS_Exc;

    void py_set_error(char* err){
        SAFEPY_BEGIN
        PyErr_SetString(PyUTLS_Exc, err);
        SAFEPY_END
    }


    static PyObject *new_ssl_connection(PyObject *self, PyObject *args)
    {
        char *address, *sni;
        GoHandle ctxptr;
        if (!PyArg_ParseTuple(args, "nss", &ctxptr, &address, &sni))
            return NULL;
        auto tuple = go_new_ssl_connection(ctxptr, address, sni);
        return tuple;
    }

    static PyObject *new_ssl_context(PyObject *self, PyObject *args)
    {
        uint16_t protocol;
        int with_alpn;
        if (!PyArg_ParseTuple(args, "Hp", &protocol, &with_alpn))
            return NULL;
        auto ctx = go_new_ssl_context(protocol, with_alpn);
        return PyLong_FromLong(ctx);
    }

    static PyObject *new_ssl_context_from_bytes(PyObject *self, PyObject *args)
    {
        PyObject *bytes;
        int blunt, padding;
        if (!PyArg_ParseTuple(args, "ppS", &blunt, &padding, &bytes))
            return NULL;
        Py_XINCREF(bytes);
        auto ctx = go_new_ssl_context_from_bytes(bytes, blunt, padding);
        Py_XDECREF(bytes);
        SAFEPY_Return(PyLong_FromLong(ctx));
    }
    static PyObject *ssl_connection_read(PyObject *self, PyObject *args, PyObject * kwargs)
    {
        int read_size;
        GoHandle ctxptr;
        PyObject* bytes;
        int no_wait = 0;
        static char *kwlist[] = {"ctxptr", "read_size", "no_wait", NULL};
        // if (!PyArg_ParseTuple(args, kwargs, "ni", kwlist, &ctxptr, &read_size, &no_wait))
        // if (!PyArg_ParseTuple(args, "ni", &ctxptr, &read_size))
        //     return NULL;
        if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ni|p", kwlist, &ctxptr, &read_size, &no_wait))
            return NULL;
        Py_BEGIN_ALLOW_THREADS
        bytes = go_ssl_connection_read(ctxptr, read_size, no_wait);
        Py_END_ALLOW_THREADS
        SAFEPY_Return(bytes);
    }

    static PyObject *ssl_connection_write(PyObject *self, PyObject *args)
    {
        PyObject *bytes;
        GoHandle ctxptr;
        if (!PyArg_ParseTuple(args, "nS", &ctxptr, &bytes))
            return NULL;
        int len;
        Py_BEGIN_ALLOW_THREADS
        len = go_ssl_connection_write(ctxptr, bytes);
        Py_END_ALLOW_THREADS
        SAFEPY_Return(PyLong_FromLong(len));
    }

    static PyObject *ssl_connection_h2_support(PyObject *self, PyObject *args)
    {
        GoHandle ctxptr;
        if (!PyArg_ParseTuple(args, "n", &ctxptr))
            return NULL;
        bool h2_support = go_ssl_connection_h2_support(ctxptr);
        SAFEPY_Return(py_bool_from_bool(h2_support));
    }


    static PyObject *ssl_connection_leaf_cert(PyObject *self, PyObject *args)
    {
        GoHandle ctxptr;
        if (!PyArg_ParseTuple(args, "n", &ctxptr))
            return NULL;
        PyObject * leaf_cert = go_ssl_connection_get_cert(ctxptr);
        SAFEPY_Return(leaf_cert);
    }

        static PyObject *ssl_connection_close(PyObject *self, PyObject *args)
    {
        // const char **kw = {"close_context",NULL};
        bool close_context = true;
        GoHandle ctxptr;
        if (!PyArg_ParseTuple(args, "n", &ctxptr))
            return NULL;
        bool closed = go_ssl_connection_close(ctxptr, close_context);
        SAFEPY_Return(py_bool_from_bool(closed));
    }


        static PyObject *ssl_connection_set_timeout(PyObject *self, PyObject *args)
    {
        // const char **kw = {"close_context",NULL};
        bool close_context = true;
        GoHandle ctxptr;
        int readTimeout, writeTimeout;
        if (!PyArg_ParseTuple(args, "nii", &ctxptr, &readTimeout, &writeTimeout))
            return NULL;
        go_ssl_connection_set_timeout(ctxptr, readTimeout, writeTimeout);
        SAFEPY_Return(Py_NewRef(Py_None));
    }



        static PyObject *ssl_connection_closed(PyObject *self, PyObject *args)
    {
        GoHandle ctxptr;
        if (!PyArg_ParseTuple(args, "n", &ctxptr))
            return NULL;
        bool closed = go_ssl_connection_closed(ctxptr);
        SAFEPY_Return(py_bool_from_bool(closed));
    }

        static PyObject *ssl_connection_do_handshake(PyObject *self, PyObject *args)
    {
        GoHandle ctxptr;
        if (!PyArg_ParseTuple(args, "n", &ctxptr))
            return NULL;
        bool done;
        Py_BEGIN_ALLOW_THREADS
        done = go_ssl_connection_do_handshake(ctxptr);
        Py_END_ALLOW_THREADS
        SAFEPY_Return(py_bool_from_bool(done));
    }

        static PyObject *close_go_handle(PyObject *self, PyObject *args)
    {
        GoHandle ctxptr;
        if (!PyArg_ParseTuple(args, "n", &ctxptr))
            return NULL;
        bool closed = go_delete_handle(ctxptr);
        SAFEPY_Return(py_bool_from_bool(closed));
    }

    static PyMethodDef functions[] = {
        // ssl_connection
        {"new_ssl_connection", new_ssl_connection, METH_VARARGS, "Create a new socket"},
        {"ssl_connection_read", (PyCFunction) ssl_connection_read, METH_VARARGS|METH_KEYWORDS, "Read bytesize from SSLConnwction"},
        {"ssl_connection_do_handshake", ssl_connection_do_handshake, METH_VARARGS, "Do handshake on SSLConnwction"},
        {"ssl_connection_write", ssl_connection_write, METH_VARARGS, "Write bytes to SSLConnection"},
        {"ssl_connection_close", ssl_connection_close, METH_VARARGS, "Close SSLConnection"},
        {"ssl_connection_closed", ssl_connection_closed, METH_VARARGS, "Check if SSLConnection is closed"},
        {"ssl_connection_h2_support", ssl_connection_h2_support, METH_VARARGS, "Check if SSLConnection supports h2"},
        {"ssl_connection_leaf_cert", ssl_connection_leaf_cert, METH_VARARGS, "Check if SSLConnection supports h2"},
        {"ssl_connection_set_timeout", ssl_connection_set_timeout, METH_VARARGS, "Check if SSLConnection supports h2"},

        // ssl_context
        {"new_ssl_context_from_bytes", new_ssl_context_from_bytes, METH_VARARGS, "Create a new SSLContext"},
        {"ssl_context_close", ssl_connection_close, METH_VARARGS, "Close SSLContext"},
        {"new_ssl_context", new_ssl_context, METH_VARARGS, "Create a new SSLContext"},

        //go_handle
        {"close_go_handle", close_go_handle, METH_VARARGS, "Close object associated with handle on go side"},

        {NULL, NULL, 0, NULL},
    };



    static int pyutls_modexec(PyObject * m){
        if (PyUTLS_Exc == NULL){
            PyUTLS_Exc = PyErr_NewException("pyutls.uTLSError", PyExc_IOError, NULL);
        }
        Py_INCREF(PyUTLS_Exc);
        if (PyModule_AddObject(m, "error", PyUTLS_Exc) < 0){
            Py_DECREF(PyUTLS_Exc);
            return -1;
        }


        return 0;
    }


    static PyModuleDef_Slot pyutls_slot[] = {
        {Py_mod_exec, (void*)pyutls_modexec},
        {0, NULL},
    };


    static struct PyModuleDef pyutls_module = {
        PyModuleDef_HEAD_INIT,
        .m_name = "_pyutls",
        .m_doc = NULL,
        .m_size = 0,
        .m_methods = functions,
        .m_slots = pyutls_slot,
    };
    // 


    PyMODINIT_FUNC PyInit_pyutls(void)
    {
        return PyModuleDef_Init(&pyutls_module);
    }

    //
    ssize_t duplicate_fd(ssize_t fd)
    {
        // Duplicate the file descriptor
        int new_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (new_fd == -1)
        {
            PyErr_SetFromErrno(PyExc_IOError);
            return 0;
        }

        return new_fd;
    }

    PyObject *ssl_connection_return(ssize_t handle, ssize_t fd)
    {
        return Py_BuildValue("(ii)", handle, fd);
    }
}
