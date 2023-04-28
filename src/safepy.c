
// extern "C"
// {
#include "safepy.h"
// #include "cgo.h"

    // extern PyObject* PyUTLS_Exc;

    void safepy_Bytes_AsStringAndSize(PyObject* bytes, char **bufptr, Py_ssize_t* sizeptr){
        SAFEPY_BEGIN
        PyBytes_AsStringAndSize(bytes, bufptr, sizeptr);
        SAFEPY_END
    }

    PyObject * safepy_Bytes_FromStringAndSize(char * val, Py_ssize_t len){
        SAFEPY_BEGIN
        PyObject* out = PyBytes_FromStringAndSize(val, len);
        SAFEPY_END
        return out;
    }

    void safepy_set_error(char* err){
        SAFEPY_BEGIN
        PyErr_SetString(PyExc_RuntimeError, err);
        SAFEPY_END
    }

     //
    ssize_t duplicate_fd(ssize_t fd)
    {
        // Duplicate the file descriptor
        // #ifdef _MSC_VER || __MINGW32__
        #ifndef F_DUPFD_CLOEXEC
        return fd;
        #else
        int new_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (new_fd == -1)
        {
            PyErr_SetFromErrno(PyExc_IOError);
            return 0;
        }

        return new_fd;
        #endif
    }

    PyObject *ssl_connection_return(ssize_t handle, ssize_t fd)
    {
        // return Py_BuildValue("(ii)", handle, fd);
        SAFEPY_BEGIN
        PyObject *out = Py_BuildValue("(ii)", handle, fd);
        SAFEPY_END
        return out;
    }
// }
