
extern "C"
{
#include "safepy.h"
#include "cgo.h"

    // extern PyObject* PyUTLS_Exc;

    void safepy_Bytes_AsStringAndSize(PyObject* bytes, char **bufptr, Py_ssize_t* sizeptr){
        SAFEPY_BEGIN
        PyBytes_AsStringAndSize(bytes, bufptr, sizeptr);
        SAFEPY_END
    }

    PyObject * safepy_Bytes_FromStringAndSize(char * val, Py_ssize_t len){
        SAFEPY_BEGIN
        auto out = PyBytes_FromStringAndSize(val, len);
        SAFEPY_END
        return out;
    }
}
