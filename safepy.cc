
extern "C"
{
#include "safepy.h"


    void py_set_error(char* err){
        SAFEPY_BEGIN
        PyErr_SetString(PyExc_RuntimeError, err);
        SAFEPY_END
    }

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
