#include <Python.h>


#define SAFEPY_BEGIN PyGILState_STATE _gstate = PyGILState_Ensure();
#define SAFEPY_END  PyGILState_Release(_gstate);
#define SAFEPY_Return(value) {      \
    if (PyErr_Occurred() == NULL)    \
        return value;                 \
    return NULL;                       \
}
void safepy_Bytes_AsStringAndSize(PyObject* bytes, char **bufptr, Py_ssize_t* sizeptr);
PyObject * safepy_Bytes_FromStringAndSize(char * val, Py_ssize_t len);
void safepy_set_error(char* err);
