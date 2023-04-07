#ifndef cgo_h
#define cgo_h
#ifdef __cplusplus
extern "C" {
#endif
#include <Python.h>

PyObject* pymodule_def();
// PyObject* PyInit_ss(void);
static inline void INCREF(PyObject* obj){
	Py_INCREF(obj);
}

static inline void DECREF(PyObject* obj){
	Py_DECREF(obj);
}

#ifdef __cplusplus
}
#endif

#endif