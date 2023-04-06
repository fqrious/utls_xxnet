#ifndef cgo_h
#define cgo_h
#ifdef __cplusplus
extern "C" {
#endif
#include <Python.h>

PyObject* pymodule_def();
// PyObject* PyInit_ss(void);


#ifdef __cplusplus
}
#endif

#endif