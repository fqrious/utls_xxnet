#ifndef cgo_h
#define cgo_h
#ifdef __cplusplus
extern "C" {
#endif
#include <Python.h>
#include <stdbool.h>

PyObject* pymodule_def();
// PyObject* PyInit_ss(void);
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

struct ssl_connection
{
	size_t handle;
	char* ip_str;
	bool h2_support;
	/* data */
};

struct ssl_context{
	size_t handle;
};

void py_set_error(char* err);



#ifdef __cplusplus
}
#endif

#endif