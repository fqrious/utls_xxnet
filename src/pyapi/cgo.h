#ifndef cgo_h
#define cgo_h
#ifdef __cplusplus
extern "C" {
#endif
// #include <Python.h>
#include <stdbool.h>


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



#ifdef __cplusplus
}
#endif

#endif