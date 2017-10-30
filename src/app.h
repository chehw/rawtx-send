#ifndef _APP_H_
#define _APP_H_

#include "compatible.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif



#define APP_LOG_HEADER "%s(%d)::%s(): "
#define CRLF "\n"
#ifdef _CONSOLE_OUTPUT
#define log_printf(fmt, ...) do { \
		fprintf(stdout, APP_LOG_HEADER fmt CRLF, \
			__FILE__, __LINE__, __FUNCTION__,\
			##__VA_ARGS__); \
	} while(0)
	
#define debug_printf(fmt, ...) do { \
		fprintf(stderr, APP_LOG_HEADER fmt CRLF, \
			__FILE__, __LINE__, __FUNCTION__,\
			##__VA_ARGS__); \
	} while(0)
#else
#define log_printf(fmt, ...) do { } while(0)	
#define debug_printf(fmt, ...) do { } while(0)
#endif

typedef struct app_ctx app_ctx_t;
typedef int (* app_init_proc)(app_ctx_t * app, int * p_argc, char *** p_argv);
typedef int (* app_main_proc)(app_ctx_t * app);
typedef void (* app_cleanup_proc)(app_ctx_t * app);

struct app_vtbl;
struct app_ctx
{
	/* virtual functions table */
	struct app_vtbl * vtbl;
	
	/* member functions */
	app_init_proc init;
	app_main_proc main;
	app_cleanup_proc cleanup;	
	//~ int (* init)(app_ctx_t * app, int * p_argc, char *** p_argv);
	//~ int (* main)(app_ctx_t * app);
	//~ void (*cleanup)(app_ctx_t * app);
	void * user_data;
	
	/* global settings */
	uint32_t network_magic;
	uint32_t protocol_version;
	int proxy_type;
	const char * proxy_settings;
};

app_ctx_t * app_new(app_ctx_t * app,
	app_init_proc init_proc,
	app_main_proc main_proc,
	app_cleanup_proc cleanup_proc,
	void * user_data
);
void app_free(app_ctx_t * app);

#ifdef __cplusplus
}
#endif
#endif
