/*
 * app.c
 * 
 * Copyright 2017 chehw <htc.chehw@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */


#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "app.h"

#include <limits.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <poll.h>
#include <unistd.h>
#include <assert.h>

#include "shell/shell.h"


static int app_init(app_ctx_t * app, int * p_argc, char *** p_argv);
static int app_main(app_ctx_t * app);
static void app_cleanup(app_ctx_t * app);

struct app_vtbl
{
	void (* construct)(app_ctx_t * app);
	void (* cleanup)(app_ctx_t * app);
	long (* ref)(app_ctx_t * app);
	long (* unref)(app_ctx_t * app);
	int  (* query_interface)(app_ctx_t * app, const char * name, void * pp_interface);
};


static struct app_vtbl s_vtbl[1] = {{
	//~ .construct = default_app_construt,
	//~ .cleanup = default_cleanup,
	//~ .ref = default_ref,
	//~ .unref = default_unref,
	//~ .query_interface = default_query_interface,
}};


enum PROXY_TYPE
{
	proxy_none,
	proxy_http,
	proxy_https,
	proxy_socks5,
	proxy_tor,
};

app_ctx_t * app_new(app_ctx_t * app,
	app_init_proc init_proc,
	app_main_proc main_proc,
	app_cleanup_proc cleanup_proc,
	void * user_data
)
{
	if(NULL == app) 
	{
		app = (app_ctx_t *)calloc(1, sizeof(app_ctx_t));
		assert(NULL != app);		
	}	
	if(NULL == init_proc) init_proc = app_init;
	if(NULL == main_proc) main_proc = app_main;
	if(NULL == cleanup_proc) cleanup_proc = app_cleanup;
	
	if(NULL == app->vtbl) 		app->vtbl = &s_vtbl[0];
	if(NULL == app->init) 		app->init = init_proc;
	if(NULL == app->main) 		app->main = main_proc;
	if(NULL == app->cleanup) 	app->cleanup = cleanup_proc;
	if(NULL == app->user_data) 	app->user_data = user_data;	
	return app;
}
void app_free(app_ctx_t * app)
{
	if(app && app->cleanup)
	{
		app->cleanup(app);
		app->cleanup = NULL;
	}
}

int app_init(app_ctx_t * app, int * p_argc, char *** p_argv)
{
	return 0;
}
int app_main(app_ctx_t * app)
{
	return 0;
}
void app_cleanup(app_ctx_t * app)
{
	return;
}
