/*
 * shell.c
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../app.h"

#include "shell.h"
#include "utils.h"


shell_param_t * shell_init(shell_param_t * shell, void * user_data)
{		
	if(NULL == shell) 
	{
		shell = (shell_param_t *)calloc(1, sizeof(shell_param_t));
		assert(NULL != shell);
	}
	
	shell->user_data = user_data;
	return shell;
}

shell_param_t * shell_init_with_args(shell_param_t * shell, int * p_argc, char *** p_argv, void * user_data)
{	
	char * magic = NULL;
	GError * g_err = NULL;
	app_ctx_t * app = (app_ctx_t *)user_data;	
	const GOptionEntry options[] = {
		{"network-magic", 'n', 0, 
			G_OPTION_ARG_STRING, 
			&magic,
			"Network Magic", 
			"magic"},
		{NULL}
	};
	gtk_init_with_args(p_argc, p_argv, "shell init", options, NULL, &g_err);
	if(g_err)
	{
		g_error_free(g_err);
	}
	if(magic)
	{
		log_printf("magic: %s", magic);
		if(strlen(magic) == 8)
		{
			hex2bin(magic, 8, (unsigned char *)&app->network_magic);
		}
		g_free(magic);
	}
	
	
	if(NULL == shell) 
	{
		shell = (shell_param_t *)calloc(1, sizeof(shell_param_t));
		assert(NULL != shell);
	}
	shell->user_data = user_data;
	return shell;
}

int shell_init_windows(shell_param_t * shell, int (* init_windows)(shell_param_t * shell, void * user_data))
{
	if(init_windows) return init_windows(shell, shell->user_data);
	GtkWidget * window;
	GtkWidget * vbox;
	GtkWidget * vpanel;
	GtkWidget * hpanel;
	GtkWidget * scrolled_win;
	GtkWidget * tree;
	GtkWidget * list;
	GtkWidget * statusbar;
	GtkWidget * textview;
	
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(window), 5);
	
	vpanel = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
	hpanel = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
	tree = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), tree);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_widget_set_size_request(scrolled_win, 180, 100);
	gtk_paned_add1(GTK_PANED(hpanel), scrolled_win);
	
	list = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), list);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_widget_set_size_request(scrolled_win, 180, 100);
	gtk_paned_add2(GTK_PANED(hpanel), scrolled_win);
	
		
	textview = gtk_text_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_win), textview);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_widget_set_size_request(scrolled_win, 480, 100);
	
	gtk_paned_add1(GTK_PANED(vpanel), hpanel);
	gtk_paned_add2(GTK_PANED(vpanel), scrolled_win);
	
	statusbar = gtk_statusbar_new();
	
	gtk_box_pack_start(GTK_BOX(vbox), vpanel, TRUE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), statusbar, FALSE, TRUE, 0);
	
	gtk_widget_show_all(window);	
	g_signal_connect_swapped(window, "destroy", G_CALLBACK(gtk_main_quit), shell);
	return 0;
}
int shell_run(shell_param_t * shell)
{
	gtk_main();
	return 0;
}

void shell_stop(shell_param_t * shell)
{
	gtk_main_quit();
	return;
}

void shell_cleanup(shell_param_t * shell)
{
	return;
}
