#ifndef _SHELL_H_
#define _SHELL_H_

#include <gtk/gtk.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct shell_param
{
	void * user_data;
	GtkWidget * window;
	GtkWidget * content_area;
	GtkWidget * left_panel;
	GtkWidget * right_panel;
	GtkWidget * logview;
	GtkWidget * statusbar;
}shell_param_t;

shell_param_t * shell_init(shell_param_t * shell, void * user_data);
shell_param_t * shell_init_with_args(shell_param_t * shell, int * p_argc, char *** p_argv, void * user_data);
int shell_init_windows(shell_param_t * shell, int (* init_windows)(shell_param_t * shell, void * user_data));
int shell_run(shell_param_t * shell);
void shell_stop(shell_param_t * shell);
void shell_cleanup(shell_param_t * shell);


#ifdef __cplusplus
}
#endif
#endif
