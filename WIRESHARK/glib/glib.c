/*
 * Copyright © 2011 Canonical Limited
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the licence, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Ryan Lortie <desrt@desrt.ca>
 */

#include "config.h"

#include <glib.h>


#ifdef _WIN32

#include <windows.h>

#include "gwin32.h"
#endif

#include <cfile.h>
#include <gmodule.h>

extern "C"
{
capture_file cfile;
struct stnode_t *df_lval = NULL;

}

GDir* g_dir_new_from_dirp(gpointer dirp){return NULL;}
GDir* g_dir_open_with_errno(const gchar *path,guint flags){return NULL;}
GDir* g_dir_open(const gchar *path, guint flags,GError **error){return NULL;}
const gchar* g_dir_read_name(GDir *dir){return NULL;}
void g_dir_rewind (GDir *dir){}
void g_dir_close(GDir *dir){}

//gchar *g_filename_display_basename(const gchar *filename){return NULL;}
//void g_get_current_time(GTimeVal *result){}


void df_scanner_text(const char *text){}
void    df_scanner_cleanup(void){}
int     df_lex(void){return 0;}


extern "C"
{
void print_ps_preamble(struct _iobuf *){}
void print_ps_finale(struct _iobuf *){}


/* Constructor/Destructor prototypes for Lemon Parser */
void *DfilterAlloc(void* (*)(gsize)){return NULL;}

void DfilterFree(void*, void (*)(void *)){}
void Dfilter(void*, int, stnode_t*, struct dfwork_t*){}

gboolean wtap_dump_file_write(wtap_dumper *wdh, const void *buf, size_t bufsize, int *err){return 0;}
gboolean wtap_dump_close(wtap_dumper *wdh, int *err){return 0;}
gboolean wtap_fdreopen(wtap *wth, const char *filename, int *err){return 0;}
wtap * wtap_open_offline(const char *filename, unsigned int type, int *err, char **err_info, gboolean do_random){return 0;}
}



const gchar * g_regex_get_pattern(const GRegex *regex){return NULL;}
gchar **g_regex_split_simple(const gchar *pattern,const gchar *string, GRegexCompileFlags compile_options, GRegexMatchFlags  match_options){return NULL;}
gboolean g_regex_match_full(const GRegex *regex,const gchar *string,gssize string_len,gint start_position,GRegexMatchFlags match_options,GMatchInfo **match_info,GError **error){return NULL;}
GRegex* g_regex_new (const gchar *pattern, GRegexCompileFlags  compile_options, GRegexMatchFlags  match_options,GError **error){return NULL;}
void g_regex_unref (GRegex *regex){}

extern "C"
{
gboolean initialize_color(struct color_t *color, guint16 red, guint16 green, guint16 blue)
{
 //
 return 0;
}

void color_filter_add_cb(struct color_filter_t *colorf, gpointer user_data){}

gchar* g_module_build_path(const gchar *directory, const gchar*module_name){return NULL;}
GModule*    g_module_open_utf8 (const gchar *file_name, GModuleFlags flags){return NULL;}
}