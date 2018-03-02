
#ifndef GLIB_H
#define GLIB_H

//#define g_assert(expr)
//#define g_assert_not_reached()

//#define HAVE_GOOD_PRINTF

#define GLIB_LOCALE_DIR  5


#define __GLIB_H_INSIDE__

#include <glib/galloca.h>
#include <glib/garray.h>
//#include <glib/gasyncqueue.h>
#include <glib/gatomic.h>
#include <glib/gbacktrace.h>
//#include <glib/gbase64.h>
//#include <glib/gbitlock.h>
//#include <glib/gbookmarkfile.h>
#include <glib/gbytes.h>
#include <glib/gcharset.h>
//#include <glib/gchecksum.h>
#include <glib/gconvert.h>
//#include <glib/gdataset.h>
//#include <glib/gdate.h>
//#include <glib/gdatetime.h>
//#include <glib/gdir.h>
#include <glib/genviron.h>
#include <glib/gerror.h>
#include <glib/gfileutils.h>
//#include <glib/ggettext.h>
#include <glib/ghash.h>
//#include <glib/ghmac.h>
#include <glib/ghook.h>
//#include <glib/ghostutils.h>
#include <glib/giochannel.h>
//#include <glib/gkeyfile.h>
#include <glib/glist.h>
#include <glib/gmacros.h>
#include <glib/gmain.h>
//#include <glib/gmappedfile.h>
//#include <glib/gmarkup.h>
#include <glib/gmem.h>
#include <glib/gmessages.h>
#include <glib/gnode.h>
//#include <glib/goption.h>
#include <glib/gpattern.h>
#include <glib/gpoll.h>
//#include <glib/gprimes.h>
#include <glib/gqsort.h>
#include <glib/gquark.h>
#include <glib/gqueue.h>
#include <glib/grand.h>
//#include <glib/gregex.h>
//#include <glib/gscanner.h>
//#include <glib/gsequence.h>
//#include <glib/gshell.h>
#include <glib/gslice.h>
#include <glib/gslist.h>
//#include <glib/gspawn.h>
#include <glib/gstrfuncs.h>
#include <glib/gstring.h>
//#include <glib/gstringchunk.h>
#include <glib/gtestutils.h>
#include <glib/gthread.h>
//#include <glib/gthreadpool.h>
#include <glib/gtimer.h>
//#include <glib/gtimezone.h>
#include <glib/gtrashstack.h>
#include <glib/gtree.h>
#include <glib/gtypes.h>
#include <glib/gunicode.h>
//#include <glib/gurifuncs.h>
#include <glib/gutils.h>
//#include <glib/gvarianttype.h>
//#include <glib/gvariant.h>
//#include <glib/gversion.h>
#include <glib/gversionmacros.h>
#ifdef G_PLATFORM_WIN32
#include <glib/gwin32.h>
#endif

//#define	g_error(str, ...)

//#define g_realloc   realloc
//#define g_malloc    malloc


/*#include <glib/gtypes.h>
#include <stdarg.h>

#include <glib/glist.h>
#include <glib/gslist.h>
#include <glib/gtree.h>
#include <glib/garray.h>
#include <glib/ghash.h>
#include <glib/gstring.h>
#include <glib/gstrfuncs.h>
#include <glib/gutils.h>
#include <glib/gmessages.h>
#include <glib/gmem.h>
#include <glib/gslice.h>
#include <glib/gunicode.h>
#include <glib/gtestutils.h>
#include <glib/gerror.h>
#include <glib/gquark.h>
#include <glib/gconvert.h>
#include <glib/gcharset.h>
#include <glib/genviron.h>   */

/*#define G_GNUC_PRINTF(...)
#define G_GNUC_MALLOC 
#define G_GNUC_NULL_TERMINATED
#define G_GNUC_NORETURN
#define G_GNUC_WARN_UNUSED_RESULT */

/*#define G_MAXULONG 0xFFFFFFFF
#define G_MAXSIZE G_MAXULONG

#define G_MAXLONG  0x7FFFFFFF
#define G_MAXSSIZE G_MAXLONG

#define G_MAXUINT32 0xFFFFFFFF

#define G_MAXINT 0x7FFFFFFF
#define G_MININT 0


#define G_MAXINT16 0x7FFF */


//typedef guint16 gunichar2;
//typedef guint32 gunichar;

//#define TRUE 1
//#define FALSE 0


#define WS_DIR				GDir
#define WS_DIRENT			const char
#define ws_dir_open			g_dir_open
#define ws_dir_read_name		g_dir_read_name
#define ws_dir_get_name(dirent)		dirent
//#define ws_dir_rewind			g_dir_rewind
#define ws_dir_close			g_dir_close


typedef enum
{
  G_REGEX_MATCH_ANCHORED         = 1 << 4,
  G_REGEX_MATCH_NOTBOL           = 1 << 7,
  G_REGEX_MATCH_NOTEOL           = 1 << 8,
  G_REGEX_MATCH_NOTEMPTY         = 1 << 10,
  G_REGEX_MATCH_PARTIAL          = 1 << 15,
  G_REGEX_MATCH_NEWLINE_CR       = 1 << 20,
  G_REGEX_MATCH_NEWLINE_LF       = 1 << 21,
  G_REGEX_MATCH_NEWLINE_CRLF     = G_REGEX_MATCH_NEWLINE_CR | G_REGEX_MATCH_NEWLINE_LF,
  G_REGEX_MATCH_NEWLINE_ANY      = 1 << 22,
  G_REGEX_MATCH_NEWLINE_ANYCRLF  = G_REGEX_MATCH_NEWLINE_CR | G_REGEX_MATCH_NEWLINE_ANY,
  G_REGEX_MATCH_BSR_ANYCRLF      = 1 << 23,
  G_REGEX_MATCH_BSR_ANY          = 1 << 24,
  G_REGEX_MATCH_PARTIAL_SOFT     = G_REGEX_MATCH_PARTIAL,
  G_REGEX_MATCH_PARTIAL_HARD     = 1 << 27,
  G_REGEX_MATCH_NOTEMPTY_ATSTART = 1 << 28
} GRegexMatchFlags;


typedef enum
{
  G_REGEX_CASELESS          = 1 << 0,
  G_REGEX_MULTILINE         = 1 << 1,
  G_REGEX_DOTALL            = 1 << 2,
  G_REGEX_EXTENDED          = 1 << 3,
  G_REGEX_ANCHORED          = 1 << 4,
  G_REGEX_DOLLAR_ENDONLY    = 1 << 5,
  G_REGEX_UNGREEDY          = 1 << 9,
  G_REGEX_RAW               = 1 << 11,
  G_REGEX_NO_AUTO_CAPTURE   = 1 << 12,
  G_REGEX_OPTIMIZE          = 1 << 13,
  G_REGEX_FIRSTLINE         = 1 << 18,
  G_REGEX_DUPNAMES          = 1 << 19,
  G_REGEX_NEWLINE_CR        = 1 << 20,
  G_REGEX_NEWLINE_LF        = 1 << 21,
  G_REGEX_NEWLINE_CRLF      = G_REGEX_NEWLINE_CR | G_REGEX_NEWLINE_LF,
  G_REGEX_NEWLINE_ANYCRLF   = G_REGEX_NEWLINE_CR | 1 << 22,
  G_REGEX_BSR_ANYCRLF       = 1 << 23,
  G_REGEX_JAVASCRIPT_COMPAT = 1 << 25
} GRegexCompileFlags;


/*typedef char   gchar;
typedef short  gshort;
typedef long   glong;
typedef int    gint;
typedef gint   gboolean;

typedef signed char		gint8;
typedef signed short	gint16;
typedef signed int		gint32;
typedef signed __int64	gint64;

typedef unsigned char		guchar;
typedef unsigned short		gushort;
typedef unsigned long		gulong;
typedef unsigned int		guint;
typedef unsigned char       guint8;
typedef unsigned short      guint16;
typedef unsigned int        guint32;
typedef unsigned __int64	guint64;

typedef float	gfloat;
typedef double	gdouble;

typedef guint32 gunichar;
typedef guint16 gunichar2;


typedef unsigned long gsize;
typedef signed long gssize;
typedef void *gpointer;
typedef const void *gconstpointer;  */

/*typedef gint            (*GCompareFunc)         (gconstpointer  a, gconstpointer  b);
typedef gboolean        (*GEqualFunc)           (gconstpointer  a, gconstpointer  b);
typedef guint           (*GHashFunc)            (gconstpointer  key);
typedef void            (*GDestroyNotify)       (gpointer       data);
typedef void            (*GFunc)                (gpointer       data, gpointer       user_data);
typedef void            (*GHFunc)               (gpointer       key,
                                                 gpointer       value,
                                                 gpointer       user_data);     */


/*typedef enum
{
  G_MODULE_BIND_LAZY	= 1 << 0,
  G_MODULE_BIND_LOCAL	= 1 << 1,
  G_MODULE_BIND_MASK	= 0x03
} GModuleFlags;  */


#define G_DIR_SEPARATOR '\\'
#define G_DIR_SEPARATOR_S "\\"
#define G_IS_DIR_SEPARATOR(c) ((c) == G_DIR_SEPARATOR || (c) == '/')
#define G_SEARCHPATH_SEPARATOR ';'
#define G_SEARCHPATH_SEPARATOR_S ";"
//-------------
//typedef void *GByteArray;    // Reimplement
typedef void *GRegex;
//typedef void *GSList;        // Reimplement
//typedef void *GHashTable;

/*typedef struct _GList GList;
struct _GList
{
  gpointer data;
  GList *next;
  GList *prev;
};

typedef struct _GSList GSList;
struct _GSList
{
  gpointer data;
  GSList *next;
};

typedef struct _GString         GString;
struct _GString
{
  gchar  *str;
  gsize len;
  gsize allocated_len;
};

typedef struct _GTree  GTree;




typedef struct _GBytes      GBytes;
typedef struct _GArray		GArray;
typedef struct _GByteArray	GByteArray;
typedef struct _GPtrArray	GPtrArray;

struct _GArray
{
  gchar *data;
  guint len;
};

struct _GByteArray
{
  guint8 *data;
  guint	  len;
};

struct _GPtrArray
{
  gpointer *pdata;
  guint	    len;
};
    
#define g_array_index(a,t,i)      (((t*) (void *) (a)->data) [(i)])
         */

typedef struct _GDir GDir;


/*#define g_malloc  malloc

#define             g_new0(struct_type, n_structs) ((struct_type*) calloc (n_structs, sizeof (struct_type)))
#define             g_new(struct_type, n_structs) ((struct_type*) malloc (sizeof (struct_type) * n_structs))
#define             g_slice_new(type) ((type*) malloc (sizeof (type)))      // ((type*) new (sizeof (type)))
#define             g_slice_new0(type) ((type*) calloc (1, sizeof (type)))
#define             g_slice_free(type, mem) free(mem)         // delete(mem)
*/
//-------------



//void g_free (gpointer mem);

/*
GArray* g_array_sized_new(gboolean zero_terminated, gboolean clear_, guint element_size, guint reserved_size);

GHashTable* g_hash_table_new_full          (GHashFunc       hash_func,
                                            GEqualFunc      key_equal_func,
                                            GDestroyNotify  key_destroy_func,
                                            GDestroyNotify  value_destroy_func);

gboolean    g_hash_table_lookup_extended   (GHashTable     *hash_table,
                                            gconstpointer   lookup_key,
                                            gpointer       *orig_key,
                                            gpointer       *value);


guint g_direct_hash  (gconstpointer v);
gint  g_direct_equal (gconstpointer v, gconstpointer v2);

gboolean g_str_equal    (gconstpointer  v1, gconstpointer  v2);
guint    g_str_hash     (gconstpointer  v);

gint  g_int_equal (gconstpointer   v, gconstpointer   v2);
guint g_int_hash  (gconstpointer   v);


*/


typedef struct _GMatchInfo	GMatchInfo;

//typedef void* GError;

gchar                 g_ascii_tolower  (gchar        c);
gchar                 g_ascii_toupper  (gchar        c);


gchar *g_path_get_dirname  (const gchar *file_name);

/* Check if a file name is an absolute path */
gboolean g_path_is_absolute	(const gchar *file_name);
/* In case of absolute paths, skip the root part */
//gchar*  g_path_skip_root	(gchar       *file_name);


GDir* g_dir_new_from_dirp(gpointer dirp);
GDir* g_dir_open_with_errno(const gchar *path,guint flags);
GDir* g_dir_open(const gchar *path, guint flags,GError **error);
const gchar* g_dir_read_name(GDir *dir);
void g_dir_rewind (GDir *dir);
void g_dir_close(GDir *dir);

 //gchar *g_filename_display_basename(const gchar *filename);
//void g_get_current_time(GTimeVal *result);


 //gchar*          g_win32_error_message (gint error);



void glib_init_static(void);
void glib_cleanup_static(void);




gchar **g_regex_split_simple(const gchar *pattern,const gchar *string, GRegexCompileFlags compile_options, GRegexMatchFlags  match_options);
const gchar * g_regex_get_pattern(const GRegex *regex);
gboolean g_regex_match_full(const GRegex *regex,const gchar *string,gssize string_len,gint start_position,GRegexMatchFlags match_options,GMatchInfo **match_info,GError **error);
GRegex* g_regex_new (const gchar *pattern, GRegexCompileFlags  compile_options, GRegexMatchFlags  match_options,GError **error);
void g_regex_unref (GRegex *regex);

#endif