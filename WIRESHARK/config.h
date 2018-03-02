#ifndef SYMBOL_EXPORT_H
#define SYMBOL_EXPORT_H


#define NULL 0
#define TRUE 1
#define FALSE 0



#define VERSION "1.3v"
#define PACKAGE "VFMon"

#define YY_NO_UNISTD_H
//#define HAVE_INET_ATON
// #pragma warning (disable:4018)
//#define ENOENT 1  // !!!!!!!!!!!!!!

//#define WS_MSVC_NORETURN	__declspec(noreturn)

#define popen			_popen
#define pclose			_pclose

/* Define if you have the floorl function. */
#define HAVE_FLOORL 1
/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1
/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1
/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1
/* Define if you have the <windows.h> header file.  */
#define HAVE_WINDOWS_H 1
/* Define if you have the <winsock2.h> header file.  */
#define HAVE_WINSOCK2_H 1

#define NEED_INET_V6DEFS_H  1

//#define S_IFMT 0xFF

//#define S_IFDIR 1
//#define S_IFREG 2

//#define _S_IFIFO 3


/* Wireshark's marker that a function parameter is unused.  Used to avoid
 * warnings on compilers that support such hints.
 */
#define _U_

/* Disable Code Analysis warnings that result in too many false positives. */
/* http://msdn.microsoft.com/en-US/library/zyhb0b82.aspx */
#if _MSC_VER >= 1400
#pragma warning ( disable : 6011 )
#endif

#if !defined(QT_VERSION) || !defined(_SSIZE_T_DEFINED)
typedef int ssize_t;
#endif

/* to use define _ws_mempbrk_sse42 if available (checked with cpuinfo)  */
//#define HAVE_SSE4_2 1


#endif