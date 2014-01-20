#ifndef PATHS_H

#define PATHS_H

/* paths.h
   part of Squirm

   Copyright (C) 1998 Chris Foote & Wayne Piekarski
*/


/* Debugging */
/* #define DEBUG 1 */

/*************  Log File Locations (must be writable by **********/
/*************  the user given in the squid.conf file   **********/
/* #define LOG_MATCH "../logs/squirm.match" */
/* #define LOG_FAIL  "../logs/squirm.fail"  */
/* #define LOG_ERROR "../logs/squirm.error" */
/* #define LOG_WHERE "../logs/squirm.where" */
/* #define LOG_DEBUG "../logs/squirm.debug" */
/* #define LOG_INFO  "../logs/squirm.info"  */

/*************  Configuration file locations  ***********/
/* #define LOCAL_ADDRESSES   "../etc/squirm.local" */
/* #define REDIRECT_PATTERNS "../etc/squirm.patterns" */

/* OS/2 PORT: we need to use variables rather than #define, since the OS/2 version may be installed
   in any directory */

extern char *LOG_MATCH;
extern char *LOG_FAIL ;
extern char *LOG_ERROR;
extern char *LOG_WHERE;
extern char *LOG_DEBUG;
extern char *LOG_INFO ;

extern char *LOCAL_ADDRESSES;
extern char *REDIRECT_PATTERNS;

#endif
