/* main.c

   See the README file for usage instructions, and INSTALL
   for help on installing

*/


/*
  Squirm - A Redirector for Squid

  Maintained by Chris Foote, chris@senet.com.au
  Copyright (C) 1998 Chris Foote & Wayne Piekarski

  If you find it useful, please let me know by sending
  email to chris@senet.com.au - Ta!

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

  Please see the file GPL in this directory for full copyright
  information.
*/


/* #include"paths.h" */
#include"squirm.h"
#include"log.h"

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/signal.h>
#include<ctype.h>
#include"lists.h"

int dodo_mode = 0;
int first_run = 1;
int sig_hup = 0;
int interactive = 0;
char *alternate_config = NULL;

/* linux signal handling is a bit wierd -
   including <signal.h> gives a compiler warning!
   so we give the prototype here:
   */
/* void signal(int, void(*)); */

/*  exit values:
    0 = normal
    1 = file errors
    2 = abnormal errors
    3 = malloc problems

    Under normal conditions, Squirm will never abort (you don't
    want your Squid to suddenly die if you've put an invalid
    regex into your config file, or renamed the config file!
    Under these abnormal conditions, squirm will run in dodo_mode
    where stdin is echoed to stdout!

    If you've entered an invalid regex expression that regcomp()
    doesn't like, or perhaps an invalid network number, check it
    out in the ERROR_LOG.

    It should never ever abort under normal circumstances - even
    if it can't allocate memory (which shouldn't happen, and Squid
    would be running like a dog under low memory conditions anyway)
    dodo_mode will be set and it will keep running :-)

    If squirm is running in dodo_mode, sending the redirector processes
    a HUP signal will cause squirm to try reading it's config files
    and building linked lists again.
*/

char *LOG_MATCH="../logs/squirm.match";
char *LOG_FAIL ="../logs/squirm.fail";
char *LOG_ERROR="../logs/squirm.error";
char *LOG_WHERE="../logs/squirm.where";
char *LOG_DEBUG="../logs/squirm.debug";
char *LOG_INFO ="../logs/squirm.info";

char *LOCAL_ADDRESSES="../etc/squirm.local";
char *REDIRECT_PATTERNS="../etc/squirm";

int main(int argc, char **argv)
{
  char buff[MAX_BUFF];
  char *redirect_url;
  struct IN_BUFF in_buff;
  int finished = 0;
  int buff_status = 0;


  /* go into interactive mode if we're run as root */

    /* ORIGINAL VERSION */
    /* if((int)getuid() == 0) {
    interactive = 1;
    fprintf(stderr, "Squirm running as UID 0: writing logs to stderr\n");*/

    /* OS2 PORT */
    char *baseDir=getenv("SQUID_DIRECTORY");
    char *flagFileName;
    FILE *flagInteractive;
    /* if we can't locate the SQUID_DIRECTORY environment variable, we use relative paths
       defined in paths.h */

    if (baseDir!=NULL)
       {
       int i;
       for (i=0; i< strlen(baseDir); i++)
         if (baseDir[i]=='\\') baseDir[i]='/';

       LOG_MATCH=(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen(LOG_MATCH))-2);
       strcpy(LOG_MATCH,baseDir);
       strcat(LOG_MATCH,"/logs/squirm.match");

       LOG_FAIL=(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen(LOG_FAIL))-2);
       strcpy(LOG_FAIL,baseDir);
       strcat(LOG_FAIL,"/logs/squirm.fail");

       LOG_ERROR=(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen(LOG_ERROR))-2);
       strcpy(LOG_ERROR,baseDir);
       strcat(LOG_ERROR,"/logs/squirm.error");

       LOG_WHERE=(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen(LOG_WHERE))-2);
       strcpy(LOG_WHERE,baseDir);
       strcat(LOG_WHERE,"/logs/squirm.where");

       LOG_DEBUG=(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen(LOG_DEBUG))-2);
       strcpy(LOG_DEBUG,baseDir);
       strcat(LOG_DEBUG,"/logs/squirm.debug");

       LOG_INFO =(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen(LOG_INFO ))-2);
       strcpy(LOG_INFO ,baseDir);
       strcat(LOG_INFO ,"/logs/squirm.info");

       LOCAL_ADDRESSES=(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen(LOCAL_ADDRESSES))-2);
       strcpy(LOCAL_ADDRESSES ,baseDir);
       strcat(LOCAL_ADDRESSES ,"/etc/squirm.local");

       REDIRECT_PATTERNS=(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen(REDIRECT_PATTERNS))-2);
       strcpy(REDIRECT_PATTERNS ,baseDir);
       strcat(REDIRECT_PATTERNS ,"/etc/squirm.patterns");
       }

     else
       {
       baseDir="..";
       }


    flagFileName=(char*)malloc(sizeof(char)*(strlen(baseDir)+strlen("/etc/squirm.interactive")));
    strcpy(flagFileName,baseDir);
    flagFileName=strcat(flagFileName,"/etc/squirm.interactive");

    flagInteractive=flagInteractive=fopen(flagFileName,"rb");
    if (flagInteractive!=NULL)
      {
      fclose(flagInteractive);
      interactive = 1;
      fprintf(stderr, "etc/squirm.interactive flag file found: writing logs to stderr\n");
      }

  /* check for alternate config file given as first argument */
  if(argc == 2)
    alternate_config = argv[1];

  if(argc > 2) {
    fprintf(stderr, "squirm:invalid arguments\n");
    fprintf(stderr, "Usage: %s [alternate-squirm-patterns-file]\n", argv[0]);
    exit(1);
  }


  /*********************************
    main program loop, executed
    forever more unless terminated
    by a kill signal or EOF on stdin
    ********************************/
  while(! finished) {

    /* install the signal handler for re-reading config
       files and freeing up linked lists     */
    signal(SIGHUP, squirm_HUP);
    sig_hup = 0;

    dodo_mode = 0;

    /* free old lists if we've been HUPped */
    if(! first_run) {
      log(LOG_INFO, "Freeing up old linked lists\n");
      free_ip_list();
      free_plist();
    }

    /*********************
      read config files
      into linked lists
      ********************/
    init_ip_list();
    load_local_addresses();

    init_pattern_list();
    load_patterns();


    if(dodo_mode)
      log(LOG_ERROR, "Invalid condition - continuing in DODO mode\n");

    log(LOG_INFO, "Squirm (PID %d) started\n", (int)getpid());


    while(!sig_hup && (fgets(buff, MAX_BUFF, stdin) != NULL)){

      /* if configs are completely invalid or some other
         exception occurs where we want the redirector to
         continue operation (so that Squid still works!),
         we simply echo stdin to stdout - i.e. "dodo mode" :-) */
      if(dodo_mode) {
        puts("");
        fflush(stdout);
        continue;
      }


      /* separate the four fields
        from the single input line
        of stdin */

      buff_status = load_in_buff(buff, &in_buff);


      /* if four fields couldn't be separated, or the
         converted values aren't appropriate, then
         just echo back the line from stdin */

      if(buff_status == 1) {
        puts("");
        fflush(stdout);
        continue;
      }

      /* check dodo_mode again */
      if(dodo_mode) {
        puts("");
        fflush(stdout);
        log(LOG_ERROR, "Invalid condition - continuing in DODO mode\n");
        continue;
      }



      /* now that we have a valid source address,
         we can compare the URL */

      if((redirect_url = pattern_compare(in_buff.url)) == NULL) {

        /* no replacement for the URL was found */
        puts("");
        fflush(stdout);
        continue;

      } else {

        /* redirect_url contains the replacement URL */
        printf("%s %s %s %s\n", redirect_url, in_buff.src_address,
               in_buff.ident, in_buff.method);
        fflush(stdout);
        log(LOG_MATCH, "%s:%s\n", in_buff.url, redirect_url);
        free(redirect_url);
        continue;
      }

    }

    if(! sig_hup)
      finished = 1;

  } /* end while(1) */

  free_ip_list();
  free_plist();

  return 0;
}











