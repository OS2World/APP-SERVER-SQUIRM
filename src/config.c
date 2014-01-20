/* config.c */

/*
  Squirm - A Redirector for Squid
  
  Maintained by Chris Foote, chris@senet.com.au
  Copyright (C) 1998 Chris Foote & Wayne Piekarski
  
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

#include"paths.h"
#include"squirm.h"
#include"log.h"

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>

extern int dodo_mode;            /* from main.c */
extern char *alternate_config;   /* from main.c */



/* load the squirm.local 
   addresses into a linked list */

void load_local_addresses(void)
{
  FILE *fp;
  char buff[MAX_BUFF];
  struct IP src_address;
  
  fp = fopen(LOCAL_ADDRESSES, "rt");
  
  if(fp == NULL) {
    log(LOG_ERROR, "unable to open local addresses file [%s]\n", 
	LOCAL_ADDRESSES);
    dodo_mode = 1;
    return;
  }

  log(LOG_INFO, "Loading IP List\n");
  
  while(!dodo_mode && (fgets(buff, MAX_BUFF, fp) != NULL)) {
    
    /* skip blank lines and comments */
    if((strncmp(buff, "#", 1) == 0) || (strncmp(buff, "\n", 1) == 0))
      continue;
    
    if(strlen(buff) != 1) {
      /* chop newline */
      buff[strlen(buff) - 1] = '\0';
      if(get_ip(buff, &src_address)) {
	log(LOG_ERROR, "Invalid IP network [%s] in config file\n", buff);
	/* there's no need to set 'dodo_mode' here because we can
	   continue quite happily. */
      } else {
	add_to_ip_list(src_address);
      }
      
    }
  }
  fclose(fp);
}






/* load the squirm.patterns into
   linked list */

void load_patterns(void)
{
  char buff[MAX_BUFF];
  FILE *fp;

  /* from main.c - main(), use alternate config if given */
  if(alternate_config != NULL)
    fp = fopen(alternate_config, "rt");
  else
    fp = fopen(REDIRECT_PATTERNS, "rt");
  

  if(fp == NULL) {
    log(LOG_ERROR, "unable to open redirect patterns file\n");
    dodo_mode = 1;
    return;
  }

  if(alternate_config != NULL)
    log(LOG_INFO, "Reading Patterns from config %s\n", alternate_config);
  else
    log(LOG_INFO, "Reading Patterns from config %s\n", REDIRECT_PATTERNS);
  
  while(!dodo_mode && (fgets(buff, MAX_BUFF, fp) != NULL)) {
    
    /* skip blank lines and comments */
    if((strncmp(buff, "#", 1) == 0) || (strncmp(buff, "\n", 1) == 0))
      continue;
    
    if(strlen(buff) != 1) {
      /* chop newline */
      buff[strlen(buff) - 1] = '\0';
      add_to_patterns(buff);
    }
  }  
  
  fclose(fp);
}




void add_to_patterns(char *pattern)
{
  char first[MAX_BUFF];
  char second[MAX_BUFF];
  char type[MAX_BUFF];
  char accel[MAX_BUFF];
  regex_t compiled;
  struct REGEX_pattern rpattern;
  int abort_type = 0;
  int parenthesis;
  int stored;
  
  /*  The regex_flags that we use are:
      REG_EXTENDED 
      REG_NOSUB 
      REG_ICASE; */

  int regex_flags = REG_NOSUB;
  
  rpattern.type = NORMAL;
  rpattern.case_sensitive = 1;
  
  stored = sscanf(pattern, "%s %s %s %s", type, first, second, accel);
  
  
  if((stored < 2) || (stored > 4)) {
    log(LOG_ERROR, 
	"unable to get a pair of patterns in add_to_patterns() "
	"for [%s]\n", pattern);
    dodo_mode = 1;
    return;
  }
  
  if(stored == 2)
    strcpy(second, "");
  
  if(strcmp(type, "abort") == 0) {
    rpattern.type = ABORT;
    abort_type = 1;
  }
  
  if(strcmp(type, "regexi") == 0) {
    regex_flags |= REG_ICASE;
    rpattern.case_sensitive = 0;
  }

  
  if(!abort_type) {

    parenthesis = count_parenthesis (first);

    if (parenthesis < 0) {
      
      /* The function returned an invalid result, 
	 indicating an invalid string */
      
      log (LOG_ERROR, "count_parenthesis() returned "
	   "left count did not match right count for line: [%s]\n",
	   pattern);
      dodo_mode = 1;
      return;

    } else if (parenthesis > 0) {

      regex_flags |= REG_EXTENDED;
      rpattern.type = EXTENDED;
      regex_flags ^= REG_NOSUB;

    }
  }
  
  
  if(regcomp(&compiled, first, regex_flags)) {
    log(LOG_ERROR, "Invalid regex [%s] in pattern file\n", first);
    dodo_mode = 1;
    return;
  }
  
  
  rpattern.cpattern = compiled;

  
  rpattern.pattern = (char *)malloc(sizeof(char) * (strlen(first) +1));
  if(rpattern.pattern == NULL) {
    log(LOG_ERROR, "unable to allocate memory in add_to_patterns()\n");
    dodo_mode = 1;
    return;
  }
  strcpy(rpattern.pattern, first);
  

  rpattern.replacement = (char *)malloc(sizeof(char) * (strlen(second) +1));
  if(rpattern.replacement == NULL) {
    log(LOG_ERROR, "unable to allocate memory in add_to_patterns()\n");
    dodo_mode = 1;
    return;
  }
  strcpy(rpattern.replacement, second);
  

  /* use accelerator string if it exists */
  if(stored == 4) {

    rpattern.has_accel = 1;
    rpattern.accel = get_accel(accel, &rpattern.accel_type, 
			       rpattern.case_sensitive);
  }


  /* use accelerator string if it exists */
  if(stored == 4) {

    rpattern.has_accel = 1;
    rpattern.accel = get_accel(accel, &rpattern.accel_type, 
			       rpattern.case_sensitive);


    if(rpattern.accel == NULL) {
      log(LOG_ERROR, "unable to allocate memory from get_accel()\n");
      dodo_mode = 1;
      return;
    }

  } else {
    rpattern.has_accel = 0;
    rpattern.accel = NULL;
  }
  
  add_to_plist(rpattern);
}





char *get_accel(char *accel, int *accel_type, int case_sensitive)
{
  /* returns the stripped accelerator string or NULL 
     if memory can't be allocated 

     converts the accel string to lower case 
     if(case_sensitive) */

  /* accel_type is assigned one of the values:
     #define ACCEL_NORMAL 1
     #define ACCEL_START  2
     #define ACCEL_END    3     */
  
  int len, i;
  char *new_accel = NULL;
  *accel_type = 0;
  
  
  len = strlen(accel);
  if(accel[0] == '^')
    *accel_type = ACCEL_START;
  if(accel[len - 1] == '$')
    *accel_type = ACCEL_END;
  if(! *accel_type)
    *accel_type = ACCEL_NORMAL;
  
  if(*accel_type == ACCEL_START || *accel_type == ACCEL_END) {
    
    /* copy the strings */
    new_accel = (char *)malloc(sizeof(char) * strlen(accel));
    if(new_accel == NULL)
      return NULL;
    
    if(*accel_type == ACCEL_START) {
      if(case_sensitive)
	for(i = 0; i < len; i++)
	  new_accel[i] = accel[i+1];
      else
	for(i = 0; i < len; i++)
	  new_accel[i] = tolower(accel[i+1]);
    }

    if(*accel_type == ACCEL_END) {
      if(case_sensitive)
	for(i = 0; i < len - 1; i++)
	  new_accel[i] = accel[i];
      else
	for(i = 0; i < len - 1; i++)
	  new_accel[i] = tolower(accel[i]);
      new_accel[i] = '\0';
    }
    
  } else {

    new_accel = strdup(accel);

    if(!case_sensitive) {
      for(i = 0; i < len; i++)
	new_accel[i] = tolower(accel[i]);
      new_accel[i] = '\0';
    }

  }

  
  return new_accel;
}




