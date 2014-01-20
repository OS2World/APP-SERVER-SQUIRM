/* squirm.h */

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


#ifndef SQUIRM_H

/* squirm.h
   part of Squirm
*/

#ifndef LISTS_H
#include"lists.h"
#endif

#define SQUIRM_H 1

#include<stdarg.h>


#define MAX_BUFF 8000

struct IN_BUFF {
  char url[MAX_BUFF];
  char src_address[MAX_BUFF];
  char ident[MAX_BUFF];
  char method[MAX_BUFF];
};

int load_in_buff(char *, struct IN_BUFF *);

char *replace_string (struct pattern_item *, char *);
void squirm_HUP(int);
int match_accel(char *url, char *accel, int accel_type, int case_sensitive);
char *pattern_compare(char *);
int compare_ip(struct IP);
int count_parenthesis (char *);


/***** config ******/
void load_local_addresses(void);
int get_ip(char *buff, struct IP *src_address);
void load_patterns(void);
char *get_accel(char *accel, int *accel_type, int case_sensitive);


#endif








