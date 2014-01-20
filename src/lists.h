/* lists.h */


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


#ifndef LISTS_H



#define LISTS_H
#include<sys/types.h>
#include"regex.h"

#define NORMAL   1
#define EXTENDED 2
#define ABORT    3

#define ACCEL_NORMAL 1
#define ACCEL_START  2
#define ACCEL_END    3

struct IP {
  short first;
  short second;
  short third;
};

struct IP_item {
  struct IP address;
  struct IP_item *next;
};


struct REGEX_pattern {
  char *pattern;
  char *replacement;
  int case_sensitive;
  int type;
  int has_accel;
  int accel_type;
  char *accel;
  regex_t cpattern;
};

struct pattern_item {
  struct REGEX_pattern patterns;
  struct pattern_item *next;
};

void init_ip_list(void);
int add_to_ip_list(struct IP);
void free_ip_list(void);

void init_pattern_list(void);
void add_to_plist(struct REGEX_pattern);
void add_to_patterns(char *pattern);
void free_plist(void);

#endif
