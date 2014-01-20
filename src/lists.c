/* lists.c */

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


#include"squirm.h"
#include"paths.h"
#include"log.h"
#include"lists.h"

#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include"regex.h"

/* #ifndef _RX_H
#include<regex.h>
#endif */



extern int dodo_mode;


struct IP_item *head;
struct pattern_item *phead;


void init_ip_list(void)
{
  head = NULL;
}

void init_pattern_list(void)
{
  phead = NULL;
}



int add_to_ip_list(struct IP src_address)
{
  struct IP_item *curr;
  struct IP_item *new;
  
  curr = NULL;
  new = NULL;
  
  new = (struct IP_item *)malloc(sizeof(struct IP_item));
  if(new == NULL) {
    log(LOG_ERROR, "unable to allocate memory in add_to_ip_list()\n");
    dodo_mode = 1;
    return 1;
  }
  
  
  new->address.first  = src_address.first;
  new->address.second = src_address.second;
  new->address.third  = src_address.third;
  new->next = NULL;
  
  if(head == NULL)
    head = new;
  else {
    for(curr = head; curr->next != NULL; curr = curr->next)
      ;
    curr->next = new;
  }
  
  
  return 0;
}




void add_to_plist(struct REGEX_pattern pattern)
{
  struct pattern_item *curr;
  struct pattern_item *new;
  
  curr = NULL;
  new = NULL;
  
  /* two strings are already allocated in the "pattern" struct
     argument to this function */
  
  new = (struct pattern_item *)malloc(sizeof(struct pattern_item));
  if(new == NULL) {
    log(LOG_ERROR, "unable to allocate memory in add_to_plist()\n");
    /* exit(3); */
    dodo_mode = 1;
    return;
  }
  
  new->patterns.pattern = pattern.pattern;
  new->patterns.replacement = pattern.replacement;
  new->patterns.type = pattern.type;
  new->patterns.has_accel = pattern.has_accel;
  new->patterns.accel = pattern.accel;
  new->patterns.accel_type = pattern.accel_type;
  new->patterns.case_sensitive = pattern.case_sensitive;
  
  /* not sure whether we need to copy each item in the struct */
  new->patterns.cpattern = pattern.cpattern;
  new->next = NULL;
  
  if(phead == NULL)
    phead = new;
  else {
    for(curr = phead; curr->next != NULL; curr = curr->next)
      ;
    curr->next = new;
  }
}




void free_ip_list(void)
{
  struct IP_item *prev;
  struct IP_item *next;
  
  prev = NULL;
  next = NULL;
  
  
  if(head != NULL) {
    next = head->next;
    free(head);
  }
  
  for(prev = next; next != NULL; ) {
    next = prev->next;
    free(prev);
    prev = next;
  }
  
  head = NULL;
}






void free_plist(void)
{
  struct pattern_item *prev;
  struct pattern_item *next;
  
  prev = NULL;
  next = NULL;
  
  if(phead != NULL) {
    next = phead->next;
    free(phead);
  }
  
  for(prev = next; next != NULL; ) {
    next = prev->next;
    
    free(prev->patterns.pattern);
    free(prev->patterns.replacement);
    if(prev->patterns.accel)
      free(prev->patterns.accel);
    
    free(prev);
    prev = next;
  }
  
  phead = NULL;
}









