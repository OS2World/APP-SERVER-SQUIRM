/* log.h */


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


#ifndef LOG_H

#define LOG_H


#ifdef __GNUC__
void log(char *, char *, ...) __attribute__ ((format (printf, 2, 3)));
#else
void log(char *, char *, ...);
#endif
char *get_date(void);


#endif
