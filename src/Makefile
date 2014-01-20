# Makefile for Squirm
#

OFILES = squirm.o main.o config.o log.o lists.o regex.o

HFILES = squirm.h paths.h lists.h log.h regex.h

CC=gcc
#CC=checkergcc

#EXTRALIBS=-lregex
#EXTRALIBS=

BINARIES = squirm

CFLAGS = -O3 -funroll-loops -fomit-frame-pointer -s -I./regex -L./regex
#COMPILE=-I.\regex -L.\regex
#CFLAGS = -Wall -g

all:	$(BINARIES)

install:	all
			install -m 755 -o root -g root -d /usr/local/squirm \
			/usr/local/squirm/bin
			install -m 770 -o root -g squid -d /usr/local/squirm/etc
			install -m 750 -o squid -g squid -d /usr/local/squirm/logs
			install -m 660 -o root -g squid squirm.local.dist squirm.patterns.dist \
			/usr/local/squirm/etc
			install -m 755 -o root -g root --strip squirm /usr/local/squirm/bin
			
squirm.o:	squirm.c $(HFILES)
			$(CC) -c squirm.c 		$(CFLAGS)

main.o:		main.c $(HFILES)
			$(CC) -c main.c		$(CFLAGS)

config.o:	config.c $(HFILES)
			$(CC) -c config.c		$(CFLAGS)

log.o:		log.c $(HFILES)
			$(CC) -c log.c		$(CFLAGS)

lists.o:	lists.c $(HFILES)
			$(CC) -c lists.c		$(CFLAGS)

squirm:		$(OFILES) $(HFILES)
			$(CC) -o squirm.exe $(OFILES)	$(EXTRALIBS)


pure:		clean
			rm -f *~

clean:		
			rm -f squirm.o main.o config.o log.o lists.o \
			 core squirm


