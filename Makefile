CC	= gcc
CFLAGS	= -ggdb -Wall -Werror -D_GNU_SOURCE

LIB	= libextlib.so.1
LIB_FLAGS = -fPIC -shared
EXTRAS = `pkg-config --cflags --libs gnome-keyring-1` -lmcrypt -lm

RM	= rm
ECHO	= echo

SRCS	= main.c syscall_handler.c
OBJS	= ${SRCS:.c=.o} ${COM_SRCS:.c=.o}

.SUFFIXES: .o .c

all: $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) $(LIB_FLAGS) $(OBJS) $(EXTRAS) -o $(LIB)

.c.o :
	$(OLIB) $(CC) $(CFLAGS) $(EXTRAS) -c $<

clean :
	-$(RM) -f $(OBJS)
	-$(RM) -f $(LIB)

