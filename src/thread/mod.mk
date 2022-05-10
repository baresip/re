ifdef HAVE_THREADS
SRCS	+= thread/thread.c
else ifdef HAVE_PTHREAD
SRCS	+= thread/thread.c
SRCS	+= thread/posix.c
else ifdef WIN32
SRCS	+= thread/thread.c
SRCS	+= thread/win32.c
endif
