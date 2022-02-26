ifdef HAVE_THREADS
SRCS	+= thread/thread.c
else ifdef HAVE_PTHREAD
SRCS	+= thread/posix.c
endif
