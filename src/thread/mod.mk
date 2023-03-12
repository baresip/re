ifdef HAVE_THREADS
else ifeq ($(OS),win32)
SRCS	+= thread/win32.c
else
SRCS	+= thread/posix.c
endif
SRCS	+= thread/thread.c
