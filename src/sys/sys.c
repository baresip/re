/**
 * @file sys.c  System information
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_sys.h>
#include <re_list.h>
#include <re_tmr.h>
#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#ifndef WIN32
#include <sys/wait.h>
#endif
#endif
#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SETRLIMIT
#include <sys/resource.h>
#endif

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

enum {
	MAX_ENVSZ = 32767
};
#else
#ifdef __APPLE__
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#else
#ifndef environ
extern char **environ;
#endif
#endif
#endif


#define DEBUG_MODULE "sys"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum { EXEC_SLEEP_US = 10 * 1000 };

/**
 * Get kernel name and version
 *
 * @param pf     Print function for output
 * @param unused Unused parameter
 *
 * @return 0 if success, otherwise errorcode
 */
int sys_kernel_get(struct re_printf *pf, void *unused)
{
#ifdef HAVE_UNAME
	struct utsname u;

	(void)unused;

	if (0 != uname(&u))
		return errno;

	return re_hprintf(pf, "%s %s %s %s %s", u.sysname, u.nodename,
			  u.release, u.version, u.machine);
#else
	const char *str;

	(void)unused;

#if defined(WIN32)
	str = "Win32";
#else
	str = "?";
#endif

	return re_hprintf(pf, "%s", str);
#endif
}


/**
 * Get build info
 *
 * @param pf     Print function for output
 * @param unused Unused parameter
 *
 * @return 0 if success, otherwise errorcode
 */
int sys_build_get(struct re_printf *pf, void *unused)
{
	const unsigned int bus_width = 8*sizeof(void *);
	const char *endian = "unknown";

	const uint32_t a = 0x12345678;
	const uint8_t b0 = ((uint8_t *)&a)[0];
	const uint8_t b1 = ((uint8_t *)&a)[1];
	const uint8_t b2 = ((uint8_t *)&a)[2];
	const uint8_t b3 = ((uint8_t *)&a)[3];

	(void)unused;

	if (0x12==b0 && 0x34==b1 && 0x56==b2 && 0x78==b3)
		endian = "big";
	else if (0x12==b3 && 0x34==b2 && 0x56==b1 && 0x78==b0)
		endian = "little";

	return re_hprintf(pf, "%u-bit %s endian", bus_width, endian);
}


/**
 * Get architecture
 *
 * @return Architecture string
 */
const char *sys_arch_get(void)
{
#ifdef ARCH
	return ARCH;
#else
	return "?";
#endif
}


/**
 * Get name of Operating System
 *
 * @return Operating System string
 */
const char *sys_os_get(void)
{
#ifdef OS
	return OS;
#else
	return "?";
#endif
}


/**
 * Get libre version
 *
 * @return libre version string
 */
const char *sys_libre_version_get(void)
{
#ifdef RE_VERSION
	return RE_VERSION;
#else
	return "?";
#endif
}


/**
 * Return the username (login name) for the current user
 *
 * @return Username or NULL if not available
 */
const char *sys_username(void)
{
#ifdef HAVE_PWD_H
	char *login;

	login = getenv("LOGNAME");
	if (!login)
		login = getenv("USER");
#ifdef HAVE_UNISTD_H
	if (!login) {
		login = getlogin();
	}
#endif

	return str_isset(login) ? login : NULL;
#else
	return NULL;
#endif
}


/**
 * Enable or disable coredump
 *
 * @param enable true to enable, false to disable coredump
 *
 * @return 0 if success, otherwise errorcode
 */
int sys_coredump_set(bool enable)
{
#ifdef HAVE_SETRLIMIT
	const struct rlimit rlim = {
		enable ? RLIM_INFINITY : 0,
		enable ? RLIM_INFINITY : 0
	};

	return 0 == setrlimit(RLIMIT_CORE, &rlim) ? 0 : errno;
#else
	(void)enable;
	return ENOSYS;
#endif
}


/**
 * Get an environment variable
 *
 * @param env   Pointer to destination env var
 * @param name  Environment variable name
 *
 * @return 0 if success, otherwise errorcode
 */
int sys_getenv(char **env, const char *name)
{
	if (!env || !name)
		return EINVAL;

#ifdef WIN32
	uint32_t rc    = 1;
	uint32_t bufsz = rc;
	char *buf;

	buf = mem_zalloc(bufsz, NULL);
	if (!buf)
		return ENOMEM;

	while (1) {
		rc = GetEnvironmentVariableA(name, buf, bufsz);
		if (!rc || rc == bufsz || rc > MAX_ENVSZ) {
			mem_deref(buf);
			return ENODATA;
		}

		/* success */
		if (rc < bufsz) {
			*env = buf;
			return 0;
		}

		/* failed, getenv needs more space */
		bufsz = rc;
		buf   = mem_realloc(buf, bufsz);
		if (!buf) {
			mem_deref(buf);
			return ENOMEM;
		}
	}
#else
	char *tmp = getenv(name);
	if (!tmp)
		return ENODATA;

	return str_dup(env, tmp);
#endif
}


static int _sys_exect(uint64_t timeout_ms, const char *path, va_list ap)
{
#ifndef WIN32
	char *argv[32];
	size_t n = 0;

	if (!path)
		return EINVAL;

	argv[n++] = (char *)path;
	for (; n < RE_ARRAY_SIZE(argv) - 1; n++) {
		char *arg = va_arg(ap, char *);
		if (!arg)
			break;
		argv[n] = arg;
	}

	if (n == RE_ARRAY_SIZE(argv) - 1)
		return E2BIG;

	argv[n] = NULL;

	pid_t pid = fork();
	if (pid < 0)
		return errno;

	if (pid == 0) {
		/* CHILD */
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);

		setpgid(0, 0);

		execve(argv[0], argv, environ);

		_exit(127);
	}

	/* PARENT */
	setpgid(pid, pid);

	int status;
	uint64_t start = tmr_jiffies();
	bool timedout  = false;

	while (true) {
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == -1) {
			if (errno == EINTR)
				continue;
			return errno;
		}
		if (w == pid)
			break;

		if (timeout_ms > 0 && (tmr_jiffies() - start) > timeout_ms) {
			timedout = true;
			break;
		}
		sys_usleep(EXEC_SLEEP_US);
	}

	if (timedout) {
		DEBUG_WARNING("exec/timeout: SIGTERM %s\n", path);
		kill(-pid, SIGTERM);

		for (int i = 0; i < 10; i++) {
			if (waitpid(pid, &status, WNOHANG) == pid)
				return ETIME;
			sys_usleep(EXEC_SLEEP_US);
		}

		DEBUG_WARNING("exec/timeout: SIGKILL %s\n", path);
		kill(-pid, SIGKILL);

		waitpid(pid, &status, 0);
		return ETIME;
	}

	if (WIFEXITED(status))
		return -WEXITSTATUS(status);
	else if (WIFSIGNALED(status)) {
		DEBUG_WARNING("exec: killed by signal %d\n", WTERMSIG(status));
		return ECANCELED;
	}

	return ENODATA;
#else
	(void)timeout_ms;
	(void)path;
	(void)ap;
	return ENOSYS;
#endif
}


/**
 * Execute a program synchronously
 *
 * @param path       Full Path to executable
 * @param ...        Variable argument list of program arguments, last arg must
 *                   be NULL for termination
 *
 * @return 0 on success, negative program exit code on failure, otherwise
 * errorcode
 */
int sys_exec(const char *path, ...)
{
	va_list ap;

	va_start(ap, path);
	int err = _sys_exect(0, path, ap);
	va_end(ap);

	return err;
}


/**
 * Execute a program synchronously with optional timeout
 *
 * @param timeout_ms Timeout in milliseconds (0 = no timeout)
 * @param path       Full Path to executable
 * @param ...        Variable argument list of program arguments, last arg must
 *                   be NULL for termination
 *
 * @return 0 on success, negative program exit code on failure, otherwise
 * errorcode
 *
 */
int sys_exect(uint64_t timeout_ms, const char *path, ...)
{
	va_list ap;

	va_start(ap, path);
	int err = _sys_exect(timeout_ms, path, ap);
	va_end(ap);

	return err;
}
