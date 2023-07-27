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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
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
#endif

#ifdef WIN32
enum {
	MAX_ENVSZ = 32767
};
#endif


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
