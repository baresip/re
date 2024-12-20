/**
 * @file fs.c  File-system functions
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#include <direct.h>
#include <lmaccess.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_sys.h>
#include <re_mem.h>
#include <re_mbuf.h>


#define DEBUG_MODULE "fs"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#ifdef WIN32
#define open _open
#define read _read
#define close _close
#define dup _dup
#define dup2 _dup2
#define fileno _fileno
#endif

#define MINBUF_SIZE 1024


static int dup_stdout = -1;
static int dup_stderr = -1;

/**
 * Create a directory with full path
 *
 * @param path Directory path
 * @param mode Access permissions
 *
 * @return 0 if success, otherwise errorcode
 */
int fs_mkdir(const char *path, uint16_t mode)
{
	int ret;

	if (!path)
		return EINVAL;

#if defined (WIN32)
	(void)mode;
	ret = _mkdir(path);
#else
	ret = mkdir(path, mode);
#endif
	if (ret < 0)
		return errno;

	return 0;
}


/**
 * Get the home directory for the current user
 *
 * @param path String to write home directory
 * @param sz   Size of path string
 *
 * @return 0 if success, otherwise errorcode
 */
int fs_gethome(char *path, size_t sz)
{
#ifdef WIN32
	char win32_path[MAX_PATH];

	if (!path || !sz)
		return EINVAL;

	if (S_OK != SHGetFolderPath(NULL,
				    CSIDL_APPDATA | CSIDL_FLAG_CREATE,
				    NULL,
				    0,
				    win32_path)) {
		return ENOENT;
	}

	str_ncpy(path, win32_path, sz);

	return 0;

#elif defined(HAVE_PWD_H)
	const char *loginname;
	struct passwd *pw;

	if (!path || !sz)
		return EINVAL;

	loginname = sys_username();
	if (!loginname)
		return ENOENT;

	pw = getpwnam(loginname);
	if (!pw)
		return errno;

	str_ncpy(path, pw->pw_dir, sz);

	return 0;
#else
	(void)path;
	(void)sz;
	return ENOSYS;
#endif
}


/**
 * Check if given path is directory
 *
 * @param path Directory
 *
 * @return True if directory, False if not
 */
bool fs_isdir(const char *path)
{
	struct stat st;

	if (!path)
		return false;

	if (stat(path, &st) < 0)
		return false;

	if ((st.st_mode & S_IFMT) != S_IFDIR)
		return false;

	return true;
}


/**
 * Check if given file exists and is a regular file
 *
 * @param file Filepath
 *
 * @return True if exists and is regular file, False if not
 */
bool fs_isfile(const char *file)
{
	struct stat st;

	if (!file)
		return false;

	if (stat(file, &st) < 0)
		return false;

	if ((st.st_mode & S_IFMT) != S_IFREG)
		return false;

	return true;
}


/**
 * Open file with security enhancements (like fopen_s).
 * The file is created with mode 0600 if it does not exist
 *
 * @param fp   FILE pointer for allocation
 * @param file Pathname
 * @param mode fopen mode
 *
 * @return 0 if success, otherwise errorcode
 *
 */
int fs_fopen(FILE **fp, const char *file, const char *mode)
{
#ifdef WIN32
	return fopen_s(fp, file, mode);
#else
	FILE *pfile;
	int fd;

	if (!fp || !file || !str_isset(mode))
		return EINVAL;

	if (mode[0] == 'r' || fs_isfile(file))
		goto fopen;

	fd = open(file, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
	if (fd == -1)
		return errno;

	(void)close(fd);

fopen:
	pfile = fopen(file, mode);
	if (!pfile)
		return errno;

	*fp = pfile;

	return 0;
#endif
}


/**
 * Hide/Close stdout and stderr output (no THREAD-SAFETY)
 */
void fs_stdio_hide(void)
{
	dup_stdout = dup(fileno(stdout));
	dup_stderr = dup(fileno(stderr));
#ifdef WIN32
	int fd = open("nul", O_WRONLY);
#else
	int fd = open("/dev/null", O_WRONLY);
#endif
	if (fd < 0)
		return;

	(void)dup2(fd, fileno(stdout));
	(void)dup2(fd, fileno(stderr));

	close(fd);
}


/**
 * Restore stdout and stderr output (no THREAD-SAFETY)
 */
void fs_stdio_restore(void)
{
	if (dup_stdout < 0 || dup_stderr < 0)
		return;

	(void)dup2(dup_stdout, fileno(stdout));
	(void)dup2(dup_stderr, fileno(stderr));
}


int fs_fread(struct mbuf **mbp, const char *path)
{
	FILE *f = NULL;
	size_t n = 0;
	void *buf = NULL;
	struct mbuf *mb = NULL;
	int err;

	if (!mbp || !path)
		return EINVAL;

	err = fs_fopen(&f, path, "r");
	if (err || !f) {
		DEBUG_WARNING("Could not open file '%s'\n", path);
		return err;
	}

	mb = mbuf_alloc(MINBUF_SIZE);
	buf = mem_zalloc(MINBUF_SIZE, NULL);
	if (!mb || !buf) {
		err = ENOMEM;
		goto out;
	}

	while (1) {
		n = fread(buf, 1, MINBUF_SIZE, f);
		if (!n)
			goto out;

		err = mbuf_write_mem(mb, buf, n);
		if (err) {
			DEBUG_WARNING("Error reading file '%s' (%m)\n",
				path, err);
			goto out;
		}
	}

out:
	fclose(f);

	mem_deref(buf);
	if (err)
		mem_deref(mb);
	else
		*mbp = mb;

	return err;
}
