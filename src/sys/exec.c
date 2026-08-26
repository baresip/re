/**
 * @file exec.c  Execute programs (UNIX only)
 *
 * Copyright (C) 2026 Sebastian Reimers
 */
#include <stdlib.h>
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_list.h>
#include <re_mbuf.h>
#include <re_tmr.h>
#include <re_sys.h>
#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#ifndef WIN32
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#endif
#endif

#ifdef __APPLE__
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#else
#ifndef environ
extern char **environ;
#endif
#endif


#define DEBUG_MODULE "sys/exec"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum { EXEC_SLEEP_US = 10 * 1000 };


#ifndef WIN32

/**
 * Output pipe of the child process (stdout or stderr)
 */
struct exec_pipe {
	int fdr;	 /**< Read end in the parent process        */
	int fdw;	 /**< Write end, inherited by the child     */
	struct mbuf *mb; /**< Buffer for the captured output        */
	size_t pos;	 /**< Buffer position before capturing      */
};


static void exec_pipe_close(re_sock_t *fd)
{
	if (!fd || *fd < 0)
		return;

	(void)close(*fd);
	*fd = RE_BAD_SOCK;
}


static int exec_pipe_init(struct exec_pipe *p, struct mbuf *mb)
{
	re_sock_t pfd[2];
	int err;

	p->fdr = RE_BAD_SOCK;
	p->fdw = RE_BAD_SOCK;
	p->mb  = NULL;
	p->pos = 0;

	if (!mb)
		return 0;

	if (pipe(pfd) < 0)
		return errno;

	/* Close-on-exec, so that the descriptors are not leaked into
	 * unrelated child processes. dup2() in the child clears the flag
	 * for the duplicated descriptor. */
	for (int i = 0; i < 2; i++) {
		if (fcntl(pfd[i], F_SETFD, FD_CLOEXEC) < 0)
			goto error;
	}

	/* Non-blocking reads, the parent polls both pipes */
	if (fcntl(pfd[0], F_SETFL, O_NONBLOCK) < 0)
		goto error;

	p->fdr = pfd[0];
	p->fdw = pfd[1];
	p->mb  = mb;
	p->pos = mb->pos;

	return 0;

error:
	err = errno;
	(void)close(pfd[0]);
	(void)close(pfd[1]);
	return err;
}


static int exec_pipe_read(struct exec_pipe *p)
{
	uint8_t buf[1024];
	int err = 0;

	while (p->fdr >= 0) {

		ssize_t n = read(p->fdr, buf, sizeof(buf));
		if (n > 0) {
			err = mbuf_write_mem(p->mb, buf, (size_t)n);
			if (err)
				break;

			continue;
		}

		if (n == 0) /* EOF, the child closed the pipe */
			break;

		if (errno == EINTR)
			continue;

		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		err = errno;
		break;
	}

	exec_pipe_close(&p->fdr);

	return err;
}


static int exec_child_redirect(int fd, int stdfd)
{
	if (fd < 0)
		return 0;

	if (fd == stdfd) {
		/* pipe() got the descriptor of the standard stream, dup2()
		 * would be a no-op and would not clear close-on-exec */
		if (fcntl(fd, F_SETFD, 0) < 0)
			return errno;

		return 0;
	}

	if (dup2(fd, stdfd) < 0)
		return errno;

	return 0;
}


static int exec_pipes_read(struct exec_pipe *outp, struct exec_pipe *errp)
{
	int err = exec_pipe_read(outp);
	err |= exec_pipe_read(errp);

	return err;
}


static void exec_pipes_wait(struct exec_pipe *outp, struct exec_pipe *errp,
			    int ms)
{
	struct pollfd fds[2];
	nfds_t nfds = 0;

	if (outp->fdr >= 0) {
		fds[nfds].fd	 = outp->fdr;
		fds[nfds].events = POLLIN;
		++nfds;
	}

	if (errp->fdr >= 0) {
		fds[nfds].fd	 = errp->fdr;
		fds[nfds].events = POLLIN;
		++nfds;
	}

	if (!nfds) {
		sys_usleep(EXEC_SLEEP_US);
		return;
	}

	(void)poll(fds, nfds, ms);
}
#endif


int sys_vexec(struct mbuf *mb_out, struct mbuf *mb_err, uint64_t timeout_ms,
	      const char *path, va_list ap)
{
#ifndef WIN32
	char *argv[32];
	size_t n = 0;
	struct exec_pipe pout, perr;
	int err;

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

	err = exec_pipe_init(&pout, mb_out);
	if (err)
		return err;

	err = exec_pipe_init(&perr, mb_err);
	if (err)
		goto out;

	pid_t pid = fork();
	if (pid < 0) {
		err = errno;
		goto out;
	}

	if (pid == 0) {
		/* CHILD */
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);

		setpgid(0, 0);

		err = exec_child_redirect(pout.fdw, STDOUT_FILENO);
		if (err)
			_exit(127);

		err = exec_child_redirect(perr.fdw, STDERR_FILENO);
		if (err)
			_exit(127);

		execve(argv[0], argv, environ);

		_exit(127);
	}

	/* PARENT */
	setpgid(pid, pid);

	/* The write ends are owned by the child now */
	exec_pipe_close(&pout.fdw);
	exec_pipe_close(&perr.fdw);

	int status;
	uint64_t start = tmr_jiffies();
	bool timedout  = false;

	while (true) {
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == -1) {
			if (errno == EINTR)
				continue;
			err = errno;
			goto out;
		}
		if (w == pid)
			break;

		/* Drain the pipes while the child is running, otherwise
		 * the child blocks once a pipe buffer is full */
		err = exec_pipes_read(&pout, &perr);
		if (err)
			goto out;

		if (timeout_ms > 0 && (tmr_jiffies() - start) > timeout_ms) {
			timedout = true;
			break;
		}

		exec_pipes_wait(&pout, &perr, EXEC_SLEEP_US / 1000);
	}

	if (timedout) {
		DEBUG_WARNING("timeout: SIGTERM %s\n", path);
		kill(-pid, SIGTERM);

		for (int i = 0; i < 10; i++) {
			if (waitpid(pid, &status, WNOHANG) == pid)
				goto timeout;
			sys_usleep(EXEC_SLEEP_US);
		}

		DEBUG_WARNING("timeout: SIGKILL %s\n", path);
		kill(-pid, SIGKILL);

		waitpid(pid, &status, 0);

	timeout:
		/* Keep whatever the child managed to write */
		(void)exec_pipes_read(&pout, &perr);
		err = ETIME;
		goto out;
	}

	/* The child is gone, collect the remaining output */
	err = exec_pipes_read(&pout, &perr);
	if (err)
		goto out;

	if (WIFEXITED(status)) {
		err = -WEXITSTATUS(status);
	}
	else if (WIFSIGNALED(status)) {
		DEBUG_WARNING("killed by signal %d\n", WTERMSIG(status));
		err = ECANCELED;
	}
	else {
		err = ENODATA;
	}

out:
	exec_pipe_close(&pout.fdr);
	exec_pipe_close(&pout.fdw);
	exec_pipe_close(&perr.fdr);
	exec_pipe_close(&perr.fdw);

	if (pout.mb)
		mbuf_set_pos(pout.mb, pout.pos);

	if (perr.mb)
		mbuf_set_pos(perr.mb, perr.pos);

	return err;
#else
	(void)mb_out;
	(void)mb_err;
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
	int err = sys_vexec(NULL, NULL, 0, path, ap);
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
int sys_texec(uint64_t timeout_ms, const char *path, ...)
{
	va_list ap;

	va_start(ap, path);
	int err = sys_vexec(NULL, NULL, timeout_ms, path, ap);
	va_end(ap);

	return err;
}


/**
 * Execute a program synchronously with optional timeout and capture the
 * standard output and standard error streams
 *
 * @param mb_out     mbuf for the standard output (optional)
 * @param mb_err     mbuf for the standard error output (optional)
 * @param timeout_ms Timeout in milliseconds (0 = no timeout)
 * @param path       Full Path to executable
 * @param ...        Variable argument list of program arguments, last arg must
 *                   be NULL for termination
 *
 * @return 0 on success, negative program exit code on failure, otherwise
 * errorcode
 */
int sys_cexec(struct mbuf *mb_out, struct mbuf *mb_err, uint64_t timeout_ms,
	      const char *path, ...)
{
	va_list ap;

	va_start(ap, path);
	int err = sys_vexec(mb_out, mb_err, timeout_ms, path, ap);
	va_end(ap);

	return err;
}
