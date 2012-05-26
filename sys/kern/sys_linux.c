/*
 * Copyright (c) 2012 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Vishesh Yadav <vishesh3y@gmail.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 */

#include <sys/linux/inotify.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/types.h>

MALLOC_DECLARE(M_INOTIFY);
MALLOC_DEFINE(M_INOTIFY, "inotify", "inotify file system monitoring");

static const int inotify_max_user_instances = 128;
static const int inotify_max_user_watches = 8192;
static const int inotify_max_queued_events = 16384;

struct inotify_handle {
	struct file	*fp;
	unsigned int	 event_count;
	unsigned int	 max_events;
	unsigned int	 queue_size;
	TAILQ_HEAD(, inotify_watch) wlh;
};

struct inotify_watch {
	int		 wd;
	uint32_t	 mask;
	struct file	*fp;
	struct inotify_handle *handle;
	TAILQ_ENTRY(inotify_watch) watchlist;
};

static int	inotify_read(struct file *fp, struct uio *uio,
			struct ucred *cred, int flags);
static int	inotify_close(struct file *fp);
static int	inotify_stat(struct file *fp, struct stat *fb,
			struct ucred *cred);

static int	inotify_add_watch(int fd, const char *path, uint32_t mask,
			struct inotify_handle *ih);
static int	inotify_rm_watch(struct inotify_handle *ih,
			struct inotify_watch *iw);

static struct fileops inotify_fops = {
	.fo_read = inotify_read,
	.fo_close = inotify_close,
	.fo_stat = inotify_stat
};


/* TODO: Remove hardcoded constants for inotify_max_* */
int
sys_inotify_init(struct inotify_init_args *args)
{
	struct thread *td = curthread;
	struct inotify_handle *ih;
	struct file *fp;	
	int fd;
	int error;

	error = falloc(td->td_lwp, &fp, &fd);
	if (error != 0) {
		kprintf("inotify_init: Error creating file structure for inotify!\n");
		return 0;
	}

	ih = kmalloc(sizeof(struct inotify_handle), M_INOTIFY, M_WAITOK);
	TAILQ_INIT(&ih->wlh);
	ih->fp = fp;
	ih->event_count = 0;
	ih->queue_size = 0;
	ih->max_events = 4096;
	

	fp->f_data = ih;
	fp->f_ops = &inotify_fops;
	fsetfd(td->td_proc->p_fd, fp, fd);

	return fd;
}

int
sys_inotify_init1(struct inotify_init1_args *args)
{
	kprintf("syscall => inotify_init1\n");
	return 0;
}

int
sys_inotify_add_watch(struct inotify_add_watch_args *args)
{
	kprintf("syscall => inotify_add_watch");
	return 0;
}

int
sys_inotify_rm_watch(struct inotify_rm_watch_args *args)
{
	kprintf("syscall => inotify_rm_watch");
	return 0;
}


static int
inotify_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags)
{
	/**
	 * call copyin and copyout functions to walk through watch list
	 * and prepare to call kevent
	 */
	return 0;
}

static int
inotify_close(struct file *fp)
{
	/*
	 * Unset fd and walk through all watches, and destroy them
	 * and close all the opened files
	 */
	return 0;
}

static int
inotify_stat(struct file *fp, struct stat *fb, struct ucred *cred)
{
	return 0;
}


static int
inotify_add_watch(int fd, const char *path, uint32_t mask,
		struct inotify_handle *ih)
{
	int wd;
	int error;
	struct file *fp;
	struct inotify_watch *iw;

	error = fn_open(path, O_RDONLY,, &fp);
	if (error == 0) {
		kprintf("inotify:create_watch: Error opening file! \n");
		return (error);
	}

	iw = kmalloc(sizeof(struct inotify_watch), M_INOTIFY, M_WAITOK);
	iw->fp = fp;
	iw->mask = mask;

	/* allocate a wd */
	/* associate fd with fp, table  */

	TAILQ_INSERT_TAIL(ih->iwh, iw, watchlist);

	return (error);
}

static int
inotify_rm_watch(struct inotify_handle *ih, struct inotify_watch *iw)
{
	return 0;
}

