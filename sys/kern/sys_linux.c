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
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/spinlock2.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/types.h>


MALLOC_DECLARE(M_INOTIFY);
MALLOC_DEFINE(M_INOTIFY, "inotify", "inotify file system monitoring");

static const int inotify_max_user_instances = 128;
static const int inotify_max_user_watches = 8192;
static const int inotify_max_queued_events = 16384;

static struct filedesc *inotify_wfdp = NULL;

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

static int	inotify_add_watch(struct inotify_handle *ih, const char *path,
			uint32_t mask);
static int	inotify_rm_watch(struct inotify_handle *ih,
			struct inotify_watch *iw);

static int	inotify_fdalloc(struct filedesc *fdp, int want, int *result);
static void	fdgrow_locked(struct filedesc *fdp, int want)
static void	fdreserve_locked(struct filedesc *fdp, int fd, int incr)


static struct fileops inotify_fops = {
	.fo_read = inotify_read,
	.fo_close = inotify_close,
	.fo_stat = inotify_stat
};

static __inline void
inotify_wfdinit(struct filedesc **fdp)
{
	/*fdp = kmalloc(sizeof(struct filedesc), M_INOTIFY,*/
			/*M_WAITOK | M_ZERO);*/

	/*fdp->fd_refcnt = 1;*/
	/*fdp->fd_cmask = 022;*/
	/*fdp->fd_files = fdp->fd_builtin_files;*/
	/*fdp->fd_nfiles = NDFILE;*/
	/*fdp->fd_lastfile = -1;*/
	/*spin_init(&fdp->fd_spin);*/

	/* TODO: Make our own fdinit */
	*fdp = fdinit(curthread->td_proc);
}

/* TODO: lock shared data */
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
	fp->f_flag = O_RDONLY;
	fsetfd(td->td_proc->p_fd, fp, fd);

	if (inotify_wfdp == NULL) {
		inotify_wfdinit(&inotify_wfdp);
	}

	args->sysmsg_iresult = fd;
	return (error);
}

int
sys_inotify_init1(struct inotify_init1_args *args)
{
	kprintf("syscall => inotify_init1\n");
	return 0;
}

/* TODO: DOesnt adds directories yet */
int
sys_inotify_add_watch(struct inotify_add_watch_args *args)
{
	struct proc *proc = curthread->td_proc;
	struct file *fp;
	struct inotify_handle *ih;
	char path[MAXPATHLEN];
	int fd = args->fd;
	int error;

	/*
	 * Find old watch if exists and update it
	 * otherwise append the new one
	 */

	fp = proc->p_fd->fd_files[fd].fp;
	ih = (struct inotify_handle*)fp->f_data;

	if (fp->f_ops != &inotify_fops) {
		return (EBADF);
	}

	error = copyinstr(args->pathname, path, MAXPATHLEN, NULL);
	/* XXX handle copyinstr error  */
	error = inotify_add_watch(ih, path, args->mask);
	if (error != 0) {
		kprintf("inotify_add_watch syscall: Error adding watch!\n");
	}

	args->sysmsg_iresult = fd;
	return error;
}

static int
inotify_add_watch(struct inotify_handle *ih, const char *path, uint32_t mask)
{
	struct file *fp;
	struct inotify_watch *iw;
	int error, wd = -1;

	error = fp_open(path, O_RDONLY, 0400, &fp);
	if (error != 0) {
		kprintf("inotify_add_watch: Error opening file! \n");
		return (error);
	}

	error = inotify_fdalloc(inotify_wfdp, 1, &wd);
	if (error != 0) {
		kprintf("inotify_add_watch: filedesc table full\n");
		fp_close(fp);
		/* TODO: Check other cleaups required */
		return (error);
	}

	iw = kmalloc(sizeof(struct inotify_watch), M_INOTIFY, M_WAITOK);
	iw->fp = fp;
	iw->mask = mask;
	iw->wd = wd;
	fsetfd(inotify_wfdp, fp, wd);
	TAILQ_INSERT_TAIL(&ih->wlh, iw, watchlist);

	return (error);
}

int
sys_inotify_rm_watch(struct inotify_rm_watch_args *args)
{
	/* Nothing related to rm_watch. Just prototyping */
	struct proc *proc = curthread->td_proc;
	struct file *fp;
	struct inotify_handle *ih;
	struct inotify_watch *iw;
	int fd = args->fd;
	/*int error;*/

	kprintf("syscall => inotify_rm_watch");

	fp = proc->p_fd->fd_files[fd].fp;
	ih = (struct inotify_handle*)fp->f_data;

	TAILQ_FOREACH(iw, &ih->wlh, watchlist) {
		kprintf("Now iterated => %d \n", iw->wd);
	}
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

	/* Just to make it compile. Warnig treated as error. */
	inotify_stat(0, 0, 0);
	inotify_rm_watch(0, 0);
	return 0;
}

static int
inotify_stat(struct file *fp, struct stat *fb, struct ucred *cred)
{
	return 0;
}

static int
inotify_rm_watch(struct inotify_handle *ih, struct inotify_watch *iw)
{
	return 0;
}


/* NOTE: Following are  Copied from fdalloc and modified */

/* TODO: Set limits as per handle or desc initialized? */
/*
 * Grow the file table so it can hold through descriptor (want).
 *
 * The fdp's spinlock must be held exclusively on entry and may be held
 * exclusively on return.  The spinlock may be cycled by the routine.
 *
 * MPSAFE
 */
static void
fdgrow_locked(struct filedesc *fdp, int want)
{
	struct fdnode *newfiles;
	struct fdnode *oldfiles;
	int nf, extra;

	nf = fdp->fd_nfiles;
	do {
		/* nf has to be of the form 2^n - 1 */
		nf = 2 * nf + 1;
	} while (nf <= want);

	spin_unlock(&fdp->fd_spin);
	newfiles = kmalloc(nf * sizeof(struct fdnode), M_INOTIFY, M_WAITOK);
	spin_lock(&fdp->fd_spin);

	/*
	 * We could have raced another extend while we were not holding
	 * the spinlock.
	 */
	if (fdp->fd_nfiles >= nf) {
		spin_unlock(&fdp->fd_spin);
		kfree(newfiles, M_INOTIFY);
		spin_lock(&fdp->fd_spin);
		return;
	}
	/*
	 * Copy the existing ofile and ofileflags arrays
	 * and zero the new portion of each array.
	 */
	extra = nf - fdp->fd_nfiles;
	bcopy(fdp->fd_files, newfiles, fdp->fd_nfiles * sizeof(struct fdnode));
	bzero(&newfiles[fdp->fd_nfiles], extra * sizeof(struct fdnode));

	oldfiles = fdp->fd_files;
	fdp->fd_files = newfiles;
	fdp->fd_nfiles = nf;

	if (oldfiles != fdp->fd_builtin_files) {
		spin_unlock(&fdp->fd_spin);
		kfree(oldfiles, M_INOTIFY);
		spin_lock(&fdp->fd_spin);
	}
}


/*
 * Number of nodes in right subtree, including the root.
 */
static __inline int
right_subtree_size(int n)
{
	return (n ^ (n | (n + 1)));
}

/*
 * Bigger ancestor.
 */
static __inline int
right_ancestor(int n)
{
	return (n | (n + 1));
}

/*
 * Smaller ancestor.
 */
static __inline int
left_ancestor(int n)
{
	return ((n & (n + 1)) - 1);
}

/*
 * Traverse the in-place binary tree buttom-up adjusting the allocation
 * count so scans can determine where free descriptors are located.
 *
 * MPSAFE - caller must be holding an exclusive spinlock on fdp
 */
static void
fdreserve_locked(struct filedesc *fdp, int fd, int incr)
{
	while (fd >= 0) {
		fdp->fd_files[fd].allocated += incr;
		KKASSERT(fdp->fd_files[fd].allocated >= 0);
		fd = left_ancestor(fd);
	}
}


/*
 * Reserve a file descriptor for the process.  If no error occurs, the
 * caller MUST at some point call fsetfd() or assign a file pointer
 * or dispose of the reservation.
 *
 * MPSAFE
 */
static int
inotify_fdalloc(struct filedesc *fdp, int want, int *result)
{
	/*struct proc *p = curthread->td_proc;*/
	/*struct uidinfo *uip;*/
	int fd, rsize, rsum, node, lim;

	lim = 2048;

	/* TODO: Check if user has run out of watch limit */

	/*
	 * Grow the dtable if necessary
	 */
	spin_lock(&fdp->fd_spin);
	if (want >= fdp->fd_nfiles)
		fdgrow_locked(fdp, want);

	/*
	 * Search for a free descriptor starting at the higher
	 * of want or fd_freefile.  If that fails, consider
	 * expanding the ofile array.
	 *
	 * NOTE! the 'allocatedinotify_wfdp' field is a cumulative recursive allocation
	 * count.  If we happen to see a value of 0 then we can shortcut
	 * our search.  Otherwise we run through through the tree going
	 * down branches we know have free descriptor(s) until we hit a
	 * leaf node.  The leaf node will be free but will not necessarily
	 * have an allocated field of 0.
	 */
retry:
	/* move up the tree looking for a subtree with a free node */
	for (fd = max(want, fdp->fd_freefile); fd < min(fdp->fd_nfiles, lim);
	     fd = right_ancestor(fd)) {
		if (fdp->fd_files[fd].allocated == 0)
			goto found;

		rsize = right_subtree_size(fd);
		if (fdp->fd_files[fd].allocated == rsize)
			continue;	/* right subtree full */

		/*
		 * Free fd is in the right subtree of the tree rooted at fd.
		 * Call that subtree R.  Look for the smallest (leftmost)
		 * subtree of R with an unallocated fd: continue moving
		 * down the left branch until encountering a full left
		 * subtree, then move to the right.
		 */
		for (rsum = 0, rsize /= 2; rsize > 0; rsize /= 2) {
			node = fd + rsize;
			rsum += fdp->fd_files[node].allocated;
			if (fdp->fd_files[fd].allocated == rsum + rsize) {
				fd = node;	/* move to the right */
				if (fdp->fd_files[node].allocated == 0)
					goto found;
				rsum = 0;
			}
		}
		goto found;
	}
	/*
	 * No space in current array.  Expand?
	 */
	if (fdp->fd_nfiles >= lim) {
		spin_unlock(&fdp->fd_spin);
		return (EMFILE);
	}
	fdgrow_locked(fdp, want);
	goto retry;

found:
	KKASSERT(fd < fdp->fd_nfiles);
	if (fd > fdp->fd_lastfile)
		fdp->fd_lastfile = fd;
	if (want <= fdp->fd_freefile)
		fdp->fd_freefile = fd;
	*result = fd;
	KKASSERT(fdp->fd_files[fd].fp == NULL);
	KKASSERT(fdp->fd_files[fd].reserved == 0);
	fdp->fd_files[fd].fileflags = 0;
	fdp->fd_files[fd].reserved = 1;
	fdreserve_locked(fdp, fd, 1);
	spin_unlock(&fdp->fd_spin);
	return (0);
}

