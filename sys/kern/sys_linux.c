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
#include <sys/dirent.h>
#include <sys/file.h>
#include <sys/file2.h>
#include <sys/kern_syscall.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/nlookup.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/spinlock2.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>

/*XXX Where is this constant in headers? */
#ifndef MAXNAMELEN
#define MAXNAMELEN 255
#endif

MALLOC_DECLARE(M_INOTIFY);
MALLOC_DEFINE(M_INOTIFY, "inotify", "inotify file system monitoring");

static int	inotify_init(int flags, int *result);
static int	inotify_add_watch(struct inotify_handle *ih,
			const char *path, uint32_t pathlen, uint32_t mask, int *res);
static void	inotify_delete_watch(struct inotify_watch *iw);
static void	inotify_rm_watch(struct inotify_handle *ih, struct inotify_watch *iw);

static int	inotify_read(struct file *fp, struct uio *uio,
			struct ucred *cred, int flags);
static int	inotify_close(struct file *fp);
static int	inotify_stat(struct file *fp, struct stat *st,
			struct ucred *cred);
static int	inotify_shutdown(struct file *fp, int how);

static int	inotify_fdalloc(struct filedesc *fdp, int want, int *result);
static void	fdgrow_locked(struct filedesc *fdp, int want);
static void	fdreserve_locked(struct filedesc *fdp, int fd, int incr);

static struct inotify_watch*	inotify_find_watchwd(struct inotify_handle *ih, int wd);
static struct inotify_watch*	inotify_find_watch(struct inotify_handle *ih, 
							const char *path);

static struct fileops inotify_fops = {
	.fo_read = inotify_read,
	.fo_write = badfo_readwrite,
	.fo_ioctl = badfo_ioctl,
	.fo_kqfilter = badfo_kqfilter,
	.fo_stat = inotify_stat,
	.fo_close = inotify_close,
	.fo_shutdown = inotify_shutdown
};

static const uint inotify_max_user_instances = 128;
static const uint inotify_max_user_watches = 8192;
static const uint inotify_max_queued_events = 16384;

/* TODO: Global limits. Integrate with sysctl */
/*
 *static const uint inotify_max_user_instances_default = 128;
 *static const uint inotify_max_user_watches_default = 8192;
 *static const uint inotify_max_queued_events_default = 16384;
 *
 *static uint inotify_max_user_instances;
 *static uint inotify_max_user_watches;
 *static uint inotify_max_queued_events;
 *
 *SYSCTL_UINT(_kern, OID_AUTO, inotify_max_user_watches, CTLFLAG_RW,
 *                &inotify_max_user_watches, 0, "inotify maximum user watches limit");
 *SYSCTL_UINT(_kern, OID_AUTO, inotify_max_user_instances, CTLFLAG_RW,
 *                &inotify_max_user_instances, 0, "inotify maximum user instances limit");
 *SYSCTL_UINT(_kern, OID_AUTO, inotify_max_queued_events, CTLFLAG_RW,
 *                &inotify_max_queued_events, 0, "inotify maximum  queued events limit");
 *
 *static int
 *inotify_module_load(module_t mod, int cmd, void *arg)
 *{
 *        int error = 0;
 *
 *        switch (cmd) {
 *        case MOD_LOAD:
 *                kprintf("inotify: module loaded\n");
 *                [>sysctl_register_oid(&sysctl__kern_inotify_max_user_watches);<]
 *                [>sysctl_register_oid(&sysctl__kern_inotify_max_user_instances);<]
 *                [>sysctl_register_oid(&sysctl__kern_inotify_max_queued_events);<]
 *                break;
 *        case MOD_UNLOAD:
 *                [>sysctl_unregister_oid(&sysctl__kern_inotify_max_user_watches);<]
 *                [>sysctl_unregister_oid(&sysctl__kern_inotify_max_user_instances);<]
 *                [>sysctl_unregister_oid(&sysctl__kern_inotify_max_queued_events);<]
 *                break;
 *        default:
 *                error = EINVAL;
 *                break;
 *        }
 *        return error;
 *}
 *
 *static moduledata_t inotify_moddata= {
 *        "inotify_module",
 *        inotify_module_load,
 *        0
 *};
 */

DECLARE_MODULE(inotify_module, inotify_moddata, SI_SUB_EXEC, SI_ORDER_ANY);

/* TODO: Remove hardcoded constants for inotify_max_* */
int
sys_inotify_init(struct inotify_init_args *args)
{
	int error;
	error = inotify_init(0, &args->sysmsg_iresult);
	return (error);
}

int
sys_inotify_init1(struct inotify_init1_args *args)
{
	int error;
	error = inotify_init(args->flags, &args->sysmsg_iresult);
	return (error);
}

/* TODO: Check user limits, EMFILE */
/* TODO: Set appropriate flags */
static int
inotify_init(int flags, int *result)
{	
	struct thread *td = curthread;
	struct inotify_handle *ih;
	struct file *fp;	
	int fd = -1;
	int error;

	if (flags & ~(IN_CLOEXEC | IN_NONBLOCK))
		return (EINVAL);

	ih = kmalloc(sizeof(struct inotify_handle), M_INOTIFY, M_WAITOK);
	if (ih == NULL) {
		error = ENOMEM;
		goto done;
	}

	error = falloc(td->td_lwp, &fp, &fd);
	if (error != 0) {
		kprintf("inotify_init: Error creating file structure for inotify!\n");
		goto done;
	}

	TAILQ_INIT(&ih->wlh);
	ih->fp = fp;
	ih->event_count = 0;
	ih->queue_size = 0;
	ih->max_events = inotify_max_queued_events; /*TODO: Make it work? */

	fp->f_data = ih;
	fp->f_ops = &inotify_fops;
	fp->f_flag = FREAD;
	fp->f_type = DTYPE_INOTIFY;
	fsetfd(td->td_proc->p_fd, fp, fd);
	fdrop(fp);

	ih->wfdp = fdinit(curthread->td_proc);

done:
	*result = fd;
	return (error);
}

int
sys_inotify_add_watch(struct inotify_add_watch_args *args)
{
	struct proc *proc = curthread->td_proc;
	struct file *fp;
	struct inotify_handle *ih;
	struct inotify_watch *iht;
	char path[MAXPATHLEN];
	int fd = args->fd, error, res = -1;
	uint32_t pathlen;

	fp = proc->p_fd->fd_files[fd].fp;
	ih = (struct inotify_handle*)fp->f_data;

	if (fp->f_ops != &inotify_fops) {
		args->sysmsg_iresult = -1;
		return (EBADF);
	}

	error = copyinstr(args->pathname, path, MAXPATHLEN, &pathlen);
	if (error == 0 && pathlen <= 1) {
		return (ENOENT);
	}

	iht = inotify_find_watch(ih, path);
	if (iht != NULL) {
		iht->mask = args->mask;
		res = iht->wd;
		error = 0;
		goto done;
	}

	error = inotify_add_watch(ih, path, pathlen, args->mask, &res);
	if (error != 0) {
		kprintf("inotify_add_watch syscall: Error adding watch!\n");
		goto done;
	}

done:
	args->sysmsg_iresult = res;
	return (error);
}

static __inline int
INOTIFY_WATCH_INIT(struct inotify_watch **_iw, struct file *_fp, int _wd, uint32_t _mask, 
		struct inotify_watch *_parent, const char *_path, uint32_t _pathlen)
{
	struct inotify_watch *iw = kmalloc(sizeof(struct inotify_watch), M_INOTIFY, M_WAITOK);
	if (iw == NULL)
		return ENOMEM;

	iw->fp = _fp;
	iw->mask = _mask;
	iw->wd = _wd;
	iw->parent = _parent;
	iw->pathname = kmalloc(_pathlen + 1, M_INOTIFY, M_WAITOK);
	iw->pathlen = _pathlen;
	iw->childs = -1;
	strcpy(iw->pathname, _path);

	*_iw = iw;
	return 0;
}

/*TODO: Check user permission to read file */
static int
inotify_add_watch(struct inotify_handle *ih, const char *path, uint32_t pathlen, uint32_t mask, int *res)
{
	struct thread *td = curthread;
	struct ucred *cred = td->td_ucred;
	struct file *fp, *nfp;
	struct inotify_watch *iw = NULL, *siw = NULL;
	int wd = -1, error;

	struct stat st;
	struct dirent *direp;
	int nfd, nwd, dblen;
	uint32_t subpathlen;
	struct nlookupdata nd;
	char subpath[MAXPATHLEN], *dbuf;
	u_int dcount = (sizeof(struct dirent) + (MAXNAMELEN+1)) * inotify_max_user_watches;
	
	error = fp_open(path, O_RDONLY, 0400, &fp);
	if (error != 0) {
		kprintf("inotify_add_watch: Error opening file! \n");
		return (error);
	}

	error = inotify_fdalloc(ih->wfdp, 1, &wd);
	if (error != 0) {
		fp_close(fp);
		return (error);
	}

	error = INOTIFY_WATCH_INIT(&iw, fp, wd, mask, NULL, path, pathlen);
	if (error != 0)
		goto early_error;

	/* Now check if its a directory and get the entries */
	fo_stat(fp, &st, cred);
	if (st.st_mode & S_IFDIR) {
		kprintf("inotify_add_watch: Got a directory to add.\n");
		++iw->childs;

		error = nlookup_init(&nd, path, UIO_SYSSPACE, 0);
		if (error != 0)
			goto error_and_cleanup;

		error = kern_open(&nd, O_RDONLY, 0400, &nfd);
		nlookup_done(&nd);
		if (error != 0)
			goto error_and_cleanup;

		dbuf = kmalloc(dcount, M_INOTIFY, M_WAITOK); 
		/* XXX: make this read after basep, to work with large dirs
		 * and limited buffer 
		 */
		error = kern_getdirentries(nfd, dbuf, dcount, NULL, &dblen, UIO_SYSSPACE);
		if (error != 0) {
			kprintf("inotify_add_watch: error retrieving directories\n");
			kern_close(nfd);
			goto error_and_cleanup;
		}
		kern_close(nfd);

		strcpy(subpath, path);
		strcat(subpath, "/");
		for (direp = (struct dirent *)dbuf; (char*)direp < dbuf + dblen;
				direp = _DIRENT_NEXT(direp)) {
			if ((char *)_DIRENT_NEXT(direp) > dbuf + dblen)
				break;
			if (direp->d_namlen > MAXNAMELEN)
				continue;

			/* now check if given entry is again directory
			 * and this time we ignore them 
			 */
			if ( strcmp(direp->d_name, ".") == 0 ||
					strcmp(direp->d_name, "..") == 0) {
				continue;
			}
			strcpy(subpath + pathlen, direp->d_name);
			subpathlen = pathlen + direp->d_namlen + 1;

			error = fp_open(subpath, O_RDONLY, 0400, &nfp);
			if (error != 0) {
				kprintf("inotify_add_watch: Error opening file! \n");
				goto in_scan_error;
			}

			fo_stat(nfp, &st, cred);
			if (st.st_mode & S_IFDIR) {
				fp_close(nfp);
				continue;
			} else {
				error = inotify_fdalloc(ih->wfdp, 1, &nwd);
				if (error != 0)
					goto late_in_scan_error;

				fsetfd(ih->wfdp, nfp, nwd);
				error = INOTIFY_WATCH_INIT(&siw, nfp, nwd, mask, iw, subpath, subpathlen);
				if (error != 0)
					goto late_in_scan_error;

				TAILQ_INSERT_TAIL(&ih->wlh, siw, watchlist);
				++iw->childs;
				fdrop(nfp);
				kprintf("Adding => %s\n", direp->d_name);
			}
		}
		kfree(dbuf, M_INOTIFY);
	}

	fsetfd(ih->wfdp, fp, wd);
	TAILQ_INSERT_TAIL(&ih->wlh, iw, watchlist);
	fdrop(fp);

	*res = wd;
	return (error);

late_in_scan_error:
	fp_close(nfp);
	fsetfd(ih->wfdp, NULL, nwd);

in_scan_error:
	kfree(dbuf, M_INOTIFY);
	inotify_rm_watch(ih, iw);

error_and_cleanup:
	kfree(iw->pathname, M_INOTIFY);
	kfree(iw, M_INOTIFY);

early_error:
	fp_close(fp);
	fsetfd(ih->wfdp, NULL, wd);
	*res = -1;
	return (error);
}

int
sys_inotify_rm_watch(struct inotify_rm_watch_args *args)
{
	struct proc *proc = curthread->td_proc;
	struct file *ifp;
	struct inotify_handle *ih;
	struct inotify_watch *iw;
	int fd = args->fd, wd = args->wd;
	int error = 0, res = -1;

	ifp = proc->p_fd->fd_files[fd].fp;
	if (ifp->f_ops != &inotify_fops) {
		error = EBADF;
		goto done;
	}

	ih = (struct inotify_handle*)ifp->f_data;
	iw = inotify_find_watchwd(ih, wd);

	if (iw == NULL) {
		kprintf("inotify_rm_watch: INVAL wd passed\n");
		error = EINVAL;
		goto done;
	}
	
	inotify_rm_watch(ih, iw);
	res = 0;

done:
	args->sysmsg_iresult = res;
	return (error);
}

static void
inotify_rm_watch(struct inotify_handle *ih, struct inotify_watch *iw)
{
	struct inotify_watch *w1, *wtemp;

	if (iw->childs > 0) {
		TAILQ_FOREACH_MUTABLE(w1, &ih->wlh, watchlist, wtemp) {
			if (w1->parent == iw) {
				TAILQ_REMOVE(&ih->wlh, w1, watchlist);
				funsetfd(ih->wfdp, w1->wd);
				inotify_delete_watch(w1);
				--iw->childs;
			}

			if (iw->childs == 0)
				break;
		}
	}

	TAILQ_REMOVE(&ih->wlh, iw, watchlist);
	funsetfd(ih->wfdp, iw->wd);
	inotify_delete_watch(iw);
}

static int
inotify_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags)
{
	/**
	 * call copyin and copyout functions to walk through watch list
	 * and prepare to call kevent
	 */
	kprintf("called inotify_read\n");
	return 0;
}

static void
inotify_delete_watch(struct inotify_watch *iw)
{
	kprintf("deleting %s\n", iw->pathname);
	fp_close(iw->fp);
	kfree(iw->pathname, M_INOTIFY);
	kfree(iw, M_INOTIFY);
}

static int
inotify_shutdown(struct file *fp, int how)
{
	kprintf("inotify shutdown called\n");
	return 0;
}

static int
inotify_close(struct file *fp)
{	
	/*struct proc *proc = curthread->td_proc;*/
	struct inotify_handle *ih;
	struct inotify_watch *iw, *iw2;
	struct filedesc *fdp;

	kprintf("called inotify close\n");
	ih = (struct inotify_handle*)fp->f_data;
	fdp = ih->wfdp;

	iw = TAILQ_FIRST(&ih->wlh);
	while (iw != NULL) {
		iw2 = TAILQ_NEXT(iw, watchlist);
		inotify_delete_watch(iw);
		iw = iw2;
	}

	if (fdp->fd_files != fdp->fd_builtin_files)
		kfree(fdp->fd_files, M_INOTIFY);
	if (fdp->fd_cdir) {
		cache_drop(&fdp->fd_ncdir);
		vrele(fdp->fd_cdir);
	}
	if (fdp->fd_rdir) {
		cache_drop(&fdp->fd_nrdir);
		vrele(fdp->fd_rdir);
	}
	if (fdp->fd_jdir) {
		cache_drop(&fdp->fd_njdir);
		vrele(fdp->fd_jdir);
	}
	kfree(fdp, M_INOTIFY);
	kfree(ih, M_INOTIFY);

	return 0;
}

static int
inotify_stat(struct file *fp, struct stat *st, struct ucred *cred)
{
	/*struct inotify_handle *ih = (struct inotify_handle *)fp->f_data;*/
	bzero((void *)st, sizeof(*st));
	return 0;
}

static struct inotify_watch*
inotify_find_watchwd(struct inotify_handle *ih, int wd)
{	
	struct inotify_watch *iw;

	TAILQ_FOREACH(iw, &ih->wlh, watchlist) {
		if (iw->wd == wd)
			return iw;
	}
	return NULL;
}

/*XXX: Index the list by pathname for faster lookup */
static struct inotify_watch*
inotify_find_watch(struct inotify_handle *ih, const char *path)
{	
	struct inotify_watch *iw;

	TAILQ_FOREACH(iw, &ih->wlh, watchlist) {
		if (strcmp(iw->pathname, path) == 0)
			return iw;
	}
	return NULL;
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

	lim = inotify_max_user_watches;

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

