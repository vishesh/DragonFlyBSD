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
#include <sys/nlookup.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/spinlock2.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>

/* TODO: Delete pending events when watches are removed */
/* TODO: Find and replace with inotify_flags */

#define INOTIFY_EVENT_SIZE	(sizeof (struct inotify_event))

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
static struct inotify_ucount*	inotify_find_iuc(uid_t id);

static int	inotify_copyin(void *arg, struct kevent *kevp, int maxevents, int *events);
static int	inotify_copyout(void *arg, struct kevent *kevp, int count, int *res);
static int	inotify_to_kevent(struct inotify_watch *iw, struct kevent *kev);

struct inotify_kevent_copyin_args {
	struct inotify_handle *handle;
	struct inotify_watch  *last_iw;
	int count;
	int error;
};

static struct fileops inotify_fops = {
	.fo_read = inotify_read,
	.fo_write = badfo_readwrite,
	.fo_ioctl = badfo_ioctl,
	.fo_kqfilter = badfo_kqfilter,
	.fo_stat = inotify_stat,
	.fo_close = inotify_close,
	.fo_shutdown = inotify_shutdown
};

static const uint inotify_max_user_instances_default = 128;
static const uint inotify_max_user_watches_default = 8192; /* we consider all watches */
static const uint inotify_max_queued_events_default = 16384;

static uint inotify_max_user_instances;
static uint inotify_max_user_watches;
static uint inotify_max_queued_events;

SLIST_HEAD(, inotify_ucount) iuc_head = SLIST_HEAD_INITIALIZER(iuc_head);

static void
inotify_sysinit(void *args)
{
	static struct sysctl_oid *root;
	static struct sysctl_ctx_list clist;

	inotify_max_user_instances = inotify_max_user_instances_default;
	inotify_max_user_watches = inotify_max_user_watches_default;
	inotify_max_queued_events = inotify_max_queued_events_default;

	SLIST_INIT(&iuc_head);

	/* create the table */
	sysctl_ctx_init(&clist);
	root = SYSCTL_ADD_NODE(&clist, SYSCTL_STATIC_CHILDREN(_kern),
			OID_AUTO, "inotify", CTLFLAG_RW, 0, "inotify settings root node");
	if(root == NULL) {
		kprintf("SYSCTL_ADD_NODE failed!\n");
		return ;
	}

	SYSCTL_ADD_UINT(&clist, SYSCTL_CHILDREN(root), OID_AUTO, "max_user_watches",
			CTLFLAG_RW, &inotify_max_user_watches, 0,
			"inotify maximum user watches limit");
	SYSCTL_ADD_UINT(&clist, SYSCTL_CHILDREN(root), OID_AUTO, "max_user_instances",
			CTLFLAG_RW, &inotify_max_user_instances, 0,
			"inotify maximum user instance limit");
	SYSCTL_ADD_UINT(&clist, SYSCTL_CHILDREN(root), OID_AUTO, "max_queued_events",
			CTLFLAG_RW, &inotify_max_queued_events, 0,
			"inotify maximum queued events");
}

SYSINIT(inotify, SI_SUB_HELPER_THREADS, SI_ORDER_ANY, inotify_sysinit, NULL);


static struct inotify_ucount*
inotify_find_iuc(uid_t id)
{
	struct inotify_ucount *iuc;
	SLIST_FOREACH(iuc, &iuc_head, ic_entry) {
		if (iuc->ic_uid == id)
			return iuc;
	}
	
	iuc = kmalloc(sizeof *iuc, M_INOTIFY, M_WAITOK);
	iuc->ic_uid = id;
	iuc->ic_watches = 0;
	iuc->ic_instances = 0;

	SLIST_INSERT_HEAD(&iuc_head, iuc, ic_entry);
	return iuc;
}

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

/* TODO: Set appropriate flags */
static int
inotify_init(int flags, int *result)
{	
	struct thread *td = curthread;
	struct inotify_handle *ih;
	struct inotify_ucount *iuc;
	struct file *fp;	
	int fd = -1;
	int error;

	iuc = inotify_find_iuc(td->td_ucred->cr_uid);
	if (iuc->ic_instances >= inotify_max_user_instances)
		return (EMFILE);

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

	TAILQ_INIT(&ih->eventq);
	TAILQ_INIT(&ih->wlh);
	ih->fp = fp;
	ih->event_count = 0;
	ih->queue_size = 0;
	ih->max_events = inotify_max_queued_events; /*TODO: Make it work? */
	ih->nchilds = 0;
	ih->iuc = iuc;

	++iuc->ic_instances;
	fp->f_data = ih;
	fp->f_ops = &inotify_fops;
	fp->f_flag = FREAD;
	fp->f_type = DTYPE_INOTIFY;
	fsetfd(td->td_proc->p_fd, fp, fd);
	fdrop(fp);

	ih->wfdp = fdinit(curthread->td_proc);
	kqueue_init(&ih->kq, ih->wfdp);

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
	struct inotify_ucount *iuc;
	char path[MAXPATHLEN];
	int fd = args->fd, error, res = -1;
	uint32_t pathlen;

	fp = proc->p_fd->fd_files[fd].fp;
	ih = (struct inotify_handle*)fp->f_data;
	iuc = ih->iuc;

	if (iuc->ic_watches >= inotify_max_user_watches)
		return (ENOSPC);


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
		if (args->mask & IN_MASK_ADD) {
			iht->mask |= args->mask;
		} else {
			iht->mask = args->mask;
		}
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
	iw->iw_qrefs = 0;
	iw->iw_marks = 0;
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
	struct inotify_ucount *iuc = ih->iuc;
	struct inotify_watch *iw = NULL, *siw = NULL;
	int wd = -1, error;

	struct stat st;
	struct dirent *direp;
	int nfd, nwd, dblen;
	uint32_t subpathlen;
	struct nlookupdata nd;
	char subpath[MAXPATHLEN], *dbuf;
	u_int dcount = (sizeof(struct dirent) + (MAXPATHLEN+1)) * inotify_max_user_watches;
	
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

	fo_stat(fp, &st, cred);
	if ((st.st_mode & S_IFREG) && (mask & IN_ONLYDIR))
		goto early_error;

	error = INOTIFY_WATCH_INIT(&iw, fp, wd, mask, NULL, path, pathlen);
	/*kprintf("added name= %s, wd = %d\n", path, wd);*/
	if (error != 0)
		goto early_error;

	++iuc->ic_watches;
	++ih->nchilds;
	TAILQ_INSERT_TAIL(&ih->wlh, iw, watchlist);

	/* Now check if its a directory and get the entries */
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
			goto in_scan_error;
		}
		kern_close(nfd);

		strcpy(subpath, path);
		strcat(subpath, "/");
		for (direp = (struct dirent *)dbuf; (char*)direp < dbuf + dblen;
				direp = _DIRENT_NEXT(direp)) {
			if ((char *)_DIRENT_NEXT(direp) > dbuf + dblen)
				break;
			if (direp->d_namlen > MAXPATHLEN)
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
				if (iuc->ic_watches >= inotify_max_user_watches) {
					error = ENOSPC;
					goto iwfdp_in_scan_error;
				}

				error = inotify_fdalloc(ih->wfdp, 1, &nwd);
				if (error != 0)
					goto iwfdp_in_scan_error;

				fsetfd(ih->wfdp, nfp, nwd);
				error = INOTIFY_WATCH_INIT(&siw, nfp, nwd, mask, iw, subpath, subpathlen);
				if (error != 0)
					goto late_in_scan_error;

				TAILQ_INSERT_TAIL(&ih->wlh, siw, watchlist);
				++iw->childs;
				++ih->nchilds;
				++iuc->ic_watches;
				fdrop(nfp);
				/*kprintf("Adding => %s, wd = %d\n", direp->d_name, siw->wd);*/
			}
		}
		kfree(dbuf, M_INOTIFY);
	}

	fsetfd(ih->wfdp, fp, wd);
	fdrop(fp);
	*res = wd;
	return (error);

late_in_scan_error:
	fsetfd(ih->wfdp, NULL, nwd);

iwfdp_in_scan_error:
	fp_close(nfp);

in_scan_error:
	kfree(dbuf, M_INOTIFY);

error_and_cleanup:
	iuc->ic_watches -= iw->childs + 2;
	ih->nchilds -= iw->childs + 2;
	inotify_rm_watch(ih, iw);

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
	} else if (iw->parent != NULL) {
		kprintf("inotify_rm_watch: INVAL wd passed. Not available for user.\n");
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
inotify_delete_watch(struct inotify_watch *iw)
{
	if (iw->fp) {
		fp_close(iw->fp);
		iw->fp = NULL;
	}
	if (iw->iw_qrefs > 0)
		return;
	kfree(iw->pathname, M_INOTIFY);
	kfree(iw, M_INOTIFY);
}

static void
inotify_rm_watch(struct inotify_handle *ih, struct inotify_watch *iw)
{
	struct inotify_watch *w1, *wtemp;
	struct inotify_ucount *iuc = ih->iuc;

	iuc->ic_watches -= iw->childs + 1;
	ih->nchilds -= iw->childs + 1;
	if (iw->childs > 0) {
		TAILQ_FOREACH_MUTABLE(w1, &ih->wlh, watchlist, wtemp) {
			if (w1->parent == iw) {
				knote_fdclose(w1->fp, ih->wfdp, w1->wd);
				TAILQ_REMOVE(&ih->wlh, w1, watchlist);
				funsetfd(ih->wfdp, w1->wd);
				w1->iw_marks |= IW_MARKED_FOR_DELETE;
				inotify_delete_watch(w1);
				--iw->childs;
			}

			if (iw->childs == 0)
				break;
		}
	}

	knote_fdclose(iw->fp, ih->wfdp, iw->wd);
	TAILQ_REMOVE(&ih->wlh, iw, watchlist);
	funsetfd(ih->wfdp, iw->wd);
	iw->iw_marks |= IW_MARKED_FOR_DELETE;
	inotify_delete_watch(iw);
}

static int
inotify_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags)
{
	struct inotify_kevent_copyin_args ika;
	struct inotify_handle *ih;
	struct inotify_watch *iw;
	struct inotify_queue_entry *iqe, *iqe_temp;
	struct inotify_event *ie;
	int error, res = 0, nevents;
	int eventlen;

	ie = kmalloc(INOTIFY_EVENT_SIZE + MAXPATHLEN, M_INOTIFY, M_WAITOK);
	ih = (struct inotify_handle*)fp->f_data;
	nevents = inotify_max_queued_events - ih->queue_size;
	ika.handle = ih;
	ika.error = 0;
	ika.count = 0;
	ika.last_iw = TAILQ_FIRST(&ih->wlh);

	error = kern_kevent(&ih->kq, nevents, &res, &ika,
				inotify_copyin, inotify_copyout, NULL);

	if (error != 0)
		goto done;

	TAILQ_FOREACH_MUTABLE(iqe, &ih->eventq, entries, iqe_temp) {
		iw = iqe->iw;
		if (iw->iw_marks & IW_MARKED_FOR_DELETE) {
			if (--iw->iw_qrefs < 1)
				inotify_delete_watch(iw);
			continue;
		}

		if (iw->parent == NULL) {
			eventlen = INOTIFY_EVENT_SIZE;
			ie->wd = iw->wd;
			ie->mask = 0;
			ie->len = 0;

		} else {
			eventlen = INOTIFY_EVENT_SIZE + iw->pathlen;
			ie->wd = iw->parent->wd;
			ie->mask = IN_ISDIR;
			ie->len = iw->pathlen;
			strcpy(ie->name, iw->pathname);
		}

		if (uio->uio_resid < eventlen)
			break;

		ie->mask |= iqe->mask;
		ie->cookie = 0;

		error = uiomove((caddr_t)ie, eventlen, uio);
		if (error > 0) {
			kprintf("inotify_read: error while transferring\n");
			break;
		}
		
		TAILQ_REMOVE(&ih->eventq, iqe, entries);
		kfree(iqe, M_INOTIFY);
		--ih->queue_size;
		--iw->iw_qrefs;

		if (iw->mask & IN_ONESHOT) {
			if (iw->parent == NULL) {
				inotify_rm_watch(ih, iw);
			} else {
				inotify_rm_watch(ih, iw->parent);
			}
		}
	}

done:
	kfree(ie, M_INOTIFY);
	return (error);
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
	struct inotify_handle *ih;
	struct inotify_watch *iw, *iw2;
	struct inotify_queue_entry *iqe, *iqe_next;
	struct filedesc *fdp;

	ih = (struct inotify_handle*)fp->f_data;

	fdp = ih->wfdp;
	--ih->iuc->ic_instances;
	ih->iuc->ic_watches -= ih->nchilds;

	iqe = TAILQ_FIRST(&ih->eventq);
	TAILQ_FOREACH_MUTABLE(iqe, &ih->eventq, entries, iqe_next) {
		TAILQ_REMOVE(&ih->eventq, iqe, entries);
		kfree(iqe, M_INOTIFY);
	}

	iw = TAILQ_FIRST(&ih->wlh);
	while (iw != NULL) {
		iw2 = TAILQ_NEXT(iw, watchlist);
		knote_fdclose(iw->fp, ih->wfdp, iw->wd);
		iw->iw_qrefs = 0;
		inotify_delete_watch(iw);
		iw = iw2;
	}

	if (fdp->fd_files != fdp->fd_builtin_files) {
		kfree(fdp->fd_files, M_INOTIFY);
	}
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

	kqueue_terminate(&ih->kq);
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

static int
inotify_to_kevent(struct inotify_watch *iw, struct kevent *kev)
{
	u_int flags = EV_ADD | EV_ENABLE | EV_CLEAR;
	u_int fflags = NOTE_REVOKE | NOTE_RENAME;
	uint32_t mask = iw->mask;

	if (mask & IN_OPEN)
		fflags |= NOTE_OPEN;
	if (mask & IN_ACCESS)
		fflags |= NOTE_ACCESS;
	if (mask & IN_CLOSE_WRITE)
		fflags |= NOTE_CLOSE_WRITE;
	if (mask & IN_CLOSE_NOWRITE)
		fflags |= NOTE_CLOSE_NOWRITE;
	if (mask & IN_MODIFY)
		fflags |= NOTE_WRITE;
	if (mask & IN_CREATE)
		fflags |= NOTE_CREATE;
	if (mask & IN_ATTRIB)
		fflags |= NOTE_ATTRIB;
	if (mask & IN_MOVED_FROM)
		fflags |= NOTE_RENAME;
	if (mask & IN_MOVED_TO)
		fflags |= NOTE_WRITE;
	if (mask & IN_MOVE_SELF)
		fflags |= NOTE_RENAME;
	if (mask & IN_DELETE)
		fflags |= NOTE_DELETE;
	if (mask & IN_DELETE_SELF)
		fflags |= NOTE_DELETE;

	/* flags */
	if (mask & IN_ONESHOT) {
		flags |= EV_ONESHOT;
	}


	EV_SET(kev, iw->wd, EVFILT_VNODE, flags, fflags, 0, (void*)iw);
	return (0);
}

static void
inotify_from_kevent(struct kevent *kev, inotify_flags *flag)
{
	uint32_t result;
	u_int fflags = kev->fflags;
	struct inotify_watch *iw = (struct inotify_watch *)kev->udata;

	if (fflags & NOTE_OPEN) {
		result |= IN_OPEN;
	}
	if (fflags & NOTE_CLOSE_WRITE) {
		result |= IN_CLOSE_WRITE;
	}
	if (fflags & NOTE_CLOSE_NOWRITE) {
		result |= IN_CLOSE_NOWRITE;
	}
	if (fflags & NOTE_ACCESS) {
		result |= IN_ACCESS;
	}
	if (fflags & NOTE_WRITE) {
		if (iw->parent == NULL && iw->childs < 0) {
			/* regular file */
			result |= IN_MODIFY;
		} else if (iw->parent == NULL && iw->childs >= 0) {
			/* directory */
			/* NOTE: also triggered when a file is moved in,
			 * removed - IN_MOVED_TO? */
			result &= ~IN_MODIFY;
			kprintf("inotify: something added or removed?\n");
		} else {
			kprintf("inotify: NOTE_WRITE for some file in directory.\n");
			result |= IN_MODIFY;
		}
	}
	if (fflags & NOTE_ATTRIB) {
		result |= IN_ATTRIB;
	}
	if (fflags & NOTE_CREATE) {
		result |= IN_CREATE;
		/* TODO: Find the newly created file/dir */
		/* NOTE: NOTE_WRITE also happens */
		kprintf("inotify: created a new file/dir?\n");
	}
	if (fflags & NOTE_DELETE) {
		if (iw->parent == NULL) {
			result |= IN_DELETE_SELF;
		} else {
			result |= IN_DELETE; /* file deleted under dir */
		}
	}
	if (fflags & NOTE_RENAME) {
		if (iw->parent == NULL) {
			result |= IN_MOVE_SELF;
			/* TODO: New path? */
			kprintf("inotify: renamed un-parented watch\n");
		} else {
			/* TODO: IN MOVED FROM */
			kprintf("inotify: renamed parented watch\n");
		}
	}
	if (fflags & NOTE_REVOKE) {
		result |= IN_UNMOUNT; /* or revoked */
	}

	*flag = result;
}


static int
inotify_copyin(void *arg, struct kevent *kevp, int maxevents, int *events)
{
	struct inotify_kevent_copyin_args *ikap;
	struct inotify_handle *ih;
	struct inotify_watch *iw;
	struct kevent *kev;
	int  error;

	ikap = (struct inotify_kevent_copyin_args *)arg;
	ih = ikap->handle;
	iw = ikap->last_iw;

	while ( iw != NULL && *events < maxevents) {
		kev = &kevp[*events];
		error = inotify_to_kevent(iw, kev);
		++ikap->count;
		iw = TAILQ_NEXT(iw, watchlist);
		++*events;
	}

	ikap->last_iw = iw;
	return (0);
}

static int
inotify_copyout(void *arg, struct kevent *kevp, int count, int *res)
{
	struct inotify_kevent_copyin_args *ikap;
	struct inotify_handle *ih;
	struct inotify_watch *iw;
	struct kevent *kev;
	struct inotify_queue_entry *iqe;
	inotify_flags rmask;
	int i;

	ikap = (struct inotify_kevent_copyin_args *)arg;
	ih = ikap->handle;

	for (i = 0; i < count; ++i) {
		kev = &kevp[i];
		iw = (struct inotify_watch *)kev->udata;
		inotify_from_kevent(kev, &rmask);

		if ((iw->mask & IN_ONESHOT) && ((iw->iw_marks & IW_GOT_ONESHOT)
			|| (iw->parent != NULL && iw->parent->iw_marks & IW_GOT_ONESHOT))) {
			continue;
		}

		iqe = kmalloc(sizeof *iqe, M_INOTIFY, M_WAITOK);
		iqe->iw = iw;
		iqe->mask = rmask;
		++iw->iw_qrefs;

		if (iw->parent != NULL)
			iw->parent->iw_marks |= IW_GOT_ONESHOT;
		iw->iw_marks |= IW_GOT_ONESHOT;

		TAILQ_INSERT_TAIL(&ih->eventq, iqe, entries);
	}

	*res += count;
	ih->queue_size += *res;
	ikap->count = 0;

	return (0);
}

