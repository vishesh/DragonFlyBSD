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

#include <sys/inotify.h>
#include <sys/dirent.h>
#include <sys/file.h>
#include <sys/file2.h>
/*#include <sys/idr.h>*/
#include <sys/kern_syscall.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/nlookup.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/spinlock2.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>

/* TODO: Find and replace with inotify_flags */
/* TODO: IN_ISDIR for watch files */
/* TODO: cleanup unnecessary structures and memory allocations. 
 	Directly use inotify_events in copyout. */
/* TODO: Better cleanup and memory management */
/* TODO: Optimize */

#define INOTIFY_EVENT_SIZE	(sizeof (struct inotify_event))

#define inotify_watch_name(iw)	(iw)->fp->f_nchandle.ncp->nc_name
#define inotify_watch_name_len(iw)	(iw)->fp->f_nchandle.ncp->nc_nlen

MALLOC_DECLARE(M_INOTIFY);
MALLOC_DEFINE(M_INOTIFY, "inotify", "inotify file system monitoring");

static int	inotify_init(int flags, int *result);
static int	inotify_add_watch(struct inotify_handle *ih,
			const char *path, uint32_t pathlen, inotify_flags mask, int *res);
static void	inotify_insert_child(struct inotify_handle *ih, struct inotify_watch *child);
static struct inotify_watch*  inotify_insert_child_watch(struct inotify_watch *parent,
		const char *path);

static void	inotify_delete_watch(struct inotify_watch *iw);
static void	inotify_rm_watch(struct inotify_handle *ih, struct inotify_watch *iw);
static void	inotify_remove_child(struct inotify_watch *iw);

static int	inotify_read(struct file *fp, struct uio *uio,
			struct ucred *cred, int flags);
static int	inotify_close(struct file *fp);
static int	inotify_stat(struct file *fp, struct stat *st,
			struct ucred *cred);
int		inotify_kqfilter(struct file *fp, struct knote *kn);
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
static void	inotify_queue_event(struct inotify_watch *iw, inotify_flags mask, inotify_flags hint, const char *filename, int cookie);

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
	.fo_kqfilter = inotify_kqfilter,
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

static int
fp_open_at(const char *path, int flags, int mode, struct file *rfp,
		struct file **fpp)
{
	struct thread *td = curthread;
	struct file *fp;
	struct nlookupdata nd;
	int error;

	if ((error = falloc(NULL, fpp, NULL)) != 0)
		return (error);
	fp = *fpp;
	if (td->td_proc) {
		if ((flags & O_ROOTCRED) == 0)
			fsetcred(fp, td->td_proc->p_ucred);
	}

	if  ((error = nlookup_init(&nd, path, UIO_SYSSPACE, NLC_LOCKVP)) != 0)
		goto done;

	if (nd.nl_path[0] != '/') {
		cache_drop(&nd.nl_nch);
		cache_copy(&rfp->f_nchandle, &nd.nl_nch);
	}

	flags = FFLAGS(flags);
	if (error == 0)
		error = vn_open(&nd, fp, flags, mode);

	nlookup_done(&nd);

done:
	if (error) {
		fdrop(fp);
		*fpp = NULL;
	}

	return (error);
}

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
			return (iuc);
	}
	
	iuc = kmalloc(sizeof *iuc, M_INOTIFY, M_WAITOK);
	iuc->ic_uid = id;
	iuc->ic_watches = 0;
	iuc->ic_instances = 0;

	SLIST_INSERT_HEAD(&iuc_head, iuc, ic_entry);
	return (iuc);
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
	ih->kq.kq_state |= KQ_DATASYS;

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

	error = inotify_add_watch(ih, path, pathlen-1, args->mask, &res);
	if (error != 0) {
		kprintf("inotify_add_watch syscall: Error adding watch!\n");
		goto done;
	}

done:
	args->sysmsg_iresult = res;
	return (error);
}

/* TODO: Allocate memory for path and string at once, and fix ripples */
static __inline int
INOTIFY_WATCH_INIT(struct inotify_watch **_iw, struct file *_fp, int _wd,
		inotify_flags _mask, struct inotify_watch *_parent,
		struct inotify_handle *_handle,
		const char *_path, uint32_t _pathlen)
{
	struct inotify_watch *iw = kmalloc(sizeof(struct inotify_watch), M_INOTIFY, M_WAITOK);
	if (iw == NULL)
		return (ENOMEM);

	iw->fp = _fp;
	iw->mask = _mask;
	iw->wd = _wd;
	iw->parent = _parent;
	iw->childs = -1;
	iw->iw_qrefs = 0;
	iw->iw_marks = 0;
	iw->handle = _handle;
	if (_path != NULL) {
		iw->pathname = kmalloc(_pathlen + 1, M_INOTIFY, M_WAITOK);
		iw->pathlen = _pathlen;
		strcpy(iw->pathname, _path);
	} else {
		iw->pathname = NULL;
		iw->pathlen = 0;
	}
	TAILQ_INIT(&iw->knel);

	*_iw = iw;
	return (0);
}

static void
inotify_insert_child(struct inotify_handle *ih, struct inotify_watch *child)
{
	TAILQ_INSERT_TAIL(&ih->wlh, child, watchlist);
	++child->childs;
	++ih->nchilds;
	++ih->iuc->ic_watches;
}


static struct inotify_watch*
inotify_insert_child_watch(struct inotify_watch *parent, const char *path)
{
	struct file *fp;
	struct inotify_watch *iw = NULL;
	struct inotify_handle *ih = parent->handle;
	struct inotify_ucount *iuc = ih->iuc;
	int wd, error;

	if (iuc->ic_watches >= inotify_max_user_watches) {
		/* error = ENOSPC; */
		return (NULL);
	}

	error = fp_open_at(path, O_RDONLY, 0400, parent->fp, &fp);
	if (error != 0) {
		kprintf("inotify_insert_child_watch: Error opening file, old = %s! \n", 
				path);
		return (NULL);
	}

	error = inotify_fdalloc(ih->wfdp, 1, &wd);
	if (error != 0)
		goto done;

	fsetfd(ih->wfdp, fp, wd);
	error = INOTIFY_WATCH_INIT(&iw, fp, wd, parent->mask, parent, ih, NULL, 0);
	if (error != 0)
		goto done;

	inotify_insert_child(ih, iw);

done:
	fdrop(fp);
	return (iw);
}

static int
inotify_add_watch(struct inotify_handle *ih, const char *path, uint32_t pathlen,
		inotify_flags mask, int *res)
{
	struct thread *td = curthread;
	struct ucred *cred = td->td_ucred;
	struct file *fp, *nfp;
	struct inotify_ucount *iuc = ih->iuc;
	struct inotify_watch *iw = NULL, *siw = NULL;
	int wd = -1, error;

	struct stat st;
	struct dirent *direp = NULL;
	int nfd, nwd, dblen;
	struct nlookupdata nd;
	char *dbuf;
	u_int dcount = sizeof(struct dirent) * 10;
	long basep = 0;
	
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

	error = INOTIFY_WATCH_INIT(&iw, fp, wd, mask, NULL, ih, path, pathlen);
	if (error != 0)
		goto early_error;

	++iuc->ic_watches;
	++ih->nchilds;
	TAILQ_INSERT_TAIL(&ih->wlh, iw, watchlist);

	/* Now check if its a directory and get the entries */
	if (st.st_mode & S_IFDIR) {
		++iw->childs;

		error = nlookup_init(&nd, path, UIO_SYSSPACE, NLC_FOLLOW);
		if (error != 0)
			goto error_and_cleanup;

		/* as get direntries require a fd */
		error = kern_open(&nd, O_RDONLY, 0400, &nfd);
		nlookup_done(&nd);
		if (error != 0)
			goto error_and_cleanup;

		dbuf = kmalloc(dcount, M_INOTIFY, M_WAITOK);

		for (;;) {
			error = kern_getdirentries(nfd, dbuf, dcount, &basep, &dblen, UIO_SYSSPACE);
			if (error != 0) {
				kprintf("inotify_add_watch: error retrieving directories\n");
				kern_close(nfd);
				goto in_scan_error;
			}
			if (dblen == 0)
				break;

			for (direp = (struct dirent *)dbuf; (char*)direp < dbuf + dblen;
					direp = _DIRENT_NEXT(direp)) {
				if ((char *)_DIRENT_NEXT(direp) > dbuf + dblen)
					break;
				if (direp->d_namlen > MAXPATHLEN)
					continue;

				/* now check if given entry is again directory
				 * and this time we ignore them 
				 */
				if (strcmp(direp->d_name, ".") == 0 ||
						strcmp(direp->d_name, "..") == 0) {
					continue;
				}

				error = fp_open_at(direp->d_name, O_RDONLY, 0400, fp, &nfp);
				if (error != 0) {
					kprintf("inotify_add_watch: Error opening file! \n");
					goto in_scan_error;
				}
				kprintf("Added %s\n", direp->d_name);

				if (iuc->ic_watches >= inotify_max_user_watches) {
					error = ENOSPC;
					goto iwfdp_in_scan_error;
				}

				error = inotify_fdalloc(ih->wfdp, 1, &nwd);
				if (error != 0)
					goto iwfdp_in_scan_error;

				fsetfd(ih->wfdp, nfp, nwd);
				error = INOTIFY_WATCH_INIT(&siw, nfp, nwd, mask, iw, ih, NULL, 0);
				if (error != 0)
					goto late_in_scan_error;

				inotify_insert_child(ih, siw);
				fdrop(nfp);
			}
		}
		kern_close(nfd);
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
	if (iw->pathname != NULL)
		kfree(iw->pathname, M_INOTIFY);
	kfree(iw, M_INOTIFY);
}

static void
inotify_remove_child(struct inotify_watch *iw)
{
	struct inotify_handle *ih = iw->handle;

	TAILQ_REMOVE(&ih->wlh, iw, watchlist);
	funsetfd(ih->wfdp, iw->wd);
	iw->iw_marks |= IW_MARKED_FOR_DELETE;
	--iw->parent->childs;
	inotify_delete_watch(iw);
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
				inotify_remove_child(w1);
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

/* TODO: Order IN_MOVED_TO and IN_MOVED_FROM events by marking or otherwise */
static int
inotify_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags)
{
	struct inotify_kevent_copyin_args ika;
	struct inotify_handle *ih;
	struct inotify_watch *iw;
	struct inotify_queue_entry *iqe, *iqe_temp;
	struct inotify_event *ie = NULL;
	int error, res = 0, nevents, eventlen;
	char *watch_name;

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

		if (iw->parent == NULL) {
			eventlen = INOTIFY_EVENT_SIZE;
			if ((iqe->mask & IN_CREATE) > 0 ||
					(iqe->mask & IN_MOVED_TO) > 0) {
				ie->mask = IN_ISDIR;
				ie->len = iqe->namelen + 1;
				eventlen += ie->len;
				strcpy(ie->name, iqe->name);

			} else {
				ie->mask = 0;
				ie->len = 0;
			}
			ie->wd = iw->wd;

		} else {
			eventlen = INOTIFY_EVENT_SIZE + inotify_watch_name_len(iw) + 1;
			ie->len = inotify_watch_name_len(iw) + 1;
			ie->wd = iw->parent->wd;
			ie->mask = IN_ISDIR;
			if (iqe->namelen > 0) {
				strcpy(ie->name, iqe->name);
			} else {
				watch_name = inotify_watch_name(iw);
				strcpy(ie->name, watch_name);
			}
		}

		if (uio->uio_resid < eventlen)
			break;

		ie->mask |= iqe->mask;
		ie->cookie = iqe->cookie;

		error = uiomove((caddr_t)ie, eventlen, uio);
		if (error > 0) {
			kprintf("inotify_read: error while transferring\n");
			break;
		}
		
		--ih->queue_size;
		--iw->iw_qrefs;
		TAILQ_REMOVE(&ih->eventq, iqe, entries);
		kfree(iqe, M_INOTIFY);

		if (iw->mask & IN_ONESHOT) {
			if (iw->parent == NULL) {
				inotify_rm_watch(ih, iw);
			} else {
				inotify_rm_watch(ih, iw->parent);
			}
		} else  if ((iw->iw_marks & IW_MARKED_FOR_DELETE) > 0 && iw->iw_qrefs < 1) {
			inotify_delete_watch(iw);
		} else if ((iw->iw_marks & IW_WATCH_DELETE) && iw->iw_qrefs < 1) {
			inotify_remove_child(iw);
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
	return (0);
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
		vrele(fdp->fd_rdir); }
	if (fdp->fd_jdir) {
		cache_drop(&fdp->fd_njdir);
		vrele(fdp->fd_jdir);
	}

	kqueue_terminate(&ih->kq);

	return (0);
}

static int
inotify_stat(struct file *fp, struct stat *st, struct ucred *cred)
{
	/*struct inotify_handle *ih = (struct inotify_handle *)fp->f_data;*/
	bzero((void *)st, sizeof(*st));
	return (0);
}

/*ARGSUSED*/
static int
filt_inotifyread(struct knote *kn, long hint)
{
	struct file *fp = kn->kn_ptr.p_fp;
	struct inotify_handle *ih = (struct inotify_handle*)fp->f_data;

	/*
	 * filesystem is gone, so set the EOF flag and schedule 
	 * the knote for deletion.
	 */
	if (hint == NOTE_REVOKE) {
		kn->kn_flags |= (EV_EOF | EV_NODATA | EV_ONESHOT);
		return (1);
	}

        return (ih->queue_size > 0);
}

static void
filt_inotifydetach(struct knote *kn)
{
	struct vnode *vp = (struct vnode *)kn->kn_hook;

	lwkt_gettoken(&vp->v_token);
	knote_remove(&vp->v_pollinfo.vpi_kqinfo.ki_note, kn);
	lwkt_reltoken(&vp->v_token);
}


static struct filterops inotifyread_filtops =
	{ FILTEROP_ISFD, NULL, filt_inotifydetach, filt_inotifyread };

int
inotify_kqfilter(struct file *fp, struct knote *kn)
{
	struct vnode *vp = (struct vnode *)kn->kn_hook;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &inotifyread_filtops;
		break;
	default:
		return (EOPNOTSUPP);
	}

	kn->kn_hook = (caddr_t)vp;

	/* XXX: kq token actually protects the list */
	lwkt_gettoken(&vp->v_token);
	knote_insert(&vp->v_pollinfo.vpi_kqinfo.ki_note, kn);
	lwkt_reltoken(&vp->v_token);

	return (0);
}

static struct inotify_watch*
inotify_find_watchwd(struct inotify_handle *ih, int wd)
{	
	struct inotify_watch *iw;

	TAILQ_FOREACH(iw, &ih->wlh, watchlist) {
		if (iw->wd == wd && iw->parent != NULL)
			return iw;
	}
	return (NULL);
}

/*XXX: Index the list by pathname for faster lookup */
static struct inotify_watch*
inotify_find_watch(struct inotify_handle *ih, const char *path)
{	
	struct inotify_watch *iw;

	TAILQ_FOREACH(iw, &ih->wlh, watchlist) {
		if (iw->parent != NULL && strcmp(iw->pathname, path) == 0)
			return (iw);
	}
	return (NULL);
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
	inotify_flags mask = iw->mask;
	intptr_t knel_head;

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
		fflags |= NOTE_MOVED_FROM;
	if (mask & IN_MOVED_TO)
		fflags |= NOTE_MOVED_TO;
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

	knel_head = (intptr_t)&iw->knel;
	EV_SET(kev, iw->wd, EVFILT_VNODE, flags, fflags, knel_head, (void*)iw);
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
			/* directory: file is created, moved in or out */
			/* we just ignore it now */
			result &= ~IN_MODIFY;
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
		/* NOTE: NOTE_WRITE also happens */
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
		} else {
			/* IN_MOVED_FROM case, since we have no direct way to
			 * know for which what that event was triggered.
			 */
			knote_fdclose(iw->fp, iw->handle->wfdp, iw->wd);
			iw->iw_marks |= IW_WATCH_DELETE;
		}
	}
	if (fflags & NOTE_MOVED_FROM) {
		result |= IN_MOVED_FROM;
	}
	if (fflags & NOTE_MOVED_TO) {
		result |= IN_MOVED_TO;
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

static void
inotify_queue_event(struct inotify_watch *iw, inotify_flags mask, inotify_flags hint, const char *filename, int cookie)
{
	struct inotify_queue_entry *iqe;
	struct inotify_handle *ih = iw->handle;
	int namelen = 0;

	if ((iw->mask & IN_ONESHOT) && ((iw->iw_marks & IW_GOT_ONESHOT)
		|| (iw->parent != NULL && iw->parent->iw_marks & IW_GOT_ONESHOT))) {
		return;
	} else if ((mask & hint) == 0) {
		return;
	}

	if (filename != NULL)
		namelen = strlen(filename) + 1;

	iqe = kmalloc(sizeof *iqe + namelen, M_INOTIFY, M_WAITOK);
	iqe->namelen = namelen;
	if (namelen > 0)
		strcpy(iqe->name, filename);

	iqe->iw = iw;
	iqe->mask = hint;
	iqe->cookie = cookie;
	++iw->iw_qrefs;

	if (iw->parent != NULL)
		iw->parent->iw_marks |= IW_GOT_ONESHOT;
	iw->iw_marks |= IW_GOT_ONESHOT;

	TAILQ_INSERT_TAIL(&ih->eventq, iqe, entries);
	++ih->queue_size;
}

static __inline void
inotify_ikap_events(struct inotify_watch *iw, int khint, int inmask,
		struct inotify_kevent_copyin_args *ikap)
{
	struct kevent_note_entry *knep1, *knep2;
	char *fname;

	TAILQ_FOREACH_MUTABLE(knep1, &iw->knel, entries, knep2) {
		if (knep1->hint & khint) {
			fname = (char *)&knep1->data;
			inotify_queue_event(iw, inmask, inmask, fname, knep1->cookie);
			if (khint == NOTE_CREATE) {
				inotify_insert_child_watch(iw, fname);
			} else if (khint == NOTE_MOVED_TO) {
				inotify_insert_child_watch(iw, fname);
			}
			/* clean the data */
			TAILQ_REMOVE(&iw->knel, knep1, entries);
			kfree(knep1, M_KQUEUE);
		}
	}
}

static int
inotify_copyout(void *arg, struct kevent *kevp, int count, int *res)
{
	struct inotify_kevent_copyin_args *ikap;
	struct inotify_handle *ih;
	struct inotify_watch *iw;
	struct kevent *kev;
	inotify_flags rmask;
	int i;

	ikap = (struct inotify_kevent_copyin_args *)arg;
	ih = ikap->handle;

	for (i = 0; i < count; ++i) {
		kev = &kevp[i];
		iw = (struct inotify_watch *)kev->udata;
		inotify_from_kevent(kev, &rmask);

		if (rmask & IN_CREATE)
			inotify_ikap_events(iw, NOTE_CREATE, IN_CREATE, ikap);
		if (rmask & IN_MOVED_FROM)
			inotify_ikap_events(iw, NOTE_MOVED_FROM, IN_MOVED_FROM, ikap);
		if (rmask & IN_MOVED_TO)
			inotify_ikap_events(iw, NOTE_MOVED_TO, IN_MOVED_TO, ikap);

		inotify_queue_event(iw, rmask, IN_OPEN, NULL, 0);
		inotify_queue_event(iw, rmask, IN_ACCESS, NULL, 0);
		inotify_queue_event(iw, rmask, IN_MODIFY, NULL, 0);
		inotify_queue_event(iw, rmask, IN_ATTRIB, NULL, 0);
		inotify_queue_event(iw, rmask, IN_MOVE_SELF, NULL, 0);
		inotify_queue_event(iw, rmask, IN_CLOSE_WRITE, NULL, 0);
		inotify_queue_event(iw, rmask, IN_CLOSE_NOWRITE, NULL, 0);
		inotify_queue_event(iw, rmask, IN_DELETE, NULL, 0);
		inotify_queue_event(iw, rmask, IN_DELETE_SELF, NULL, 0);
		inotify_queue_event(iw, rmask, IN_UNMOUNT, NULL, 0);

		if (rmask & IN_UNMOUNT) {
			if (iw->parent != NULL) {
				inotify_queue_event(iw, IN_IGNORED, IN_IGNORED, NULL, 0);
			} else {
				inotify_queue_event(iw->parent, IN_IGNORED, IN_IGNORED, NULL, 0);
			}
		} else {
			if (rmask & IN_DELETE_SELF) {
				inotify_queue_event(iw, IN_IGNORED, IN_IGNORED, NULL, 0);
			}
		}
		if (rmask & IN_DELETE) {
			iw->iw_marks |= IW_WATCH_DELETE;
		}
	}

	*res += count;
	ikap->count = 0;

	return (0);
}

