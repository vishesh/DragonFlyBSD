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

/*
 * inotify interface
 */

#ifndef _DF_BSD_INOTIFY_H
#define _DF_BSD_INOTIFY_H

#include <sys/filedesc.h>
#include <sys/stdint.h>
#include <sys/types.h>

struct inotify_event {
	int		wd;
	uint32_t	mask;
	uint32_t	cookie;
	uint32_t	len;
	char		name[0];
};

enum INOTIFY_FLAGS {
	IN_ACCESS	    =	0x00000001,
	IN_MODIFY	    =	0x00000002,
	IN_ATTRIB	    =	0x00000004,
	IN_CLOSE_WRITE	    =	0x00000008,
	IN_CLOSE_NOWRITE    =	0x00000010,
	IN_OPEN		    =	0x00000020,
	IN_MOVED_FROM	    =	0x00000040,
	IN_MOVED_TO	    =	0x00000080,
	IN_CREATE	    =	0x00000100,
	IN_DELETE	    =	0x00000200,
	IN_DELETE_SELF	    =	0x00000400,
	IN_MOVE_SELF	    =	0x00000800,
	IN_UNMOUNT	    =	0x00002000,
	IN_Q_OVERFLOW	    =	0x00004000,
	IN_IGNORED	    =	0x00008000,
	IN_ONLYDIR	    =	0x01000000,
	IN_DONT_FOLLOW	    =	0x02000000,
	IN_MASK_ADD	    =	0x20000000,
	IN_ISDIR	    =	0x40000000,
	IN_ONESHOT	    =	0x80000000,

	IN_CLOSE	    =	(IN_CLOSE_WRITE | IN_CLOSE_NOWRITE),
	IN_MOVE		    =	(IN_MOVED_FROM | IN_MOVED_TO),

	IN_ALL_EVENTS	    =	(IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
				 IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM |
				 IN_MOVED_TO | IN_DELETE | IN_CREATE | IN_DELETE_SELF | \
				 IN_MOVE_SELF)
};


/*
 *#define IN_ACCESS		0x00000001
 *#define IN_MODIFY		0x00000002
 *#define IN_ATTRIB		0x00000004
 *#define IN_CLOSE_WRITE		0x00000008
 *#define IN_CLOSE_NOWRITE	0x00000010
 *#define IN_OPEN			0x00000020
 *#define IN_MOVED_FROM		0x00000040
 *#define IN_MOVED_TO		0x00000080
 *#define IN_CREATE		0x00000100
 *#define IN_DELETE		0x00000200
 *#define IN_DELETE_SELF		0x00000400
 *#define IN_MOVE_SELF		0x00000800
 *#define IN_UNMOUNT		0x00002000
 *#define IN_Q_OVERFLOW		0x00004000
 *#define IN_IGNORED		0x00008000
 *#define IN_ONLYDIR		0x01000000
 *#define IN_DONT_FOLLOW		0x02000000
 *#define IN_MASK_ADD		0x20000000
 *#define IN_ISDIR		0x40000000
 *#define IN_ONESHOT		0x80000000
 *
 *#define IN_CLOSE		(IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)
 *#define IN_MOVE			(IN_MOVED_FROM | IN_MOVED_TO)
 *
 *#define IN_ALL_EVENTS	(IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | \
 *                         IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | \
 *                         IN_MOVED_TO | IN_DELETE | IN_CREATE | IN_DELETE_SELF | \
 *                         IN_MOVE_SELF)
 */

/* Kernel API */ 
#ifdef _KERNEL

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
	struct inotify_watch  *parent;
	TAILQ_ENTRY(inotify_watch) watchlist;
};

#endif	/* _KERNEL */

/* User API */
#if !defined(_KERNEL)

#include <sys/cdefs.h>

__BEGIN_DECLS
int	inotify_init (void);
int	inotify_init1 (int flags);
int	inotify_add_watch(int fd, const char *pathname, uint32_t mask);
int	inotify_rm_watch(int fd, int wd);
__END_DECLS
#endif /* !_KERNEL */

#endif	/* _DF_BSD_INOTIFY_H */

