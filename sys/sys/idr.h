/*
 * Copyright (c) 2005-2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Jeffrey Hsu.
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

/**
 * IDR is a small Integer ID management library that provides an interface to
 * map integers with some pointer that can later be retrieved.
 *
 * Usage:
 *
 * 1. Create a new IDR object and initialize it using idr_init()
 * 2. Allocate a new integer using idr_alloc(). Do use the spinlock here.
 * 3. Set it to a pointer using idr_set()
 * 4. Get the pointer mapped by given integer using idr_get()
 *
 * Pointer mapped by integer can't be NULL.
 *
 */


#ifndef _IDR_H_
#define _IDR_H_

#ifdef _KERNEL

#include <sys/spinlock.h>

struct idr_node {
	void	*data;
	char	 reserved;
	int	 allocated;
};

struct idr {
	struct	    idr_node *idr_nodes;
	int	    idr_count;
	int	    idr_lastindex;
	int	    idr_freeindex;
	int	    idr_nexpands;
	int	    idr_maxwant;
	struct	    spinlock idr_spin;
};

void	*idr_find(struct idr *idp, int id);
void	*idr_replace(struct idr *idp, void *ptr, int id);
void	 idr_remove(struct idr *idp, int id);
void	 idr_remove_all(struct idr *idp);
void	 idr_destroy(struct idr *idp);
int	 idr_for_each(struct idr *idp, int (*fn)(int id, void *p, void *data), void *data);
int	 idr_get_new(struct idr *idp, void *ptr, int *id);
int	 idr_get_new_above(struct idr *idp, void *ptr, int sid, int *id);
int	 idr_pre_get(struct idr *idp);

void	 idr_init1(struct idr *idp, int size);
void	 idr_init(struct idr *idp);


#endif /* _KERNEL */

#endif /* _IDR_H_ */

