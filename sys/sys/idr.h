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
	struct	    spinlock idr_spin;
};

void	*idr_get(struct idr *idp, int id);
void	*idr_replace(struct idr *idp, void *ptr, int id);
void	*idr_remove(struct idr *idp, int id);
void	 idr_remove_all(struct idr *idp);
void	 idr_destroy(struct idr *idp);
int	 idr_for_each(struct idr *idp, int (*fn)(int id, void *p, void *data), void *data);

void	 idr_init(struct idr *idp, int size);
int	 idr_alloc(struct idr *idp, int want, int lim, int *result);
void	 idr_set(struct idr *idp, void *ptr, int id);

void * __inline idr_node(struct idr *idp, int fd)
{
	return idp->idr_nodes[fd];
}

void * __inline idr_data(struct idr *idp, int fd)
{
	return idp->idr_nodes[fd]->data;
}


#endif /* _KERNEL */

#endif /* _IDR_H_ */

