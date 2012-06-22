#include <sys/idr.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/spinlock2.h>

MALLOC_DEFINE(M_IDR, "idr", "Integer ID management");

static void  idr_grow(struct idr *idp, int want);
static void  idr_reserve(struct idr *idp, int id, int incr);

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

static void
idr_reserve(struct idr *idp, int id, int incr)
{
	while (id >= 0) {
		idp->idr_nodes[id].allocated += incr;
		KKASSERT(idp->idr_nodes[id].allocated >= 0);
		id = left_ancestor(id);
	}
}

static __inline
void
idrfixup(struct idr *idp, int id)
{
	if (id < idp->idr_freeindex) {
	       idp->idr_freeindex = id;
	}
	while (idp->idr_lastindex >= 0 &&
	       idp->idr_nodes[idp->idr_lastindex].data == NULL &&
	       idp->idr_nodes[idp->idr_lastindex].reserved == 0
	) {
		--idp->idr_lastindex;
	}
}

static __inline
struct idr_node *
idr_get_node(struct idr *idp, int id)
{
	struct idr_node *idrnp;
	KKASSERT((unsigned)id < idp->idr_count);
	idrnp = &idp->idr_nodes[id];
	KKASSERT(idrnp->data != NULL);
	KKASSERT(idrnp->allocated > 0);
	return idrnp;
}

int
idr_alloc(struct idr *idp, int want, int lim, int *result)
{
	int id, rsize, rsum, node;
	
	spin_lock(&idp->idr_spin);
	if (want >= idp->idr_count)
		idr_grow(idp, want);

	/*
	 * Search for a free descriptor starting at the higher
	 * of want or fd_freefile.  If that fails, consider
	 * expanding the ofile array.
	 *
	 * NOTE! the 'allocated' field is a cumulative recursive allocation
	 * count.  If we happen to see a value of 0 then we can shortcut
	 * our search.  Otherwise we run through through the tree going
	 * down branches we know have free descriptor(s) until we hit a
	 * leaf node.  The leaf node will be free but will not necessarily
	 * have an allocated field of 0.
	 */
retry:
	/* move up the tree looking for a subtree with a free node */
	for (id = max(want, idp->idr_freeindex); id < min(idp->idr_count, lim);
	     id = right_ancestor(id)) {
		if (idp->idr_nodes[id].allocated == 0)
			goto found;

		rsize = right_subtree_size(id);
		if (idp->idr_nodes[id].allocated == rsize)
			continue;	/* right subtree full */

		/*
		 * Free fd is in the right subtree of the tree rooted at fd.
		 * Call that subtree R.  Look for the smallest (leftmost)
		 * subtree of R with an unallocated fd: continue moving
		 * down the left branch until encountering a full left
		 * subtree, then move to the right.
		 */
		for (rsum = 0, rsize /= 2; rsize > 0; rsize /= 2) {
			node = id + rsize;
			rsum += idp->idr_nodes[node].allocated;
			if (idp->idr_nodes[id].allocated == rsum + rsize) {
				id = node;	/* move to the right */
				if (idp->idr_nodes[node].allocated == 0)
					goto found;
				rsum = 0;
			}
		}
		goto found;
	}

	/*
	 * No space in current array.  Expand?
	 */
	if (idp->idr_count >= lim) {
		spin_unlock(&idp->idr_spin);
		return (EMFILE);
	}
	idr_grow(idp, want);
	goto retry;

found:
	KKASSERT(id < idp->idr_count);
	if (id > idp->idr_lastindex)
		idp->idr_lastindex = id;
	if (want <= idp->idr_freeindex)
		idp->idr_freeindex = id;
	*result = id;
	KKASSERT(idp->idr_nodes[id].data == NULL);
	KKASSERT(idp->idr_nodes[id].reserved == 0);
	idp->idr_nodes[id].reserved = 1;
	idr_reserve(idp, id, 1);
	spin_unlock(&idp->idr_spin);
	return (0);
}

/*
 * Grow the file table so it can hold through descriptor (want).
 *
 * The fdp's spinlock must be held exclusively on entry and may be held
 * exclusively on return.  The spinlock may be cycled by the routine.
 *
 * MPSAFE
 */
static void
idr_grow(struct idr *idp, int want)
{
	struct idr_node *newnodes;
	struct idr_node *oldnodes;
	int nf, extra;

	nf = idp->idr_count;
	do {
		/* nf has to be of the form 2^n - 1 */
		nf = 2 * nf + 1;
	} while (nf <= want);

	spin_unlock(&idp->idr_spin);
	newnodes = kmalloc(nf * sizeof(struct idr_node), M_IDR, M_WAITOK);
	spin_lock(&idp->idr_spin);

	/*
	 * We could have raced another extend while we were not holding
	 * the spinlock.
	 */
	if (idp->idr_count >= nf) {
		spin_unlock(&idp->idr_spin);
		kfree(newnodes, M_IDR);
		spin_lock(&idp->idr_spin);
		return;
	}
	/*
	 * Copy the existing ofile and ofileflags arrays
	 * and zero the new portion of each array.
	 */
	extra = nf - idp->idr_count;
	bcopy(idp->idr_nodes, newnodes, idp->idr_count * sizeof(struct idr_node));
	bzero(&newnodes[idp->idr_count], extra * sizeof(struct idr_node));

	oldnodes = idp->idr_nodes;
	idp->idr_nodes = newnodes;
	idp->idr_count = nf;

	spin_unlock(&idp->idr_spin);
	kfree(oldnodes, M_IDR);
	spin_lock(&idp->idr_spin);

	idp->idr_nexpands++;
}

void *
idr_remove(struct idr *idp, int id)
{	
	void *ptr;

	if ((unsigned)id >= idp->idr_count)
		return (NULL);
	if ((ptr = idp->idr_nodes[id].data) == NULL)
		return (NULL);
	idp->idr_nodes[id].data = NULL;

	idr_reserve(idp, id, -1);
	idrfixup(idp, id);

	return (ptr);

}

void
idr_remove_all(struct idr *idp)
{
}

void
idr_destroy(struct idr *idp)
{
	kfree(idp->idr_nodes, M_IDR);
}

void *
idr_get(struct idr *idp, int id)
{
	KKASSERT((unsigned)id < idp->idr_count);
	KKASSERT(idp->idr_nodes[id].allocated > 0);
	KKASSERT(idp->idr_nodes[id].data == 0);
	return idp->idr_nodes[id].data;
}

void
idr_set(struct idr *idp, void *ptr, int id)
{
	KKASSERT((unsigned)id < idp->idr_count);
	KKASSERT(idp->idr_nodes[id].reserved != 0);
	if (ptr) {
		idp->idr_nodes[id].data = ptr;
		idp->idr_nodes[id].reserved = 0;
	} else {
		idp->idr_nodes[id].reserved = 0;
		idr_reserve(idp, id, -1);
		idrfixup(idp, id);
	}
}

int
idr_for_each(struct idr *idp, int (*fn)(int id, void *p, void *data), void *data)
{
	return (0);
}

void *
idr_replace(struct idr *idp, void *ptr, int id)
{
	struct idr_node *idrnp;
	void *ret;

	idrnp = idr_get_node(idp, id);

	if (idrnp == NULL || ptr == NULL)
		return NULL;

	ret = idrnp->data;
	idrnp->data = ptr;

	return (ret);
}

void
idr_init(struct idr *idp, int size)
{
	memset(idp, 0, sizeof(struct idr));
	idp->idr_nodes = kmalloc(size * sizeof *idr, M_IDR, M_WAITOK | M_ZERO);
	idp->idr_count = size;
	idp->idr_lastindex = -1;
	spin_init(&idp->idr_spin);
}

