#include <sys/linux/inotify.h>
#include <sys/file.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/types.h>


MALLOC_DEFINE(M_INOTIFY, "inotify", "Linux inotify system");

struct inotify_handle {
	int		 fd;
	struct file	*fp;
	unsigned int	 event_count;
	unsigned int	 max_events;
	unsigned int	 queue_size;
	struct inotify_watch *watches;
};

struct inotify_watch {
	int		 wd;
	struct file	*fp;
	struct vnode	*vp;
	struct inotify_handle *handle;
	SLIST_ENTRY(inotify_watch) watchlist;
};

int
sys_inotify_init(struct inotify_init_args *args)
{
	kprintf("syscall => inotify_init");
	return 0;
}

int
sys_inotify_init1(struct inotify_init1_args *args)
{
	kprintf("syscall => inotify_init1");
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


