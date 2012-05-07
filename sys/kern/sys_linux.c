#include <linux/inotify.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

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

