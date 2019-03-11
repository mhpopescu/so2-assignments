// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Mihai Popescu mh.popescu12@gmail.com
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

struct list_info_proc {
	char *str;
	struct list_head list;
};

static struct list_head head;

static struct list_info_proc *list_info_alloc(char *str)
{
	struct list_info_proc *ti;

	ti = kmalloc(sizeof(*ti), GFP_KERNEL);
	if (ti == NULL)
		return NULL;

	ti->str = kmalloc(strlen(str) + 1, GFP_KERNEL);
	if (ti->str == NULL)
		return NULL;

	strcpy(ti->str, str);

	return ti;
}

static void list_info_addf(char *str)
{
	struct list_info_proc *ti;

	ti = list_info_alloc(str);
	list_add(&ti->list, &head);
}

static void list_info_adde(char *str)
{
	struct list_info_proc *ti;

	ti = list_info_alloc(str);
	list_add_tail(&ti->list, &head);
}

static void list_info_remove(char *str, int all)
{
	struct list_head *p, *q;
	struct list_info_proc *ti;

	p = NULL;
	q = NULL;

	list_for_each_safe(p, q, &head) {
		ti = list_entry(p, struct list_info_proc, list);
		if (!strcmp(ti->str, str)) {
			list_del(p);
			kfree(ti);
			if (!all)
				return;
		}
	}
}

static void list_info_delf(char *str)
{
	list_info_remove(str, 0);
}

static void list_info_dela(char *str)
{
	list_info_remove(str, 1);
}

static void list_info_purge(void)
{
	struct list_head *p, *q;
	struct list_info_proc *ti;

	p = NULL;
	q = NULL;

	list_for_each_safe(p, q, &head) {
		ti = list_entry(p, struct list_info_proc, list);
		list_del(p);
		kfree(ti);
	}
}

static void list_cmd(char *cmd)
{
	char *type;
	char *str;

	str = strchr(cmd, ' ');
	if (str == NULL)
		return;

	str[0] = '\0';
	str = str + 1;
	type = cmd;

	if (!strcmp(type, "addf"))
		list_info_addf(str);
	else if (!strcmp(type, "adde"))
		list_info_adde(str);
	else if (!strcmp(type, "delf"))
		list_info_delf(str);
	else if (!strcmp(type, "dela"))
		list_info_dela(str);
}


static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *p;
	struct list_info_proc *ti;

	p = NULL;

	list_for_each(p, &head) {
		ti = list_entry(p, struct list_info_proc, list);
		seq_puts(m, ti->str);
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	list_cmd(local_buffer);
	return local_buffer_size;
}

static const struct file_operations r_fops = {
	.owner		= THIS_MODULE,
	.open		= list_read_open,
	.read		= seq_read,
	.release	= single_release,
};

static const struct file_operations w_fops = {
	.owner		= THIS_MODULE,
	.open		= list_write_open,
	.write		= list_write,
	.release	= single_release,
};

static int list_init(void)
{
	INIT_LIST_HEAD(&head);

	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_fops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_fops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	list_info_purge();
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Mihai Popescu mh.popescu12@gmail.com");
MODULE_LICENSE("GPL v2");
