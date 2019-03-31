// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Mihai Popescu mh.popescu12@gmail.com
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#include "tracer.h"

#define NBITS 6
#define NKRET_PROBES 2

#define IDX_KMALLOC		1
#define IDX_KFREE		2
#define IDX_KMALLOC_MEM 3
#define IDX_KFREE_MEM	4
#define IDX_SCHED		5
#define IDX_UP			6
#define IDX_DOWN		7
#define IDX_LOCK		8
#define IDX_UNLOCK		9

struct proc_data {
	int pid, kmalloc, kfree, kmalloc_mem, kfree_mem,
		sched, up, down, lock, unlock;
	struct hlist_node hnode;
};

DEFINE_HASHTABLE(hhead, NBITS);

static struct proc_data *new_proc_data(pid_t pid)
{
	struct proc_data *pd;

	pd = kmalloc(sizeof(struct proc_data), GFP_KERNEL);
	if (pd == NULL)
		return NULL;

	memset(pd, 0, sizeof(struct proc_data));
	pd->pid = pid;
	
	return pd;
}

static int tracer_show(struct seq_file *m, void *v)
{
	struct proc_data *pd;
	int bkt = 0;
	char buf[120];

	seq_puts(m, "PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\tlock\tunlock\n");
	pr_info("PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\tlock\tunlock\n");

	hash_for_each(hhead, bkt, pd, hnode) {
		sprintf(buf, "%d\t%d\t%d\t%d\t\t%d\t\t%d\t%d\t%d\t%d\t%d\t\n", pd->pid, pd->kmalloc, pd->kfree, 
			pd->kmalloc_mem, pd->kfree_mem, pd->sched, pd->up, pd->down, pd->lock, pd->unlock);
		seq_puts(m, buf);
		pr_info("%s\n",buf);
	}
	return 0;
}

static int tracer_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_show, NULL);
}


static long
tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct proc_data *pd;
	struct hlist_node *tmp;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pd = new_proc_data(arg);
		hash_add(hhead, &pd->hnode, arg);
		break;
	case TRACER_REMOVE_PROCESS:
		hash_for_each_possible_safe(hhead, pd, tmp, hnode, arg) {
			hash_del(&pd->hnode);
			kfree(pd);
		}
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations tracer_dev_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl = tracer_ioctl,
};

static struct miscdevice tracer_misc = {
    .minor 		= TRACER_DEV_MINOR,
    .name 		= TRACER_DEV_NAME,
    .fops 		= &tracer_dev_fops,
};

static const struct file_operations tracer_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= tracer_open,
	.read		= seq_read,
	.release	= single_release,
};

struct proc_dir_entry *proc_file_entry;

static void inc_counter(int pid, int idx) {
	struct proc_data *pd;
	hash_for_each_possible(hhead, pd, hnode, pid) {
		if (pd->pid != pid)
			continue;
		((int *) pd)[idx]++;
		pr_info("%d\n", ((int *) pd)[idx]);
		break;
	}
}

/* -------------- Probes ------------------- */

static int up_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int pid = current->pid;
	inc_counter(pid, IDX_UP);

	return 0;
}

static int down_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int pid = current->pid;
	inc_counter(pid, IDX_DOWN);

	return 0;
}


/* -------------- Probes ------------------- */

// static int up_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
// {
// 	struct proc_data *pd;
// 	int pid = current->pid;
// 	hash_for_each_possible(hhead, pd, hnode, pid) {
// 		if (pd->pid != pid)
// 			continue;
// 		pd->up++;
// 		break;
// 	}
// 	return 0;
// }

// static int down_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
// {
// 	struct proc_data *pd;
// 	int pid = current->pid;
// 	hash_for_each_possible(hhead, pd, hnode, pid) {
// 		if (pd->pid != pid)
// 			continue;
// 		pd->down++;
// 		break;
// 	}

// 	return 0;
// }


struct kretprobe **probes = (struct kretprobe *[]) {
	& (struct kretprobe) {
       .entry_handler = up_probe_handler,
       .maxactive = 32,
       .kp.symbol_name = "up",
	},
	& (struct kretprobe) {
       .entry_handler = down_probe_handler,
       .maxactive = 32,
       .kp.symbol_name = "down_interruptible",
	},
};

/* -------------- End Probes --------------- */

static int tracer_init(void)
{
	int err;

	err = misc_register(&tracer_misc);
	if (err != 0) {
		pr_err("misc_register failed: %d\n", err);
		return err;
	}

	proc_file_entry = proc_create(TRACER_DEV_NAME, 0, NULL, &tracer_proc_fops);
	if(proc_file_entry == NULL) {
		pr_err("proc_create failed: \n");
		return -ENOMEM;
	}

	err = register_kretprobes(probes, NKRET_PROBES);
	if (err < 0) {
		printk(KERN_INFO "register_kretprobes failed, returned %d\n",
				err);
		return -1;
	}

	hash_init(hhead);

	pr_notice("Driver %s loaded\n", TRACER_DEV_NAME);
	return 0;
}

static void tracer_exit(void)
{
	misc_deregister(&tracer_misc);
	proc_remove(proc_file_entry);

	unregister_kretprobes(probes, NKRET_PROBES);
	printk(KERN_INFO "kretprobes unregistered\n");

	pr_notice("Driver %s unloaded\n", TRACER_DEV_NAME);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Mihai Popescu mh.popescu12@gmail.com");
MODULE_LICENSE("GPL v2");
