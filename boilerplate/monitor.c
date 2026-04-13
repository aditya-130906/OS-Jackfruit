#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/spinlock.h>

#include "monitor_ioctl.h"

#define DEVICE_NAME "container_monitor"
#define CHECK_INTERVAL_SEC 1

struct monitored_entry {
    pid_t pid;
    char container_id[MONITOR_NAME_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int soft_warned;
    struct list_head list;
};

static LIST_HEAD(monitored_list);
static DEFINE_SPINLOCK(monitored_lock); 

static struct timer_list monitor_timer;
static dev_t dev_num;
static struct cdev c_dev;
static struct class *cl;

static long get_rss_bytes(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    long rss_pages = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -1;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (mm) {
        rss_pages = get_mm_rss(mm);
        mmput(mm);
    }
    put_task_struct(task);

    return rss_pages * PAGE_SIZE;
}

static void log_soft_limit_event(const char *container_id, pid_t pid, unsigned long limit_bytes, long rss_bytes)
{
    printk(KERN_WARNING "[container_monitor] SOFT LIMIT container=%s pid=%d rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

static void kill_process(const char *container_id, pid_t pid, unsigned long limit_bytes, long rss_bytes)
{
    struct task_struct *task;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        send_sig(SIGKILL, task, 1);
    rcu_read_unlock();

    printk(KERN_WARNING "[container_monitor] HARD LIMIT container=%s pid=%d rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

static void timer_callback(struct timer_list *t)
{
    struct monitored_entry *entry, *tmp;
    unsigned long flags;
    long rss;

    spin_lock_irqsave(&monitored_lock, flags);
    list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
        rss = get_rss_bytes(entry->pid);
        if (rss < 0) {
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        if (rss >= entry->hard_limit_bytes) {
            kill_process(entry->container_id, entry->pid, entry->hard_limit_bytes, rss);
            list_del(&entry->list);
            kfree(entry);
        } else if (rss >= entry->soft_limit_bytes && !entry->soft_warned) {
            log_soft_limit_event(entry->container_id, entry->pid, entry->soft_limit_bytes, rss);
            entry->soft_warned = 1;
        } else if (rss < entry->soft_limit_bytes) {
            entry->soft_warned = 0;
        }
    }
    spin_unlock_irqrestore(&monitored_lock, flags);

    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
}

static long
