/*
 * kernel debug: to show callstack using kprobe
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <asm/stacktrace.h>
#include <linux/delay.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vewe Richard");

#define ARCH_ARM

typedef struct stCallstack {
    char function_name[100];
    unsigned int times;
    unsigned int enable;

    unsigned int count;

    struct kobject * kobj;
    struct kprobe * kp;
}Callstack;

static Callstack _callstack = {
    .function_name = "",
    .times = 1,
    .enable = 0
};

static Callstack *_pCallstack = &_callstack;

static int print_frame(struct stackframe *sf, void *data)
{
    printk("fp: %pS, sp:%pS, lr: %pS, pc: %pS\n", (void *)sf->fp, (void *)sf->sp, (void *)sf->lr, (void *)sf->pc);
    return 0;
}

/* kprobe pre_handler: called just before the probed instruction is executed */
//Note: can not call unregister_kprobe inside the pre handler
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef ARCH_ARM
    struct thread_info * td;
    struct stackframe sf;
    struct task_struct * tsk;
#endif
    
    if(_pCallstack->count <= 0) return 0;

    _pCallstack->count --;

    printk("kprobe function (%s) in handler_pre(), for %d times(left: %d)\n", 
            _pCallstack->function_name, _pCallstack->times, _pCallstack->count);

#ifdef ARCH_ARM
    td = (struct thread_info *)(regs->ARM_sp & ~(THREAD_SIZE - 1));
    tsk = td->task;

    printk("task pid: %d, name %s\n", tsk->pid, tsk->comm);

    sf.fp = regs->ARM_fp;
    sf.sp = regs->ARM_sp;
    sf.lr = regs->ARM_lr;
    sf.pc = regs->ARM_pc;
    walk_stackframe(&sf, print_frame, NULL);
#endif
    return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	return 0;
}


static ssize_t times_show(struct kobject *kobj,
                               struct kobj_attribute *attr,
                               char *buf)
{
    return sprintf(buf, "%u\n", _pCallstack->times);
}

static ssize_t times_store(struct kobject *kobj,
                                struct kobj_attribute *attr,
                                char *buf, size_t count)
{
    sscanf(buf, "%u", &(_pCallstack->times));
    return count;
}

static ssize_t name_show(struct kobject *kobj,
                               struct kobj_attribute *attr,
                               char *buf)
{
    return sprintf(buf, "%s\n", _pCallstack->function_name);
}

static ssize_t name_store(struct kobject *kobj,
                                struct kobj_attribute *attr,
                                char *buf, size_t count)
{
    sscanf(buf, "%s", _pCallstack->function_name);
    return count;
}

static ssize_t enable_show(struct kobject *kobj,
                               struct kobj_attribute *attr,
                               char *buf)
{
    return sprintf(buf, "%u\n", _pCallstack->enable);
}

static ssize_t enable_store(struct kobject *kobj,
                                struct kobj_attribute *attr,
                                char *buf, size_t count)
{
    unsigned int enable;
    int ret;
    struct kprobe * kp;

    sscanf(buf, "%u", &enable);
    if(enable == 1)
    {
        if(_pCallstack->kp)
        {
            printk("callstack: please disable previous kprobe first (echo 0 > /sys/kernel/callstack/enable)");
            return -1;
        }

        _pCallstack->kp = (struct kprobe *)kmalloc(sizeof(struct kprobe), GFP_KERNEL);
        if(_pCallstack->kp == NULL)
        {
            printk("callstack: lack of memory\n");
            return -1;
        }

        memset(_pCallstack->kp, 0, sizeof(struct kprobe));

        kp = _pCallstack->kp;

        kp->symbol_name = _pCallstack->function_name;
	kp->pre_handler = handler_pre;
	kp->post_handler = handler_post;
	kp->fault_handler = handler_fault;

	ret = register_kprobe(kp);
        _pCallstack->count = _pCallstack->times;
	if (ret < 0) {
            printk("callstack: register kprobe failed %d\n", ret);
            kfree(_pCallstack->kp);
            _pCallstack->kp = NULL;
            _pCallstack->enable = 0;
	}
        else
        {
            printk("callstack: register kprobe success\n");
            _pCallstack->enable = 1;
        }
    }
    else if(enable == 0)
    {
        if(_pCallstack->kp)
        {
            unregister_kprobe(_pCallstack->kp);
            kfree(_pCallstack->kp);
            _pCallstack->kp = NULL;
            printk("callstack: kprobe unregister\n");
            _pCallstack->enable = 0;
        }
    }
    else
    {
        printk("callstack: invalid input to enable, only 0 and 1 are allowed\n");
        return -1;
    }
    return count;
}


static struct kobj_attribute times_attribute =
    __ATTR(times, 0660, times_show,
           (void*)times_store);

static struct kobj_attribute function_name_attribute =
    __ATTR(function_name, 0660, name_show,
           (void*)name_store);

static struct kobj_attribute enable_attribute =
    __ATTR(enable, 0660, enable_show,
           (void*)enable_store);

static int __init mymodule_init (void)
{
    int error = 0;

    printk("callstack: initialised\n");

    _pCallstack->kobj =
        kobject_create_and_add("callstack", kernel_kobj);
    if (!_pCallstack->kobj)
        return -ENOMEM;

    error = sysfs_create_file(_pCallstack->kobj, &times_attribute.attr);
    if (error) {
        printk("failed to create the times file " \
                "in /sys/kernel/callstack\n");
    }

    error = sysfs_create_file(_pCallstack->kobj, &function_name_attribute.attr);
    if (error) {
        printk("failed to create the function_name file " \
                "in /sys/kernel/callstack\n");
    }

    error = sysfs_create_file(_pCallstack->kobj, &enable_attribute.attr);
    if (error) {
        printk("failed to create the enable file " \
                "in /sys/kernel/callstack\n");
    }

    return error;
}

static void __exit mymodule_exit (void)
{
    printk("callstack: Exit success\n");
    kobject_put(_pCallstack->kobj);
    if(_pCallstack->kp)
    {
        printk("callstack: unregister kprobe\n");
        unregister_kprobe(_pCallstack->kp);
        kfree(_pCallstack->kp);
    }
}

module_init(mymodule_init);
module_exit(mymodule_exit);
