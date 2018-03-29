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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vewe Richard");

#define ARCH_ARM

typedef struct stCallstack {
    char function_name[100];
    unsigned int times;
    unsigned int enable;

    unsigned int count;

    struct kobject * kobj;
    struct kprobe kp;
}Callstack;

static Callstack _callstack = {
    .function_name = "",
    .times = 1,
    .enable = 0
};

static Callstack *_pCallstack = &_callstack;

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#if 0
    struct thread_info * td;
    struct stackframe sf;
    struct task_struct * tsk;
#endif
    

    printk("kprobe function (%s) in handler_pre(), for %d times(left: %d)\n", 
            _pCallstack->function_name, _pCallstack->times, _pCallstack->count);

#if 0
    td = (struct thread_info *)(regs->ARM_sp & ~(THREAD_SIZE - 1));
    tsk = td->task;

    printk("task pid: %d\n", tsk->pid);
    printk("stack %p\n", tsk->stack);
    printk("name %s\n", tsk->comm);
    sf.fp = regs->ARM_fp;
    sf.sp = regs->ARM_sp;
    sf.lr = regs->ARM_lr;
    sf.pc = regs->ARM_pc;
    trace_printk("kprobe start jiangjqian\n");
    walk_stackframe(&sf, print_frame, NULL);
    trace_printk("kprobe end jiangjqian\n");
#endif

    if(_pCallstack->count > 0)
    {
        _pCallstack->count --;
    }

    if(_pCallstack->count == 0)
    {
        if(_pCallstack->enable)
        {
            unregister_kprobe(&_pCallstack->kp);
        }
        _pCallstack->enable = 0;
    }
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
    if(_pCallstack->enable)
    {
        unregister_kprobe(&_pCallstack->kp);
    }

    sscanf(buf, "%u", &(_pCallstack->enable));
    if(_pCallstack->enable)
    {
	int ret;
        struct kprobe * kp;

        kp = &_pCallstack->kp;

        kp->symbol_name = _pCallstack->function_name;
	kp->pre_handler = handler_pre;
	kp->post_handler = handler_post;
	kp->fault_handler = handler_fault;

	ret = register_kprobe(kp);
        _pCallstack->count = _pCallstack->times;
	if (ret < 0) {
            _pCallstack->enable = 0;
	}
    }
    return count;
}


static struct kobj_attribute times_attribute =
    __ATTR(times, 0666, times_show,
           (void*)times_store);

static struct kobj_attribute function_name_attribute =
    __ATTR(function_name, 0666, name_show,
           (void*)name_store);

static struct kobj_attribute enable_attribute =
    __ATTR(enable, 0666, enable_show,
           (void*)enable_store);

static int __init mymodule_init (void)
{
    int error = 0;

    printk("mymodule: initialised\n");

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
    printk("mymodule: Exit success\n");
    kobject_put(_pCallstack->kobj);
    if(_pCallstack->enable)
    {
        printk("unregister kprobe\n");
        unregister_kprobe(&_pCallstack->kp);
    }
}

module_init(mymodule_init);
module_exit(mymodule_exit);
