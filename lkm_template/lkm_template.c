#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/uaccess.h>

// require KPROBES when building as MODULE
#ifdef MODULE
#ifndef CONFIG_KPROBES
#error "Building as LKM requires KPROBES."
#endif
#endif

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#include "arch.h"
#define HANDLER_TYPE static int
#else
#define HANDLER_TYPE int // to allow extern def
#endif

// SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
//		void __user *, arg)
// lkm_handle_sys_reboot(magic1, magic2, cmd, arg);
// PLAN
// magic1 main magic
// magic2 command
// arg, data input

#define DEF_MAGIC 0x12345678
#define UNLOAD 0
#define PRINT_ARG 1

struct basic_payload {
	unsigned long reply_ptr;
	char text[256];
};

HANDLER_TYPE template_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	if (magic1 != DEF_MAGIC)
		return 0;

	int ok = DEF_MAGIC; // we just write magic on reply

	pr_info("LKM: intercepted call! magic: 0x%d id: 0x%d\n", magic1, magic2);

	if (magic2 == PRINT_ARG) {
		struct basic_payload basic = {0};
		if (copy_from_user(&basic, arg, sizeof(struct basic_payload)))
			return 0;

		basic.text[255] = '\0';
		pr_info("LKM: print %s\n", basic.text);

		if (copy_to_user((void __user *)basic.reply_ptr, &ok, sizeof(ok)))
			return 0;
	}

	return 0;
}

#ifdef CONFIG_KPROBES
static int sys_reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	int cmd = (int)PT_REGS_PARM3(real_regs);
	void __user *arg = (void __user *)PT_REGS_SYSCALL_PARM4(real_regs);

	return template_handle_sys_reboot(magic1, magic2, cmd, arg);
}

static struct kprobe sys_reboot_kp = {
	.symbol_name = SYS_REBOOT_SYMBOL,
	.pre_handler = sys_reboot_handler_pre,
};
#endif

static int __init lkm_template_init(void) 
{
	pr_info("LKM: init with magic: 0x%d\n", (int)DEF_MAGIC);
#ifdef CONFIG_KPROBES
	int ret = register_kprobe(&sys_reboot_kp);
	pr_info("LKM: register sys_reboot kprobe: %d\n", ret);
#endif
	return 0;
}

static void __exit lkm_template_exit(void) 
{
#ifdef CONFIG_KPROBES
	unregister_kprobe(&sys_reboot_kp);
#endif
	pr_info("LKM: unload\n");
}

module_init(lkm_template_init);
module_exit(lkm_template_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xx");
MODULE_DESCRIPTION("lkm template");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
