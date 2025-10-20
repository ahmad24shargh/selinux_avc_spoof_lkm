#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/security.h>
#include <linux/atomic.h>
#include <linux/kallsyms.h>

// require KPROBES when building as MODULE
#ifdef MODULE
#ifndef CONFIG_KPROBES
#error "Building as LKM requires KPROBES."
#endif
#else
#error "only LKM builds are allowed"
#endif

#include "arch.h"

static u32 su_sid;
static u32 kernel_sid;

// seems this isnt exported on some kernels
typedef int (*secctx_to_secid_fn)(const char *secdata, u32 seclen, u32 *secid);
static secctx_to_secid_fn secctx_to_secid = NULL;

static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	/* 
	 * just pass both arg2 and arg3 to original handler
	 * this removes all the headache.
	 * for < 4.17 int slow_avc_audit(u32 ssid, u32 tsid
	 * for >= 4.17 int slow_avc_audit(struct selinux_state *state, u32 ssid, u32 tsid
	 * for >= 6.4 int slow_avc_audit(u32 ssid, u32 tsid
	 * not to mention theres also DKSU_HAS_SELINUX_STATE
	 * since its hard to make sure this selinux state thing 
	 * cross crossing with 4.17 ~ 6.4's where slow_avc_audit
	 * changes abi (tsid in arg2 vs arg3)
	 * lets just pass both to the handler
	 */

	u32 tsid = (u32)PT_REGS_PARM2(regs);
	if (tsid == su_sid)
		PT_REGS_PARM2(regs) = (u32)kernel_sid;

	tsid = (u32)PT_REGS_PARM3(regs);
	if (tsid == su_sid)
		PT_REGS_PARM3(regs) = (u32)kernel_sid;


	pr_info("avc_spoof/slow_avc_audit: replacing su_sid: %u with kernel_sid: %u\n", su_sid, kernel_sid);
	return 0;
}

static struct kprobe slow_avc_audit_kp = {
	.symbol_name = "slow_avc_audit",
	.pre_handler = slow_avc_audit_pre_handler,
};

static int get_sid(void)
{
	// dont load at all if we cant get sids
	int err = secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: su_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: su_sid: %u\n", su_sid);

	err = secctx_to_secid("u:r:kernel:s0", strlen("u:r:kernel:s0"), &kernel_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: kernel_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: kernel_sid: %u\n", kernel_sid);
	return 0;
}

// https://github.com/ilammy/ftrace-hook/blob/master/ftrace_hook.c
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long retval;

	if (register_kprobe(&kp) < 0) 
		return 0;

	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}

static int __init avc_spoof_init(void) 
{
	pr_info("avc_spoof/init: hello!\n");

	unsigned long addr = lookup_name("security_secctx_to_secid");
	if (!addr) {
		pr_info("avc_spoof/init: security_secctx_to_secid address not found!\n");
		return -EAGAIN;
	}

	pr_info("avc_spoof/init: security_secctx_to_secid found on: 0x%lx\n", addr);	

	// confirm symbol
	char buf[64] = {0};
	sprint_symbol(buf, addr);
	buf[63] = '\0';
	if (!!strncmp(buf, "security_secctx_to_secid", strlen("security_secctx_to_secid"))) {
		pr_info("avc_spoof/init: wrong symbol!? %s found!\n", buf);
		return -EAGAIN;
	}

	pr_info("avc_spoof/init: sprint_symbol 0x%lx: %s\n", addr, buf);
	secctx_to_secid = (secctx_to_secid_fn)addr;

	int ret = get_sid();
	if (ret) {
		pr_info("avc_spoof/init: sid grab fail, unloading!\n");
		return -EAGAIN;
	}

	return 0;
}

static void __exit avc_spoof_exit(void) 
{
	unregister_kprobe(&slow_avc_audit_kp);
	pr_info("avc_spoof/exit: bye!\n");
}

module_init(avc_spoof_init);
module_exit(avc_spoof_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xx");
MODULE_DESCRIPTION("kprobe hooked avc spoofing");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
