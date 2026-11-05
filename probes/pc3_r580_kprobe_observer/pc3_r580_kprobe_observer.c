// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>

#if defined(CONFIG_X86_64)
#include <asm/processor-flags.h>
#include <asm/ptrace.h>
#else
#error "the PC3 R580 observer requires x86-64 kprobe argument access"
#endif

#define PC3_R580_TARGET "nvidia:rm_init_adapter"
#define PC3_R580_SELECTOR_TARGET "nvidia:_nv000790rm"
#define PC3_R580_LOOKUP_TARGET "nvidia:_nv031399rm"
#define PC3_R580_LOOKUP_CALL_TARGET "nvidia:_nv031364rm"
#define PC3_R580_LOOKUP_CALL_OFFSET 0x92UL
#define PC3_R580_LOOKUP_CALL_LENGTH 5UL
#define PC3_R580_LOOKUP_BRANCH_TARGET "nvidia:_nv031364rm"
#define PC3_R580_LOOKUP_BRANCH_OFFSET 0xd7eUL
#define PC3_R580_LOOKUP_BRANCH_DECISION_OFFSET 0xa81UL
#define PC3_R580_LOOKUP_JOIN_PREDECESSOR_COUNT 5
#define NV_STATE_FLAGS_OFFSET 0x10UL
#define NV_STATE_DISPLAY_SOC_CHIP_ID_OFFSET 0x274UL

static bool arm;
module_param(arm, bool, 0400);
MODULE_PARM_DESC(arm, "Insert the kprobe breakpoint (default: disabled registration only)");

static bool capture_state;
module_param(capture_state, bool, 0400);
MODULE_PARM_DESC(capture_state,
	"Opt in to nofault reads of nv_state_t.flags and disp_sw_soc_chip_id");

static bool observe_selector_path;
module_param(observe_selector_path, bool, 0400);
MODULE_PARM_DESC(observe_selector_path,
	"Opt in to fixed count-only probes for the R580 selector and descriptor lookup routines");

static bool capture_selector;
module_param(capture_selector, bool, 0400);
MODULE_PARM_DESC(capture_selector,
	"Opt in to capture _nv031399rm's second argument as one 32-bit scalar");

static bool capture_lookup_callsite;
module_param(capture_lookup_callsite, bool, 0400);
MODULE_PARM_DESC(capture_lookup_callsite,
	"Opt in to capture the three arguments at the pinned _nv031364rm callsite");

static bool capture_lookup_branch;
module_param(capture_lookup_branch, bool, 0400);
MODULE_PARM_DESC(capture_lookup_branch,
	"Opt in to a count-only probe at the pinned _nv031364rm branch target");

static bool capture_lookup_return_site;
module_param(capture_lookup_return_site, bool, 0400);
MODULE_PARM_DESC(capture_lookup_return_site,
	"Opt in to a hidden return-site comparison at _nv031399rm entry");

static bool capture_lookup_join_route;
module_param(capture_lookup_join_route, bool, 0400);
MODULE_PARM_DESC(capture_lookup_join_route,
	"Opt in to fixed predecessor counters plus the hidden lookup return-site comparison");

static bool lookup_return_site_ready;
module_param(lookup_return_site_ready, bool, 0400);

static unsigned long long owner_nonce;
module_param(owner_nonce, ullong, 0400);
MODULE_PARM_DESC(owner_nonce, "Private runner ownership token used for safe cleanup");

static atomic64_t hit_count = ATOMIC64_INIT(0);
static atomic64_t state_read_count = ATOMIC64_INIT(0);
static atomic64_t state_read_failure_count = ATOMIC64_INIT(0);
static atomic64_t state_snapshot = ATOMIC64_INIT(0);
static atomic_t state_snapshot_valid = ATOMIC_INIT(0);
static atomic64_t selector_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_observation = ATOMIC64_INIT(0);
static atomic64_t lookup_callsite_sequence = ATOMIC64_INIT(0);
static atomic64_t lookup_callsite_dropped = ATOMIC64_INIT(0);
static atomic64_t lookup_return_site_matches = ATOMIC64_INIT(0);
static atomic64_t lookup_return_site_read_failures = ATOMIC64_INIT(0);
static atomic64_t lookup_return_site_unmatched = ATOMIC64_INIT(0);
static unsigned long lookup_expected_return_ip;
static atomic64_t lookup_branch_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_branch_decision_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_branch_taken_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_branch_not_taken_hit_count = ATOMIC64_INIT(0);
static const unsigned long lookup_join_predecessor_offsets[] = {
	0x31dUL, 0x9c1UL, 0xa94UL, 0xaaaUL, 0xdaaUL,
};
static atomic64_t lookup_join_031d_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_join_09c1_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_join_0a94_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_join_0aaa_hit_count = ATOMIC64_INIT(0);
static atomic64_t lookup_join_0daa_hit_count = ATOMIC64_INIT(0);
static atomic64_t *const lookup_join_predecessor_hit_counts[] = {
	&lookup_join_031d_hit_count, &lookup_join_09c1_hit_count,
	&lookup_join_0a94_hit_count, &lookup_join_0aaa_hit_count,
	&lookup_join_0daa_hit_count,
};
static u32 lookup_callsite_arg0;
static u32 lookup_callsite_arg1;
static u32 lookup_callsite_arg2;
static struct kprobe adapter_probe;
static struct kprobe selector_probe;
static struct kprobe lookup_probe;
static struct kprobe callsite_probe;
static struct kprobe lookup_branch_probe;
static struct kprobe lookup_branch_decision_probe;
static struct kprobe lookup_join_predecessor_probes[
	PC3_R580_LOOKUP_JOIN_PREDECESSOR_COUNT];
static bool adapter_probe_registered;
static bool selector_probe_registered;
static bool lookup_probe_registered;
static bool callsite_probe_registered;
static bool lookup_branch_probe_registered;
static bool lookup_branch_decision_probe_registered;
static bool lookup_join_predecessor_probe_registered[
	PC3_R580_LOOKUP_JOIN_PREDECESSOR_COUNT];

static int hit_count_get(char *buffer, const struct kernel_param *parameter)
{
	(void)parameter;
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 (long long)atomic64_read(&hit_count));
}

static const struct kernel_param_ops hit_count_ops = {
	.get = hit_count_get,
};
module_param_cb(hits, &hit_count_ops, NULL, 0400);
MODULE_PARM_DESC(hits, "Read-only count of rm_init_adapter entries observed");

static int state_reads_get(char *buffer, const struct kernel_param *parameter)
{
	(void)parameter;
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 (long long)atomic64_read(&state_read_count));
}

static const struct kernel_param_ops state_reads_ops = {
	.get = state_reads_get,
};
module_param_cb(state_reads, &state_reads_ops, NULL, 0400);

static int state_read_failures_get(char *buffer,
				   const struct kernel_param *parameter)
{
	(void)parameter;
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 (long long)atomic64_read(&state_read_failure_count));
}

static const struct kernel_param_ops state_read_failures_ops = {
	.get = state_read_failures_get,
};
module_param_cb(state_read_failures, &state_read_failures_ops, NULL, 0400);

static int state_snapshot_get(char *buffer,
			      const struct kernel_param *parameter)
{
	u64 snapshot;

	(void)parameter;
	if (!atomic_read(&state_snapshot_valid))
		return scnprintf(buffer, PAGE_SIZE, "unavailable\n");

	snapshot = (u64)atomic64_read(&state_snapshot);
	return scnprintf(buffer, PAGE_SIZE, "%08x %08x\n",
			 (u32)(snapshot >> 32), (u32)snapshot);
}

static const struct kernel_param_ops state_snapshot_ops = {
	.get = state_snapshot_get,
};
module_param_cb(state_snapshot, &state_snapshot_ops, NULL, 0400);
MODULE_PARM_DESC(state_snapshot,
	"Latest sequential flags and display SoC chip ID scalars; no pointer");

static int atomic_count_get(char *buffer, const struct kernel_param *parameter)
{
	const atomic64_t *count = parameter->arg;

	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 (long long)atomic64_read(count));
}

static const struct kernel_param_ops atomic_count_ops = {
	.get = atomic_count_get,
};
module_param_cb(selector_hits, &atomic_count_ops, &selector_hit_count, 0400);
MODULE_PARM_DESC(selector_hits, "Read-only count of _nv000790rm entries");
module_param_cb(lookup_branch_hits, &atomic_count_ops,
		&lookup_branch_hit_count, 0400);
MODULE_PARM_DESC(lookup_branch_hits,
	"Read-only count of the pinned _nv031364rm branch-target entries");
module_param_cb(lookup_branch_decision_hits, &atomic_count_ops,
		&lookup_branch_decision_hit_count, 0400);
module_param_cb(lookup_branch_taken_hits, &atomic_count_ops,
		&lookup_branch_taken_hit_count, 0400);
module_param_cb(lookup_branch_not_taken_hits, &atomic_count_ops,
		&lookup_branch_not_taken_hit_count, 0400);
module_param_cb(lookup_join_031d_hits, &atomic_count_ops,
		&lookup_join_031d_hit_count, 0400);
module_param_cb(lookup_join_09c1_hits, &atomic_count_ops,
		&lookup_join_09c1_hit_count, 0400);
module_param_cb(lookup_join_0a94_hits, &atomic_count_ops,
		&lookup_join_0a94_hit_count, 0400);
module_param_cb(lookup_join_0aaa_hits, &atomic_count_ops,
		&lookup_join_0aaa_hit_count, 0400);
module_param_cb(lookup_join_0daa_hits, &atomic_count_ops,
		&lookup_join_0daa_hit_count, 0400);

static int lookup_hits_get(char *buffer,
			   const struct kernel_param *parameter)
{
	u64 count;

	(void)parameter;
	if (capture_selector)
		count = (u64)atomic64_read(&lookup_observation) >> 32;
	else
		count = (u64)atomic64_read(&lookup_hit_count);
	return scnprintf(buffer, PAGE_SIZE, "%llu\n",
			 (unsigned long long)count);
}

static const struct kernel_param_ops lookup_hits_ops = {
	.get = lookup_hits_get,
};
module_param_cb(lookup_hits, &lookup_hits_ops, NULL, 0400);
MODULE_PARM_DESC(lookup_hits,
	"Read-only count of _nv031399rm entries observed");

static int selector_observation_get(char *buffer,
				    const struct kernel_param *parameter)
{
	u64 snapshot;
	u32 count;

	(void)parameter;
	if (capture_selector) {
		/* Count and scalar share one atomic64 snapshot. */
		snapshot = (u64)atomic64_read(&lookup_observation);
		count = (u32)(snapshot >> 32);
		if (count != 0)
			return scnprintf(buffer, PAGE_SIZE, "%08x %08x\n",
					 count, (u32)snapshot);
	} else {
		count = (u32)atomic64_read(&lookup_hit_count);
	}
	return scnprintf(buffer, PAGE_SIZE, "%08x unavailable\n", count);
}

static const struct kernel_param_ops selector_observation_ops = {
	.get = selector_observation_get,
};
module_param_cb(selector_observation, &selector_observation_ops, NULL, 0400);
MODULE_PARM_DESC(selector_observation,
	"Atomic lookup count and latest captured 32-bit argument, or unavailable");

static int lookup_callsite_observation_get(char *buffer,
						  const struct kernel_param *parameter)
{
	u64 sequence_before;
	u64 sequence_after;
	u32 arg0;
	u32 arg1;
	u32 arg2;

	(void)parameter;
	sequence_before = (u64)atomic64_read(&lookup_callsite_sequence);
	if (sequence_before & 1)
		return scnprintf(buffer, PAGE_SIZE, "busy\n");
	if (sequence_before == 0)
		return scnprintf(buffer, PAGE_SIZE, "%016llx unavailable\n",
				 0ULL);

	smp_rmb();
	arg0 = READ_ONCE(lookup_callsite_arg0);
	arg1 = READ_ONCE(lookup_callsite_arg1);
	arg2 = READ_ONCE(lookup_callsite_arg2);
	smp_rmb();
	sequence_after = (u64)atomic64_read(&lookup_callsite_sequence);
	if (sequence_before != sequence_after || (sequence_after & 1))
		return scnprintf(buffer, PAGE_SIZE, "busy\n");

	return scnprintf(buffer, PAGE_SIZE, "%016llx %08x %08x %08x\n",
			 (unsigned long long)(sequence_after >> 1),
			 arg0, arg1, arg2);
}

static const struct kernel_param_ops lookup_callsite_observation_ops = {
	.get = lookup_callsite_observation_get,
};
module_param_cb(lookup_callsite_observation,
		&lookup_callsite_observation_ops, NULL, 0400);
MODULE_PARM_DESC(lookup_callsite_observation,
	"One bounded snapshot: count and EDI, ESI, EDX at the pinned pre-call site");

module_param_cb(lookup_callsite_dropped, &atomic_count_ops, &lookup_callsite_dropped, 0400);

module_param_cb(lookup_return_site_matches, &atomic_count_ops,
		&lookup_return_site_matches, 0400);
module_param_cb(lookup_return_site_read_failures, &atomic_count_ops,
		&lookup_return_site_read_failures, 0400);
module_param_cb(lookup_return_site_unmatched, &atomic_count_ops,
		&lookup_return_site_unmatched, 0400);
MODULE_PARM_DESC(lookup_callsite_dropped,
	"Read-only count of bounded callsite captures dropped on contention or overflow");

static void record_lookup_observation(struct pt_regs *registers)
{
	u64 old_snapshot;
	u64 next;
	u32 count;
	u32 selector;

	/* Pinned R580 callsite dataflow puts the selector in ESI (argument 2). */
	selector = (u32)regs_get_kernel_argument(registers, 1);
	do {
		old_snapshot = (u64)atomic64_read(&lookup_observation);
		count = (u32)(old_snapshot >> 32);
		if (count == (u32)~0U)
			return;
		next = ((u64)(count + 1) << 32) | selector;
	} while ((u64)atomic64_cmpxchg(&lookup_observation,
					      (s64)old_snapshot, (s64)next) != old_snapshot);
}
NOKPROBE_SYMBOL(record_lookup_observation);

static void record_lookup_callsite(struct pt_regs *registers)
{
	s64 old_sequence;
	s64 odd_sequence;
	s64 next_sequence;

	old_sequence = atomic64_read(&lookup_callsite_sequence);
	if (old_sequence < 0 || old_sequence > S64_MAX - 2 ||
	    (old_sequence & 1))
		goto dropped;
	odd_sequence = old_sequence + 1;
	if (atomic64_cmpxchg(&lookup_callsite_sequence, old_sequence,
			     odd_sequence) != old_sequence)
		goto dropped;

	WRITE_ONCE(lookup_callsite_arg0,
		   (u32)regs_get_kernel_argument(registers, 0));
	WRITE_ONCE(lookup_callsite_arg1,
		   (u32)regs_get_kernel_argument(registers, 1));
	WRITE_ONCE(lookup_callsite_arg2,
		   (u32)regs_get_kernel_argument(registers, 2));
	smp_wmb();
	next_sequence = old_sequence + 2;
	if (atomic64_cmpxchg(&lookup_callsite_sequence, odd_sequence,
			     next_sequence) != odd_sequence)
		goto dropped;
	return;

dropped:
	atomic64_inc(&lookup_callsite_dropped);
}
NOKPROBE_SYMBOL(record_lookup_callsite);

static int resolve_lookup_return_site(void)
{
	struct kprobe resolver = {
		.symbol_name = PC3_R580_LOOKUP_CALL_TARGET,
		.offset = PC3_R580_LOOKUP_CALL_OFFSET,
		.flags = KPROBE_FLAG_DISABLED,
	};
	int ret;

	ret = register_kprobe(&resolver);
	if (ret)
		return ret;
	if (!resolver.addr || resolver.addr > ULONG_MAX -
			PC3_R580_LOOKUP_CALL_LENGTH) {
		ret = -EINVAL;
	} else {
		WRITE_ONCE(lookup_expected_return_ip,
			   resolver.addr + PC3_R580_LOOKUP_CALL_LENGTH);
		WRITE_ONCE(lookup_return_site_ready, true);
	}
	unregister_kprobe(&resolver);
	if (ret) {
		WRITE_ONCE(lookup_expected_return_ip, 0);
		WRITE_ONCE(lookup_return_site_ready, false);
	}
	return ret;
}
NOKPROBE_SYMBOL(resolve_lookup_return_site);

static void record_lookup_return_site(struct pt_regs *registers)
{
	unsigned long return_ip;
	unsigned long expected_return_ip;

	expected_return_ip = READ_ONCE(lookup_expected_return_ip);
	if (!READ_ONCE(lookup_return_site_ready) || !expected_return_ip ||
	    registers->sp > ULONG_MAX - sizeof(return_ip) ||
	    copy_from_kernel_nofault(&return_ip,
				     (const void *)registers->sp,
				     sizeof(return_ip)) != 0) {
		atomic64_inc(&lookup_return_site_read_failures);
		return;
	}
	if (return_ip != expected_return_ip) {
		atomic64_inc(&lookup_return_site_unmatched);
		return;
	}
	atomic64_inc(&lookup_return_site_matches);
}
NOKPROBE_SYMBOL(record_lookup_return_site);

static int pc3_r580_selector_probe_handler(struct kprobe *probe,
					   struct pt_regs *registers)
{
	unsigned int index;

	if (probe == &selector_probe)
		atomic64_inc(&selector_hit_count);
	else if (probe == &lookup_probe) {
		if (capture_lookup_return_site) {
			atomic64_inc(&lookup_hit_count);
			record_lookup_return_site(registers);
		} else if (capture_selector)
			record_lookup_observation(registers);
		else
			atomic64_inc(&lookup_hit_count);
	} else if (probe == &callsite_probe && capture_lookup_callsite)
		record_lookup_callsite(registers);
	else if (probe == &lookup_branch_probe && capture_lookup_branch)
		atomic64_inc(&lookup_branch_hit_count);
	else if (probe == &lookup_branch_decision_probe && capture_lookup_branch) {
		atomic64_inc(&lookup_branch_decision_hit_count);
		if (registers->flags & (X86_EFLAGS_CF | X86_EFLAGS_ZF))
			atomic64_inc(&lookup_branch_taken_hit_count);
		else
			atomic64_inc(&lookup_branch_not_taken_hit_count);
	} else if (capture_lookup_branch || capture_lookup_join_route) {
		for (index = 0; index < PC3_R580_LOOKUP_JOIN_PREDECESSOR_COUNT;
		     index++) {
			if (probe == &lookup_join_predecessor_probes[index]) {
				atomic64_inc(lookup_join_predecessor_hit_counts[index]);
				break;
			}
		}
	}
	return 0;
}
NOKPROBE_SYMBOL(pc3_r580_selector_probe_handler);

static int pc3_r580_probe_handler(struct kprobe *probe, struct pt_regs *registers)
{
	unsigned long state_address;
	u32 flags;
	u32 display_soc_chip_id;
	u64 packed;

	(void)probe;
	atomic64_inc(&hit_count);
	if (!capture_state)
		return 0;

	state_address = regs_get_kernel_argument(registers, 1);
	if (state_address == 0 ||
	    state_address > ULONG_MAX - NV_STATE_DISPLAY_SOC_CHIP_ID_OFFSET -
			    sizeof(display_soc_chip_id))
		goto read_failed;

	/*
	 * This opt-in diagnostic reads two scalar fields from the second
	 * rm_init_adapter argument. The reads are sequential, not an atomic
	 * snapshot; copy_from_kernel_nofault() prevents a bad pointer from
	 * faulting in this non-sleeping kprobe handler. Never publish the address.
	 */
	if (copy_from_kernel_nofault(&flags,
				     (const void *)(state_address +
						    NV_STATE_FLAGS_OFFSET),
				     sizeof(flags)) != 0 ||
	    copy_from_kernel_nofault(&display_soc_chip_id,
				     (const void *)(state_address +
						    NV_STATE_DISPLAY_SOC_CHIP_ID_OFFSET),
				     sizeof(display_soc_chip_id)) != 0)
		goto read_failed;

	packed = ((u64)flags << 32) | display_soc_chip_id;
	atomic64_set(&state_snapshot, (s64)packed);
	atomic_set(&state_snapshot_valid, 1);
	atomic64_inc(&state_read_count);
	return 0;

read_failed:
	atomic64_inc(&state_read_failure_count);
	return 0;
}
NOKPROBE_SYMBOL(pc3_r580_probe_handler);

static void unregister_registered_probes(void)
{
	int index;

	for (index = PC3_R580_LOOKUP_JOIN_PREDECESSOR_COUNT - 1;
	     index >= 0; index--) {
		if (lookup_join_predecessor_probe_registered[index]) {
			unregister_kprobe(&lookup_join_predecessor_probes[index]);
			lookup_join_predecessor_probe_registered[index] = false;
		}
	}
	if (lookup_branch_decision_probe_registered) {
		unregister_kprobe(&lookup_branch_decision_probe);
		lookup_branch_decision_probe_registered = false;
	}
	if (lookup_branch_probe_registered) {
		unregister_kprobe(&lookup_branch_probe);
		lookup_branch_probe_registered = false;
	}
	if (lookup_probe_registered) {
		unregister_kprobe(&lookup_probe);
		lookup_probe_registered = false;
	}
	if (callsite_probe_registered) {
		unregister_kprobe(&callsite_probe);
		callsite_probe_registered = false;
	}
	if (selector_probe_registered) {
		unregister_kprobe(&selector_probe);
		selector_probe_registered = false;
	}
	if (adapter_probe_registered) {
		unregister_kprobe(&adapter_probe);
		adapter_probe_registered = false;
	}
}

static int register_lookup_join_predecessor_probes(void)
{
	unsigned int index;
	int ret;

	for (index = 0; index < PC3_R580_LOOKUP_JOIN_PREDECESSOR_COUNT;
	     index++) {
		lookup_join_predecessor_probes[index].symbol_name =
			PC3_R580_LOOKUP_BRANCH_TARGET;
		lookup_join_predecessor_probes[index].offset =
			lookup_join_predecessor_offsets[index];
		lookup_join_predecessor_probes[index].pre_handler =
			pc3_r580_selector_probe_handler;
		ret = register_kprobe(&lookup_join_predecessor_probes[index]);
		if (ret) {
			pr_err("failed to register lookup-join probe at offset %#lx: %d\n",
			       lookup_join_predecessor_offsets[index], ret);
			return ret;
		}
		lookup_join_predecessor_probe_registered[index] = true;
	}
	return 0;
}

static int __init pc3_r580_kprobe_observer_init(void)
{
	int ret;

	if (owner_nonce == 0)
		return -EINVAL;
	if (capture_state && !arm)
		return -EINVAL;
	if (capture_selector && (!arm || !observe_selector_path))
		return -EINVAL;
	if (capture_lookup_callsite && (!arm || !observe_selector_path))
		return -EINVAL;
	if (capture_lookup_branch &&
	    (!arm || !observe_selector_path || !capture_lookup_callsite))
		return -EINVAL;
	if (capture_lookup_return_site &&
	    (!arm || !observe_selector_path || capture_selector ||
	     capture_lookup_callsite || capture_lookup_branch))
		return -EINVAL;
	if (capture_lookup_join_route &&
	    (!arm || !observe_selector_path || !capture_lookup_return_site ||
	     capture_selector || capture_lookup_callsite || capture_lookup_branch))
		return -EINVAL;

	adapter_probe.symbol_name = PC3_R580_TARGET;
	adapter_probe.pre_handler = pc3_r580_probe_handler;
	if (!arm)
		adapter_probe.flags = KPROBE_FLAG_DISABLED;

	ret = register_kprobe(&adapter_probe);
	if (ret)
		return ret;
	adapter_probe_registered = true;

	if (observe_selector_path) {
		selector_probe.symbol_name = PC3_R580_SELECTOR_TARGET;
		selector_probe.pre_handler = pc3_r580_selector_probe_handler;
		lookup_probe.symbol_name = PC3_R580_LOOKUP_TARGET;
		lookup_probe.pre_handler = pc3_r580_selector_probe_handler;
		if (!arm) {
			selector_probe.flags = KPROBE_FLAG_DISABLED;
			lookup_probe.flags = KPROBE_FLAG_DISABLED;
		}
		ret = register_kprobe(&selector_probe);
		if (ret)
			goto registration_failed;
		selector_probe_registered = true;
		if (capture_lookup_return_site) {
			ret = resolve_lookup_return_site();
			if (ret)
				goto registration_failed;
		}
		ret = register_kprobe(&lookup_probe);
		if (ret)
			goto registration_failed;
		lookup_probe_registered = true;
		if (capture_lookup_callsite) {
			callsite_probe.symbol_name = PC3_R580_LOOKUP_CALL_TARGET;
			callsite_probe.offset = PC3_R580_LOOKUP_CALL_OFFSET;
			callsite_probe.pre_handler = pc3_r580_selector_probe_handler;
			ret = register_kprobe(&callsite_probe);
			if (ret)
				goto registration_failed;
			callsite_probe_registered = true;
		}
		if (capture_lookup_branch) {
			lookup_branch_probe.symbol_name = PC3_R580_LOOKUP_BRANCH_TARGET;
			lookup_branch_probe.offset = PC3_R580_LOOKUP_BRANCH_OFFSET;
			lookup_branch_probe.pre_handler = pc3_r580_selector_probe_handler;
			ret = register_kprobe(&lookup_branch_probe);
			if (ret) {
				pr_err("failed to register lookup-branch target probe: %d\n",
				       ret);
				goto registration_failed;
			}
			lookup_branch_probe_registered = true;
			lookup_branch_decision_probe.symbol_name =
				PC3_R580_LOOKUP_BRANCH_TARGET;
			lookup_branch_decision_probe.offset = PC3_R580_LOOKUP_BRANCH_DECISION_OFFSET;
			lookup_branch_decision_probe.pre_handler =
				pc3_r580_selector_probe_handler;
			ret = register_kprobe(&lookup_branch_decision_probe);
			if (ret) {
				pr_err("failed to register lookup-branch decision probe: %d\n",
				       ret);
				goto registration_failed;
			}
			lookup_branch_decision_probe_registered = true;
			ret = register_lookup_join_predecessor_probes();
			if (ret)
				goto registration_failed;
		}
		if (capture_lookup_join_route) {
			ret = register_lookup_join_predecessor_probes();
			if (ret)
				goto registration_failed;
		}
	}

	pr_info("registered %s%s%s; armed=%u\n", PC3_R580_TARGET,
		observe_selector_path ? " with fixed selector-path counters" : "",
		capture_lookup_branch ? " and lookup-branch counter" : "",
		arm ? 1 : 0);
	return 0;

registration_failed:
	unregister_registered_probes();
	return ret;
}

static void __exit pc3_r580_kprobe_observer_exit(void)
{
	unregister_registered_probes();
}

module_init(pc3_r580_kprobe_observer_init);
module_exit(pc3_r580_kprobe_observer_exit);

MODULE_DESCRIPTION("Opt-in bounded R580 kprobe canary for the PC3 V100 guest");
MODULE_AUTHOR("NVIDIA hybrid driver research");
MODULE_LICENSE("GPL");
