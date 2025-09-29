/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <vmlinux.h>
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile u64 num_cpus = 0;
const volatile u64 x_max = 0;

private(MASK) struct bpf_cpumask __kptr *x_cpumask;

static u64 vtime_now;
static u64 xcpu_rr = 0;
#define PROCESS_X ("synth")
#define PROCESS_Y ("hog")

UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define X_DSQ 1

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

bool is_x(struct task_struct *p) {
	return bpf_strncmp(p->comm, sizeof(PROCESS_X), PROCESS_X) == 0 && x_cpumask != NULL;
}

bool is_y(struct task_struct *p) {
	return bpf_strncmp(p->comm, sizeof(PROCESS_Y), PROCESS_Y) == 0;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	if (is_x(p)) {
		// look for an idle X cpu
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, cast_mask(x_cpumask), 0);
		if (cpu >= 0) {
			stat_inc(0);
			// there's an idle core waiting for us
			// scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0); // adds to DSQ of cpu returned by this fn
		} else {
			// add to the dsq of one of the X cores:
			// xcpu_rr = (xcpu_rr + 1) % (x_max + 1);
			// cpu = xcpu_rr;
			// scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | xcpu_rr, SCX_SLICE_DFL, 0);
			return prev_cpu;
		}
	} else {
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		if (is_idle) {
			stat_inc(0);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		}
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);

	if (is_x(p)) {
		scx_bpf_dsq_insert(p, X_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!(cpu <= x_max && scx_bpf_dsq_move_to_local(X_DSQ))) {
    	scx_bpf_dsq_move_to_local(SHARED_DSQ);
	}
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	struct bpf_cpumask *cpumask;
	s32 dsq_err;
	
	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		return -ENOMEM;
	}
	bpf_cpumask_clear(cpumask);
	for (u32 i = 0; i <= x_max; i++) {
		bpf_cpumask_set_cpu(i, cpumask);
	}
	cpumask = bpf_kptr_xchg(&x_cpumask, cpumask);
	if (cpumask) { // why?
		bpf_cpumask_release(cpumask);
	}

	xcpu_rr = 0;

	dsq_err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (dsq_err < 0) {
		return dsq_err;
	}
	return scx_bpf_create_dsq(X_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "simple");
