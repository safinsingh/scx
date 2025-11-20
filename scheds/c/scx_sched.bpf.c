#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

#define SHARED_DSQ 0

s32 BPF_STRUCT_OPS(sched_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	/* Pick the target CPU for a waking task, letting the default helper honor idle hints. */
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* Enqueue a runnable task onto the BPF scheduler's shared DSQ. */
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(sched_dequeue, struct task_struct *p, u64 deq_flags)
{
	/* Remove a task from scheduler management while attributes change. */
}

void BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev)
{
	/* Pull from user or shared DSQs when the local DSQ is empty. */
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(sched_tick, struct task_struct *p)
{
	/* Periodic tick while a task runs; set slice to 0 to force redispatch. */
}

void BPF_STRUCT_OPS(sched_runnable, struct task_struct *p, u64 enq_flags)
{
	/* Task becomes runnable on its associated CPU. */
}

void BPF_STRUCT_OPS(sched_running, struct task_struct *p)
{
	/* Task starts running on its associated CPU. */
}

void BPF_STRUCT_OPS(sched_stopping, struct task_struct *p, bool runnable)
{
	/* Task stops running; runnable indicates whether it stays runnable. */
}

void BPF_STRUCT_OPS(sched_quiescent, struct task_struct *p, u64 deq_flags)
{
	/* Task leaves the runnable state because it slept, moved CPUs, or was saved. */
}

bool BPF_STRUCT_OPS(sched_yield, struct task_struct *from, struct task_struct *to)
{
	/* Handle a yielding task, optionally to a specific target. */
	return false;
}

bool BPF_STRUCT_OPS(sched_core_sched_before, struct task_struct *a, struct task_struct *b)
{
	/* Provide ordering between two runnable tasks for core scheduling. */
	return false;
}

void BPF_STRUCT_OPS(sched_set_weight, struct task_struct *p, u32 weight)
{
	/* Update a task's weight [1..10000]. */
}

void BPF_STRUCT_OPS(sched_set_cpumask, struct task_struct *p, const struct cpumask *cpumask)
{
	/* Update a task's CPU affinity mask. */
}

void BPF_STRUCT_OPS(sched_update_idle, s32 cpu, bool idle)
{
	/* Notify that a CPU entered or left the idle state. */
}

void BPF_STRUCT_OPS(sched_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	/* CPU returns under scheduler control after being released. */
}

void BPF_STRUCT_OPS(sched_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/* CPU is taken away from the scheduler; see args->reason for details. */
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	/* Initialize per-task state when entering sched_ext; may sleep. */
	return 0;
}

void BPF_STRUCT_OPS(sched_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	/* Tear down per-task state when exiting or unloading the scheduler. */
}

void BPF_STRUCT_OPS(sched_enable, struct task_struct *p)
{
	/* Enable SCX scheduling for a task entering the class. */
}

void BPF_STRUCT_OPS(sched_disable, struct task_struct *p)
{
	/* Disable SCX scheduling as a task leaves or SCX unloads. */
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sched_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
	/* Initialize cgroup state for sched_ext; may block. */
	return 0;
}

void BPF_STRUCT_OPS_SLEEPABLE(sched_cgroup_exit, struct cgroup *cgrp)
{
	/* Clean up cgroup state when destroyed or scheduler unloads; may block. */
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sched_cgroup_prep_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
	/* Prepare to move a task between cgroups; may sleep for allocations. */
	return 0;
}

void BPF_STRUCT_OPS(sched_cgroup_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
	/* Commit a task's move between cgroups after prep. */
}

void BPF_STRUCT_OPS(sched_cgroup_cancel_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
	/* Undo a failed cgroup move that was previously prepared. */
}

void BPF_STRUCT_OPS(sched_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	/* Update a cgroup's weight [1..10000]. */
}

void BPF_STRUCT_OPS_SLEEPABLE(sched_cpu_online, s32 cpu)
{
	/* Handle a CPU coming online before it runs SCX tasks. */
}

void BPF_STRUCT_OPS_SLEEPABLE(sched_cpu_offline, s32 cpu)
{
	/* Handle a CPU going offline after it stops running SCX tasks. */
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init)
{
	/* Initialize the BPF scheduler; may sleep. */
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(sched_exit, struct scx_exit_info *ei)
{
	/* Clean up after the BPF scheduler, also called on init failure. */
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(sched_ops,
	       .select_cpu		= (void *)sched_select_cpu,
	       .enqueue			= (void *)sched_enqueue,
	       .dequeue			= (void *)sched_dequeue,
	       .dispatch		= (void *)sched_dispatch,
	       .tick			= (void *)sched_tick,
	       .runnable		= (void *)sched_runnable,
	       .running			= (void *)sched_running,
	       .stopping		= (void *)sched_stopping,
	       .quiescent		= (void *)sched_quiescent,
	       .yield			= (void *)sched_yield,
	       .core_sched_before	= (void *)sched_core_sched_before,
	       .set_weight		= (void *)sched_set_weight,
	       .set_cpumask		= (void *)sched_set_cpumask,
	       .update_idle		= (void *)sched_update_idle,
	       .cpu_acquire		= (void *)sched_cpu_acquire,
	       .cpu_release		= (void *)sched_cpu_release,
	       .init_task		= (void *)sched_init_task,
	       .exit_task		= (void *)sched_exit_task,
	       .enable			= (void *)sched_enable,
	       .disable			= (void *)sched_disable,
	       .cgroup_init		= (void *)sched_cgroup_init,
	       .cgroup_exit		= (void *)sched_cgroup_exit,
	       .cgroup_prep_move	= (void *)sched_cgroup_prep_move,
	       .cgroup_move		= (void *)sched_cgroup_move,
	       .cgroup_cancel_move	= (void *)sched_cgroup_cancel_move,
	       .cgroup_set_weight	= (void *)sched_cgroup_set_weight,
	       .cpu_online		= (void *)sched_cpu_online,
	       .cpu_offline		= (void *)sched_cpu_offline,
	       .init			= (void *)sched_init,
	       .exit			= (void *)sched_exit,
	       .name			= "sched");
