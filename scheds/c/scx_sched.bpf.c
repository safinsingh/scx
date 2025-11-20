#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

#define SHARED_DSQ 0

/*
 * Summary:
 *   Selects an appropriate CPU for a task that is waking up or being activated,
 *   possibly inserting the task into a dispatch queue for immediate scheduling.
 *   Provides a CPU hint for where the task should run next, but the final decision
 *   may differ at dispatch time.
 *
 * Trigger / Invocation:
 *   Called by the scheduler core when a task becomes runnable (e.g. wakeup from
 *   sleep, post-fork, or after exec) and is allowed to migrate.
 *   It is the first hook in the scheduling pipeline for a waking task.
 *   This callback is skipped for tasks that cannot migrate (pinned to one CPU or
 *   with migration disabled). It runs in atomic context (cannot
 *   sleep) during the wakeup path, before the task is enqueued on any runqueue.
 *   It may be invoked concurrently on different CPUs for different tasks, but never
 *   simultaneously for the same task.
 *
 * Parameters:
 *   @p:
 *     The task that is waking up and needs a target CPU. At invocation, @p is not
 *     enqueued on any CPU. It will be transitioning from idle/sleep to runnable
 *     state.
 *   @prev_cpu:
 *     The CPU on which @p last executed before sleeping. This serves
 *     as a hint (for example, to prefer waking on the same CPU for cache affinity).
 *   @wake_flags:
 *     Flags indicating the reason and nature of the wakeup. For
 *     example, `SCX_WAKE_FORK` if this is wakeup after fork, `SCX_WAKE_TTWU` for
 *     asynchronous wakeups, or `SCX_WAKE_SYNC` for synchronous wakeups. These flags
 *     may influence CPU selection (e.g., sync wakeups might bias toward @prev_cpu).
 *
 * Effects:
 *   Returns the CPU number that is the preferred target for @p to run on.
 *   If an idle CPU is chosen, that CPU is “kicked” (signaled to wake and schedule)
 *   by the core. This function may also directly enqueue @p into a
 *   dispatch queue: for example, inserting @p into the selected CPU’s local dispatch
 *   queue via `scx_bpf_dsq_insert()` (often with `SCX_DSQ_LOCAL`) to expedite its
 *   scheduling. In such cases, the core will skip calling ops.enqueue
 *   for @p. The CPU selection here is a performance hint and not
 *   binding – the task can still be moved to a different CPU later
 *   during dispatch. If an invalid CPU (e.g. one not in @p’s allowed mask) is
 *   returned, the core will ignore the hint. Generally, @p is kept off
 *   any runqueue until this function returns; any direct DSQ insertion performed
 *   here should correspond to the CPU returned to maintain consistency.
 *
 * Concurrency / Ordering:
 *   Not called with any per-runqueue locks held (since @p is not on a runqueue yet),
 *   though it may run with interrupts disabled or under a spin lock protecting @p’s
 *   state. It must execute quickly and without blocking. Multiple tasks may undergo
 *   select_cpu on different CPUs concurrently. The core ensures that for a given
 *   task, select_cpu runs to completion (on one CPU) before any subsequent enqueue.
 *   This callback occurs before ops.enqueue for the same event, and before @p is
 *   visible on any CPU’s runqueue. If @p was in a stopped state due to migration
 *   disabling, this callback would not run at all for that wakeup.
 *
 * Invariants:
 *   @p is not currently scheduled or queued when this runs. The implementation must
 *   not enqueue @p into more than one queue. If @p is directly inserted into a local
 *   DSQ here, the CPU returned should be that same CPU (the core uses the return
 *   value to determine which CPU’s local queue to use for insertion). The scheduler
 *   should not modify @p’s fundamental state except possibly to queue it; the task’s
 *   run state remains “not on rq” until after this returns. The core will validate
 *   the selection (enforcing CPU affinity and online status). This
 *   callback should preserve any invariants needed for later enqueue/dispatch (e.g.,
 *   not marking @p as enqueued unless it actually inserted it into a DSQ).
 *
 * Failure / Edge Cases:
 *   This function does not return error codes – it must always return a CPU (or the
 *   previous CPU as a default). If no particular CPU is better, returning @prev_cpu
 *   or the current CPU of the waker is common. If the scheduler attempts to use a
 *   helper that fails (e.g., fails to insert into a DSQ due to memory issues), the
 *   recommended approach is to call `scx_bpf_error()` to unload the scheduler, as a
 *   failure here would otherwise leave @p unhandled. Tasks with single-CPU affinity
 *   or `PF_NO_SETAFFINITY` will never invoke this callback. CPU
 *   hotplug events during selection are detected via `hotplug_seq` if set; an
 *   unexpected change can abort the load if a mismatch is seen. An idle CPU returned
 *   might become non-idle by the time dispatch occurs – the hint simply slightly
 *   improves performance if accurate.
 *
 * Notes:
 *   This callback implements logic analogous to the kernel’s `select_task_rq` for
 *   sched_ext tasks. Simpler implementations can use the provided helper
 *   `scx_bpf_select_cpu_dfl()` which returns an idle CPU if available and otherwise
 *   @prev_cpu. If an idle CPU is found and used, inserting @p into
 *   `SCX_DSQ_LOCAL` here will queue it directly on that CPU and skip ops.enqueue.
 *   Care should be taken that no sleeping or lengthy processing is done here. All
 *   decisions should be purely computational or use non-blocking helpers. Locking is
 *   generally not needed, but if global state is accessed (e.g., a global CPU mask
 *   of some kind), it must be done in a lock-free manner or with BPF spin locks, as
 *   appropriate, since this runs under strict time constraints.
 */
s32 BPF_STRUCT_OPS(sched_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

/*
 * Summary:
 *   Enqueues a runnable task into the BPF scheduler’s scheduling queue/structure.
 *   This callback takes ownership of the task from the core and decides how to
 *   queue it (e.g., add to a global runqueue or directly dispatch). It is responsible
 *   for ensuring the task will eventually be scheduled on a CPU.
 *
 * Trigger / Invocation:
 *   Invoked when a task becomes runnable under sched_ext and was not already queued
 *   via ops.select_cpu. This happens on wakeups (if ops.select_cpu didn’t insert the
 *   task directly), on newly forked tasks being made runnable, or when a running task
 *   needs to be re-queued after a preemption or time-slice depletion.
 *   In general, any transition that makes a task ready to run (except those where the
 *   task was immediately dispatched in select_cpu) will call ops.enqueue. For example,
 *   if a task’s time slice expired, the core may call enqueue to put it back in the
 *   scheduler’s queue (often with specific flags indicating it’s a requeue). This
 *   callback is not called if the task was inserted into a DSQ during select_cpu (in
 *   that case, the task bypasses enqueue).
 *   It runs in a scheduling context (often with the target CPU’s runqueue lock held)
 *   and cannot sleep. It may be called on any CPU on behalf of the task (commonly the
 *   task’s waking CPU or previous CPU). Different tasks can be enqueued in parallel
 *   on different CPUs, but a given task’s enqueue is serialized.
 *
 * Parameters:
 *   @p:
 *     The task being enqueued into the BPF scheduler’s control. At
 *     this point, @p has been taken off any legacy runqueue and is transferring to
 *     the sched_ext system. It is marked runnable.
 *   @enq_flags:
 *     A bitmask of flags (enum `scx_enq_flags`) describing the context of this
 *     enqueue. Examples include:
 *       - `SCX_ENQ_WAKEUP`: The task is waking from sleep.
 *       - `SCX_ENQ_PREEMPT`: Enqueue due to preemption; the task was preempted and
 *         should be placed at the head of a queue to potentially run sooner.
 *       - `SCX_ENQ_REENQ`: The task was removed (e.g., for priority/affinity change)
 *         and is being re-enqueued on its CPU.
 *       - `SCX_ENQ_LAST`: The task was running alone and is being enqueued because
 *         it can no longer continue running without an explicit scheduling event
 *         (used if `SCX_OPS_ENQ_LAST` flag is set).
 *       - `SCX_ENQ_HEAD`: Hint that the task should be placed at the front of the
 *         runqueue instead of the tail (this is implied by SCX_ENQ_PREEMPT).
 *     The scheduler should honor these flags when queuing @p (e.g., insert at head if
 *     HEAD flag is set, trigger an immediate preemption if PREEMPT).
 *
 * Effects:
 *   Places @p into the scheduler’s internal runqueue or dispatching structure. In a
 *   simple scheduler, this might mean inserting @p into a global FIFO or priority
 *   queue (using, for example, `scx_bpf_dsq_insert()` to SCX_DSQ_GLOBAL or a custom
 *   DSQ). In other designs, it could mean pushing @p onto a per-CPU
 *   queue or data structure for later scheduling. This function can also decide to
 *   dispatch @p immediately: for instance, a minimal scheduler might directly assign
 *   a slice to @p on a CPU via `scx_bpf_dispatch()` or insert into the target CPU’s
 *   local DSQ with a preempt flag to prompt immediate context switch.
 *   If @p is not dispatched here, it remains under BPF scheduler control until ops.dispatch
 *   selects it for execution. The core considers @p “owned” by the BPF scheduler after
 *   this call, meaning the scheduler must eventually arrange for @p to run.
 *   The function does not return a value; all decisions are side effects on @p’s queued
 *   state. Typically, it will set @p->scx.slice (either to a default timeslice or a
 *   computed value) when inserting into a DSQ. If @enq_flags includes SCX_ENQ_PREEMPT and
 *   @p is being queued to a CPU that currently has another task, the scheduler should
 *   insert @p at the head of that CPU’s queue (and use SCX_ENQ_HEAD in the insert helper)
 *   to ensure the core preempts the running task. By default, the core will
 *   trigger a preemption IPI if a task is enqueued on a remote CPU with SCX_ENQ_PREEMPT.
 *
 * Concurrency / Ordering:
 *   This callback executes with the protection of the scheduling system; on the target
 *   CPU, it will not run concurrently with another enqueue or dispatch for the same CPU.
 *   However, enqueues on different CPUs (for different tasks) can happen in parallel. If
 *   the scheduler uses a global runqueue (shared among CPUs), it must use BPF spin locks
 *   or atomic operations internally to protect concurrent access, since two CPUs might
 *   enqueue tasks at the same time. The core may invoke ops.enqueue on a CPU other than
 *   @p’s previous one (e.g., via IPI if a queued wakeup optimization is enabled by
 *   `SCX_OPS_ALLOW_QUEUED_WAKEUP`), so @p may be enqueued from
 *   a remote context. In the overall pipeline, enqueue occurs after ops.select_cpu (unless
 *   bypassed) and usually before any ops.dispatch that schedules the task. There is no
 *   guaranteed ops.runnable call immediately before enqueue – a task might be enqueued
 *   without a runnable notification (for example, when re-queuing after using its slice).
 *   If @p is migration-disabled and `SCX_OPS_ENQ_MIGRATION_DISABLED` is not set, the core
 *   may automatically place @p on its current CPU’s local DSQ instead of calling enqueue.
 *
 * Invariants:
 *   The task @p must not already be on any scheduler queue when this is called. The
 *   implementation must ensure @p is added to exactly one queue or list managed by the
 *   scheduler, and that it will be picked up by a subsequent ops.dispatch. The scheduler
 *   should not drop or forget @p; failing to eventually schedule @p will result in the
 *   task hanging (the watchdog will detect a stalled task). If the scheduler defers actual
 *   CPU assignment (i.e., doesn’t call scx_bpf_dispatch or insert into a specific CPU’s
 *   DSQ here), then ops.dispatch is expected to handle moving @p to a CPU. The order of
 *   tasks in the scheduler’s queue should respect any policy invariants (e.g., if using
 *   a priority or vruntime queue, maintain sorted order). It should also honor the enqueue
 *   flags: e.g., if `SCX_ENQ_HEAD` is set in @enq_flags, @p should be placed at the front
 *   of whatever queue such that it will run before other tasks enqueued earlier.
 *   The scheduler must not directly invoke blocking operations here. It also must not
 *   modify core scheduler state (like runqueue data); its scope is the BPF-managed state.
 *
 * Failure / Edge Cases:
 *   This function does not return an error. On catastrophic failures (e.g., out-of-memory
 *   in a BPF map used for the runqueue), the scheduler can call `scx_bpf_error()` to
 *   trigger an error dump and fall back to the default scheduler. If enqueue simply
 *   cannot queue the task (logic error), the task would stall – which is considered a
 *   fatal error (watchdog will eventually unload the scheduler). Edge cases include:
 *   - **Preemption flag**: If @enq_flags has SCX_ENQ_PREEMPT, the scheduler should be
 *     prepared for the current running task on the target CPU to be preempted. The core
 *     will clear that task’s slice to 0 and signal a reschedule. The
 *     enqueued @p should be available to run immediately.
 *   - **SCX_ENQ_LAST**: If the scheduler sets `SCX_OPS_ENQ_LAST` in ops->flags, the core
 *     will enqueue tasks that exhaust their time slice even if they were the only task.
 *     Such tasks come through here with SCX_ENQ_LAST set. The scheduler
 *     must ensure a subsequent scheduling event (e.g., by kicking a CPU or dispatching another
 *     task) because the core will not automatically continue running a task enqueued with
 *     LAST.
 *   - **Migration disabled tasks**: By default, a task that cannot migrate (affinity 1)
 *     is directly placed on its CPU’s local queue on wakeup. If the scheduler explicitly
 *     opts in via SCX_OPS_ENQ_MIGRATION_DISABLED, those tasks will come through enqueue
 *     as well, and the scheduler must handle them (likely by immediately
 *     inserting into that CPU’s DSQ). Otherwise, such tasks skip enqueue.
 *   - **Concurrent enqueues**: If two tasks wake at the same time on different CPUs,
 *     their enqueues happen in parallel. The scheduler’s data structures must tolerate
 *     this (e.g., a global queue might require a spin lock).
 *   - **No tasks**: This situation doesn’t directly apply to enqueue (there is always a
 *     task to enqueue when it’s called), but if the scheduler is overloaded or misconfigured,
 *     ensure enqueue doesn’t spin or delay – it should just queue and return.
 *
 * Notes:
 *   The enqueue phase is where the BPF scheduler can implement its policy for queuing.
 *   Simpler schedulers may choose to dispatch immediately from here if a CPU is idle, in
 *   which case ops.dispatch might be a no-op. For instance, a minimal round-robin scheduler
 *   might call `scx_bpf_dispatch(p, cpu, slice, enq_flags)` directly to hand @p to a CPU.
 *   More complex schedulers (like scx_simple) maintain a global queue: scx_simple counts
 *   tasks going to global vs local queues for stats and inserts tasks into a shared FIFO or
 *   weighted tree. The design choice here (global vs per-CPU queue,
 *   immediate vs deferred dispatch) affects the implementation of ops.dispatch. Regardless,
 *   ops.enqueue must ensure that every task will eventually get a chance to run. It’s also
 *   a point where the scheduler can set up task-specific parameters like time slice:
 *   in scx_simple, each task gets a default slice (`SCX_SLICE_DFL`) on enqueue and their
 *   virtual time is adjusted if needed. The core sets some fields (like
 *   p->scx.weight for CFS weight); the scheduler can read those. Priority or weight changes
 *   while a task is queued may not be known until the task is dequeued and re-enqueued (unless
 *   ops.set_weight is implemented). If ops.dequeue is not implemented (commonly it isn’t for
 *   simple schedulers), the core will handle cases like priority change by temporarily ignoring
 *   the BPF scheduler’s queue (the task might be dequeued in core and requeued via enqueue).
 */
void BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

/*
 * Summary:
 *   Removes a task from the BPF scheduler’s control, typically taking it out of
 *   any SCX dispatch queues or scheduling structures. This is used to temporarily
 *   isolate @p from scheduling so that its attributes (e.g. priority or weight)
 *   can be changed or it can be migrated safely.
 *
 * Trigger / Invocation:
 *   Invoked by the SCX core when a task’s scheduling state needs to be updated or
 *   it is leaving its current CPU. Common triggers include dynamic priority/weight
 *   changes, migrating @p to a different CPU, or other cases where @p must be removed
 *   from SCX-managed queues (indicated by appropriate SCX_DEQ_* flags).
 *
 * Parameters:
 *   @p:
 *     The task being dequeued. It is currently considered runnable under the BPF
 *     scheduler and may reside in a BPF-managed runqueue or dispatch queue. After
 *     this call, @p should no longer be present in any BPF scheduler queue.
 *   @deq_flags:
 *     Flags describing why @p is being dequeued (e.g. SCX_DEQ_SLEEP for sleeping,
 *     SCX_DEQ_SAVE for an attribute change, etc.). These inform the scheduler of
 *     the context (sleep, migration, update) for the removal but do not require
 *     special return handling in this function.
 *
 * Effects:
 *   Ensures that @p is removed from all BPF scheduling data structures so that the
 *   SCX core or other CPUs can safely modify @p’s scheduling parameters or place
 *   it elsewhere. If @p was queued in an SCX dispatch queue or pending for execution,
 *   it will be taken off those queues and no longer eligible for selection until
 *   it is re-enqueued. This isolation guarantees that any upcoming changes (like
 *   weight or CPU affinity updates) occur while @p is not actively scheduled by BPF.
 *
 * Concurrency / Ordering:
 *   Called with the target runqueue locked or in a context that serializes with
 *   scheduling, so @p’s state will not be concurrently modified by another CPU
 *   during removal. It may be invoked in the middle of a scheduling operation (for
 *   example, nested within ops.dispatch) when the core is adjusting @p’s status.
 *   The callback must not sleep and should execute quickly under these locking
 *   conditions. It typically precedes or coincides with a corresponding ops.quiescent()
 *   if @p is also ceasing to be runnable on a CPU.
 *
 * Invariants:
 *   After returning, @p must not be queued in any SCX scheduler list or structure.
 *   The scheduler should maintain internal consistency: any scheduling invariants
 *   (such as ordering in priority queues) should be preserved across the removal
 *   and a later re-addition of @p. This generally means @p’s removal and subsequent
 *   re-enqueue (if any) should leave the overall scheduling order consistent with
 *   the updated attributes. The SCX core will handle spurious or duplicate dequeues
 *   gracefully (keeping track of BPF ownership of @p), but the scheduler’s logic
 *   should ensure that tasks are removed exactly once per needed isolation event.
 *
 * Failure / Edge Cases:
 *   This function does not return an error code. If @p is not currently in any BPF
 *   queue (e.g. if the scheduler never queued it or it was directly dispatched),
 *   ops.dequeue can perform no action (the core will ignore a removal for a task
 *   it already considers unqueued). Not implementing this callback is safe in that
 *   the kernel will still remove @p from execution; however, leaving it unimplemented
 *   can lead to subtle issues such as @p’s scheduling position not being updated
 *   after a priority or weight change. For robust behavior (especially when using
 *   custom queuing logic), the scheduler should implement ops.dequeue to avoid
 *   stale scheduling state across attribute changes.
 */
void BPF_STRUCT_OPS(sched_dequeue, struct task_struct *p, u64 deq_flags)
{
}

/*
 * Summary:
 *   Dispatches one or more tasks from the BPF scheduler’s queues to a specific CPU’s
 *   local runqueue (dispatch queue) when that CPU has no task to run. This callback is
 *   responsible for supplying runnable tasks to idle CPUs.
 *
 * Trigger / Invocation:
 *   Invoked by the core scheduler when a CPU has exhausted its local tasks and needs
 *   more work. Specifically, when a CPU’s local DSQ (and the global DSQ) are empty at
 *   scheduling time, ops.dispatch(cpu, prev) is called to let the BPF scheduler provide
 *   tasks. This typically occurs on a context switch where the CPU has
 *   no next task, or when a CPU wakes from idle with no immediate local task. It may be
 *   called with @prev pointing to the task that was running and just got descheduled on
 *   that CPU (if that task was managed by SCX), or with @prev = NULL if
 *   the CPU was idle or the previous task was not under this scheduler. Each CPU calls
 *   dispatch independently as needed; e.g., if multiple CPUs become idle, dispatch may
 *   run concurrently on each.
 *
 * Parameters:
 *   @cpu:
 *     The index of the CPU that is requesting a task to run. This is the CPU whose
 *     local dispatch queue is empty and which is ready to receive new tasks.
 *   @prev:
 *     The task that was previously running on @cpu, if it was an SCX-scheduled task;
 *     NULL if no SCX task was running (e.g., the CPU was idle or came from a different
 *     scheduling class). If @prev is not NULL, it indicates the SCX task that just
 *     stopped running on @cpu. Notably, if @prev had exhausted its time slice but is
 *     still runnable (i.e., not sleeping), it will not yet have been enqueued elsewhere
 *     (its state `SCX_TASK_QUEUED` is false). This gives the scheduler
 *     an opportunity to continue running @prev if desired by not dispatching a new task.
 *
 * Effects:
 *   Provides tasks for @cpu to run by moving one or more tasks from the scheduler’s
 *   BPF-managed queues into @cpu’s local DSQ. In practice, the implementation will call
 *   helpers like `scx_bpf_dsq_insert()` or `scx_bpf_dsq_move_to_local()` to populate
 *   @cpu’s runqueue. For example, a global FIFO scheduler might call
 *   `scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL)` to pull the next task from a global queue
 *   into @cpu’s local queue. A scheduler with custom DSQs might insert tasks
 *   from its own structures via `scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, flags)`.
 *   The core allows up to ops.dispatch_max_batch tasks to be inserted via scx_bpf_dsq_insert
 *   in one dispatch call without an intervening move operation (to prevent long dispatch
 *   loops). Typically, dispatch will supply at least one task if any are
 *   queued. If no tasks are available in the scheduler, dispatch can leave @cpu idle by
 *   not inserting anything. If @prev is provided and still runnable, and the scheduler
 *   decides not to supply a different task, it can effectively let @prev continue executing
 *   by doing nothing (i.e., returning without dispatching a task). In that
 *   case, if ops.flags did not request forced requeue, the core will allow @prev to keep
 *   running on @cpu. Otherwise (or if @prev is NULL or not runnable), any tasks
 *   inserted into @cpu’s DSQ by this function will be scheduled immediately after this call.
 *
 * Concurrency / Ordering:
 *   ops.dispatch is called with @cpu’s scheduling lock held (preventing races on that
 *   CPU’s state). It will not be called again on the same CPU until the previous dispatch
 *   has completed. However, multiple CPUs can call dispatch in parallel. If the scheduler
 *   uses a single global queue for tasks, concurrent dispatch calls on different CPUs can
 *   race to pull from that queue. The implementation must handle such concurrency (e.g.,
 *   by using BPF spin locks around global queue operations). The core scheduling loop is:
 *   check local DSQ -> check global DSQ -> if still empty, call ops.dispatch.
 *   Therefore, dispatch is only invoked when both local and global (built-in) queues had
 *   no tasks. After ops.dispatch returns, the core will run any tasks that were inserted
 *   into the local DSQ. If none were provided, the core will attempt a final global pull
 *   and then potentially let @prev continue or go idle. In terms of ordering
 *   with other callbacks: ops.dispatch is typically called after ops.enqueue has queued
 *   tasks (the dispatch is the consumer to enqueue’s producer). It may also be called
 *   repeatedly as CPUs free up. It is not called during periods when a CPU still has tasks.
 *
 * Invariants:
 *   This function should only move tasks that are not already on a CPU. It should not
 *   attempt to directly run a task that is currently running elsewhere (the core prevents
 *   double scheduling). Any task inserted into @cpu’s local DSQ via dispatch should have
 *   its target CPU equal to @cpu (the helpers ensure this when using SCX_DSQ_LOCAL or the
 *   correct CPU ID). If ops.dispatch inserts multiple tasks, they will be queued in the
 *   order inserted; typically only one task per CPU is needed (the core will call dispatch
 *   again if the CPU becomes free again). The scheduler must respect ops.dispatch_max_batch:
 *   inserting more tasks than allowed in one go can lead to those extra insertions being
 *   ignored or delayed. If @prev is still runnable and the scheduler chooses
 *   to keep it on @cpu, dispatch must refrain from moving any new task to @cpu. The core
 *   interprets a no-dispatch (with runnable prev) as an indication to continue @prev.
 *   It’s crucial that the scheduler not both decide to continue @prev and also enqueue a
 *   new task – that would conflict. Also, if @prev was not enqueued elsewhere by this time,
 *   the core will enqueue it after dispatch returns, unless it kept running.
 *   The scheduler should maintain consistency of its internal data: e.g., if it has a
 *   custom priority queue, removing a task from it (to dispatch) must preserve the validity
 *   of that structure (perhaps by using appropriate locking).
 *
 * Failure / Edge Cases:
 *   This function does not return a value; any failure to dispatch tasks manifests as @cpu
 *   going idle despite tasks waiting, which is a performance or logic bug. If dispatch cannot
 *   find any task (scheduler queue empty), it should simply do nothing, causing @cpu to idle.
 *   If @prev is provided and marked runnable but with no tasks in queue, and the scheduler
 *   does nothing, then by default the core will allow @prev to continue executing on @cpu
 *   (unless the scheduler has set SCX_OPS_ENQ_LAST to force its enqueuing).
 *   One edge case is if @prev had its time slice exhausted and SCX_OPS_ENQ_LAST is set:
 *   in that scenario, the core will have enqueued @prev with SCX_ENQ_LAST flag instead of
 *   letting it continue, so by the time dispatch is called, @prev may already
 *   be queued (and `prev->scx.flags` will indicate it has been enqueued). The scheduler should
 *   detect that (SCX_TASK_QUEUED flag set on @prev) and treat @prev as no longer immediately
 *   runnable. Another edge case is when dispatch is called on a CPU due to an affinity change:
 *   tasks might be in transit between CPUs (ops.cpu_release / cpu_acquire might handle that
 *   in more complex schedulers; this basic scheduler does not implement those). In general,
 *   dispatch assumes all tasks it needs to consider are in its own queues. Note that BPF
 *   helpers like scx_bpf_dsq_insert cannot be called while holding a BPF spin lock (currently),
 *   so if the scheduler locks its queue, it must unlock before calling insert – or use
 *   `scx_bpf_dsq_move_to_local()` which might be safe without locks.
 *   The core will automatically handle the case where no task is dispatched: the CPU will
 *   either remain idle or, if a previous task is still eligible and SCX_OPS_ENQ_LAST is off,
 *   continue with that previous task.
 *
 * Notes:
 *   This callback is where the scheduler’s policy is applied to choose which task runs next
 *   on an idle CPU. For example, a fair scheduler might pick the task with the smallest virtual
 *   runtime from a priority queue, whereas a FIFO scheduler picks the oldest waiting task. In
 *   this implementation (based on SCX), the scheduler likely maintains a global or per-class
 *   queue of tasks. scx_simple, for instance, uses a single shared dispatch queue (ID 0)
 *   implemented as a weighted FIFO: ops.dispatch in scx_simple just moves one task from that
 *   shared queue to the requesting CPU. Some schedulers may dispatch more than
 *   one task per call if they want to load up the CPU’s local queue (e.g., to batch dispatch),
 *   but must respect dispatch_max_batch. If @prev had remaining runtime and no other task is
 *   ready, the scheduler can intentionally not dispatch anything new, which lets @prev continue
 *   (unless overridden by flags). By default, if no task is dispatched, the core will try a
 *   global queue move one more time, then either continue @prev or go idle.
 *   Schedulers can influence this behavior via flags like SCX_OPS_ENQ_LAST (which forces even
 *   solo tasks to be requeued). This particular scheduler should
 *   consider SCX_OPS_ENQ_LAST: if that flag is set, the expectation is that when a task’s slice
 *   expires, it will always go through enqueue/dispatch rather than continuing by default, so
 *   dispatch needs to handle the case where @prev is waiting in the queue even if it was the only
 *   task.
 */
void BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

/*
 * Summary:
 *   Called periodically for a running task to allow the scheduler to perform
 *   periodic accounting or preemption checks. This function represents the scheduler
 *   “tick” event for @p, giving the BPF scheduler a chance to update @p’s execution
 *   state as time progresses.
 *
 * Trigger / Invocation:
 *   Invoked by the kernel at each scheduler clock tick (typically at 1/HZ intervals)
 *   on the CPU where @p is running, as long as @p remains running under SCX and has
 *   not exhausted its time slice. This callback runs in interrupt (timer tick) context
 *   while @p is running, and will continue to be called on each tick until @p either
 *   voluntarily yields, blocks, or its allotted slice is consumed.
 *
 * Parameters:
 *   @p:
 *     The task that is currently running on the CPU when the scheduler tick occurs.
 *     It is an SCX-managed task that has not yet finished its current time slice (or
 *     for which the scheduler has not yet forced a dispatch).
 *
 * Effects:
 *   Enables the scheduler to check whether @p has consumed its allowed time slice,
 *   accumulated enough runtime to merit preemption, or needs other periodic updates
 *   (such as aging, CPU usage accounting, or latency tracking). In many SCX schedulers,
 *   this function may reduce @p->scx.slice by a fixed amount per tick and, if the slice
 *   reaches zero, trigger a reschedule by marking @p for dispatch. In this simple
 *   scheduler, leaving the body empty means no per-tick adjustments are made, and
 *   preemption is driven solely by other mechanisms (e.g., explicit slice expiration
 *   in ops.stopping or external events). The callback must be very lightweight, as it
 *   runs on every tick for running tasks.
 *
 * Concurrency / Ordering:
 *   Runs in hardirq context on the CPU where @p is running, with interrupts for that
 *   CPU already disabled. It is serialized with respect to other tick callbacks for
 *   the same CPU (no concurrent invocation on the same CPU), but different CPUs may
 *   invoke ops.tick concurrently for different tasks. It may interleave with other
 *   scheduler callbacks such as ops.running and ops.stopping, but the core ensures that
 *   ops.tick is only called while @p is actually running. Any state updates performed
 *   here must be safe in interrupt context and must not sleep.
 *
 * Invariants:
 *   At the time ops.tick is called, @p is the currently running SCX task on the CPU.
 *   The scheduler must not attempt to enqueue, dequeue, or directly reschedule tasks
 *   from this context using operations that can sleep or take non-irq-safe locks.
 *   Any invariants regarding @p’s time accounting (for example, that its slice never
 *   becomes negative) should be preserved: if the scheduler decrements @p->scx.slice,
 *   it should clamp at zero rather than underflow. The callback should not change
 *   @p’s basic run state; it should only update accounting and possibly set flags
 *   that will be acted on later in process context.
 *
 * Failure / Edge Cases:
 *   This callback does not return a value and is not expected to fail. If it is not
 *   implemented (as in this minimal scheduler), SCX still tracks basic time and can
 *   handle preemption via other callbacks, but the scheduler forfeits the opportunity
 *   to perform finer-grained periodic adjustments. Edge cases include very short-lived
 *   runs where @p is scheduled and descheduled between ticks; in such cases, ops.tick
 *   may never be called for that run, and all accounting must be handled by ops.running
 *   and ops.stopping instead.
 *
 * Notes:
 *   More sophisticated schedulers often use ops.tick to implement time-slice preemption,
 *   soft real-time budgets, or latency guarantees by monitoring runtime at each tick
 *   and deciding whether to reschedule. In this simple example, ops.tick is left empty
 *   because the policy is not time-slice driven at the tick granularity. If extended,
 *   this callback would be the natural place to integrate per-tick updates such as
 *   decrementing per-task budgets or updating per-CPU statistics.
 */
void BPF_STRUCT_OPS(sched_tick, struct task_struct *p)
{
}

/*
 * Summary:
 *   Notifies the scheduler that a task has become runnable on a CPU. This marks
 *   the start of @p’s runnable period on that CPU and allows the scheduler to
 *   maintain accounting or state for tasks that are eligible to run.
 *
 * Trigger / Invocation:
 *   Called by the SCX core when @p transitions into the runnable state on a CPU.
 *   Typical triggers include wakeup from sleep, migration to a new CPU, or restoration
 *   from a quiescent state. This notification may occur without an immediate ops.enqueue()
 *   (for example, when @p is restored and already has a place in the runqueue), and
 *   conversely, ops.enqueue() may be called without a preceding ops.runnable() in some
 *   edge cases (such as slice exhaustion handling). It is part of the sequence of
 *   callbacks that track @p’s lifecycle: runnable → running → stopping → quiescent.
 *
 * Parameters:
 *   @p:
 *     The task that has just become runnable on a CPU. @p is now eligible to be
 *     scheduled, though it may not yet have been enqueued in a specific DSQ or
 *     runqueue. Its state reflects that it can run when selected.
 *   @enq_flags:
 *     A bitmask of SCX_ENQ_* flags describing the context in which @p became runnable
 *     (e.g., wakeup, migration, or re-enqueue). These flags mirror those used by
 *     ops.enqueue() and can be used to distinguish between different runnable events.
 *
 * Effects:
 *   Allows the BPF scheduler to update any internal state or statistics related to
 *   @p becoming runnable. This might include incrementing counters of runnable tasks,
 *   recording timestamps for wait-time accounting, or marking @p as eligible in any
 *   auxiliary data structures. The callback should not itself enqueue @p into a BPF
 *   queue; that responsibility belongs to ops.enqueue() when the core decides to
 *   queue @p. Instead, ops.runnable should be treated as a notification hook to keep
 *   the scheduler’s internal view of task states synchronized with the core.
 *
 * Concurrency / Ordering:
 *   Invoked in a scheduling context where @p’s state transition to runnable is
 *   serialized with other operations on the same CPU’s runqueue. Different CPUs may
 *   call ops.runnable concurrently for different tasks. For a given CPU and task, an
 *   ops.runnable() call is eventually paired with an ops.quiescent() when @p stops
 *   being runnable there (for example, when it blocks, migrates away, or exits).
 *   There is no guarantee that ops.runnable is called immediately before ops.enqueue,
 *   but the two will often appear close together in the wake-up or migration path.
 *
 * Invariants:
 *   After ops.runnable is called, @p should be treated by the scheduler as part of
 *   the CPU’s runnable population until a corresponding ops.quiescent is delivered
 *   (or the scheduler is unloaded). The scheduler must ensure that any per-CPU or
 *   global counts of runnable tasks remain consistent with these notifications.
 *   This callback should not change @p’s location in queues or its dispatch position;
 *   it is purely informational. If the scheduler uses its own bookkeeping for
 *   runnable sets, ops.runnable is the correct place to add @p to such accounting.
 *
 * Failure / Edge Cases:
 *   This callback does not return a value. If it is not implemented, the SCX core
 *   still manages runnable state correctly, but the BPF scheduler loses the chance to
 *   track when tasks become runnable (e.g., for latency accounting). The implementation
 *   should handle the possibility that ops.runnable is called in situations where no
 *   subsequent ops.enqueue occurs (for instance, if @p directly continues running or
 *   is immediately dispatched elsewhere), and ensure that internal state remains
 *   consistent across such patterns.
 *
 * Notes:
 *   In more complex schedulers, ops.runnable is often used to record the timestamp
 *   when a task becomes runnable, so that the time spent waiting before it runs can
 *   be measured when ops.running is later invoked. This minimal scheduler does not
 *   currently use ops.runnable, but the hook exists to support such accounting and
 *   policy decisions if extended.
 */
void BPF_STRUCT_OPS(sched_runnable, struct task_struct *p, u64 enq_flags)
{
}

/*
 * Summary:
 *   Notification that a task has started running on a CPU. Marks the transition of
 *   the task into the executing state on its assigned processor, allowing the scheduler
 *   to perform any bookkeeping for task start.
 *
 * Trigger / Invocation:
 *   Called on the CPU whenever a task scheduled by this BPF scheduler is actually
 *   context-switched in and begins execution on that CPU. It is part
 *   of the sequence of notifications around a task’s lifecycle: ops.runnable (task
 *   becomes runnable) → ops.running (task starts running) → ops.stopping (task stops
 *   running) → ops.quiescent (task is no longer runnable). ops.running is invoked
 *   after the task has been selected to run (via enqueue/dispatch) and right as it
 *   begins consuming CPU time. It is only called for tasks that are actually executing
 *   under this scheduler; idle tasks or tasks from other scheduling classes do not
 *   trigger this callback.
 *
 * Parameters:
 *   @p:
 *     The task that has just begun running on the current CPU. At this point, @p is
 *     in the RUNNING state under sched_ext control, and its p->scx fields reflect
 *     the scheduling parameters that were in effect when it was dispatched.
 *
 * Effects:
 *   Allows the scheduler to perform per-run bookkeeping when @p starts running. This
 *   might include recording the start time of this run segment, updating statistics,
 *   or adjusting @p’s scheduling metadata. For instance, a scheduler using virtual time
 *   might snapshot the current global virtual time into @p’s fields, or update a
 *   “last start” timestamp used for lag calculations. In example schedulers like
 *   scx_simple, ops.running updates `vtime_now` so that the task’s virtual time is
 *   not ahead of the global baseline when it starts running. This ensures that
 *   tasks that waited a long time do not unfairly benefit when they finally run.
 *   This callback does not decide which CPU to run on (that’s select_cpu/dispatch),
 *   nor does it manage runqueue membership – it purely reacts to the fact that @p is
 *   now executing. It should be lightweight and non-blocking.
 *
 * Concurrency / Ordering:
 *   ops.running is called in the context of the CPU on which @p is running, typically
 *   with that CPU’s runqueue lock held or in a context that prevents concurrent
 *   scheduling changes for that CPU. It is not called concurrently for the same task:
 *   a given task cannot start running twice without first stopping (ops.stopping) in
 *   between. However, different tasks can trigger ops.running concurrently on different
 *   CPUs. The ordering relative to other callbacks is:
 *     - ops.runnable is usually called before ops.running when a task becomes runnable.
 *     - ops.running is called right before @p starts executing.
 *     - ops.stopping is called when @p stops executing.
 *     - ops.quiescent is called if @p becomes non-runnable afterwards.
 *   The scheduler can rely on this ordering to partition a task’s CPU usage into
 *   well-defined segments.
 *
 * Invariants:
 *   At the time of ops.running, @p is on exactly one CPU and is the currently executing
 *   task there (except possibly for short windows where the core manages context-switch
 *   bookkeeping). The implementation must not modify core scheduler state; it should
 *   only touch BPF-managed fields (e.g., p->scx or BPF maps). Any per-task or global
 *   invariants that relate to “task is running” may be established here, such as setting
 *   a flag indicating that @p is on-CPU if the scheduler tracks that explicitly.
 *   However, most sched_ext schedulers rely on the core’s notion of running vs runnable
 *   and do not duplicate that. ops.running should not enqueue or dequeue tasks; its job
 *   is to account for and react to @p starting execution.
 *
 * Failure / Edge Cases:
 *   This callback does not return a value and is not expected to fail. Any serious error
 *   (e.g., an invariant violation) could be reported via scx_bpf_error to trigger a
 *   scheduler unload, but normally ops.running performs small and safe updates that
 *   cannot fail. Edge cases include very short runs where @p is preempted almost
 *   immediately – ops.running will still be called, followed quickly by ops.stopping.
 *   The scheduler’s accounting should handle such short segments correctly (it may
 *   effectively charge a full slice or a small amount of time, depending on policy).
 *   Another edge case is if @p migrates to another CPU around the time of running;
 *   the core ensures that ops.running sees @p on the new CPU and that prior CPU’s
 *   state is cleaned up, so no special handling is typically needed.
 *
 * Notes:
 *   This callback, along with ops.stopping (and ops.runnable/ops.quiescent, if used),
 *   helps partition a task’s execution into segments for accounting. Many BPF schedulers
 *   use ops.running to record or adjust virtual time. For instance, scx_simple updates the
 *   global `vtime_now` to ensure it is not less than the virtual start time of the task
 *   that’s now running. That means if a task had accumulated a large lag (vruntime)
 *   while waiting, the global reference is caught up when it starts, so that lag isn’t
 *   ignored. Other possible uses include setting a flag that a task is currently running
 *   (if needed for debugging) or updating cumulative CPU usage counters. Since the kernel
 *   already tracks per-task CPU time, a BPF scheduler typically doesn’t need to replicate
 *   that, but it might maintain its own metrics. In summary, ops.running is a chance for
 *   the scheduler to react right as a task begins using the CPU, e.g., to update fair
 *   scheduling metrics or log that event.
 */
void BPF_STRUCT_OPS(sched_running, struct task_struct *p)
{
}

/*
 * Summary:
 *   Notification that a task has stopped running on a CPU. Called at the end of the
 *   task’s time slice or when it is preempted or voluntarily yields or blocks. Allows
 *   the scheduler to perform accounting for the run that just finished and prepare the
 *   task’s state for what comes next (either requeue or quiescence).
 *
 * Trigger / Invocation:
 *   Invoked whenever a task that was running under sched_ext is being descheduled
 *   (context-switched out) on a CPU. Common triggers include:
 *   - The task’s time slice expired.
 *   - The task voluntarily yielded or is going to sleep (blocking on I/O, etc.).
 *   - The task is preempted by a higher priority task.
 *   - The task is being removed due to migration or priority/affinity change.
 *   It is typically called on the CPU where the task was running, at the moment of
 *   context switch. However, it can be called from a different CPU if the task is
 *   being forced off its CPU (e.g., affinity change from another CPU’s context).
 *   In such cases, the task might already be stopped on its original CPU but the callback
 *   executes on another. This callback precedes ops.quiescent if the task is no longer
 *   runnable, or precedes a subsequent enqueue if the task remains runnable. It will
 *   be paired with a prior ops.running for the same running period on that task.
 *
 * Parameters:
 *   @p:
 *     The task that is stopping execution on a CPU. It was the currently running task
 *     and is now being taken off CPU.
 *   @runnable:
 *     A boolean indicating whether @p is still runnable (true) or not (false) at the
 *     moment of stopping. If true, @p is still in a runnable state and
 *     will likely be re-queued (for example, its time slice expired but it did not block,
 *     so it should go back into a runqueue). If false, @p is becoming non-runnable (e.g.,
 *     going to sleep or exiting), so it will enter quiescent state after this.
 *
 * Effects:
 *   Performs end-of-run bookkeeping for @p. Typically, this involves accounting for the CPU
 *   time that @p consumed during its last run on the CPU and updating its scheduling
 *   parameters (like virtual runtime or accumulated runtime). For instance, in a weighted
 *   fair scheduler, ops.stopping would calculate how much of the time slice was used and
 *   add the corresponding weighted runtime to @p’s virtual time. In scx_simple, this
 *   callback adds `(SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight` to p->scx.dsq_vtime,
 *   charging the task for the CPU time it used (any remaining slice is treated as if used).
 *   This effectively updates @p’s position in the fair scheduling order. If @p yielded early,
 *   the core may have set p->scx.slice = 0 to indicate it gave up the rest of its slice,
 *   and the accounting logic would then charge the full slice (as scx_simple does) or otherwise
 *   handle it. If @runnable is true, @p will be enqueued again either by the core or explicitly
 *   by the scheduler, so ops.stopping may prepare it for requeue (for example, updating its
 *   vruntime before it goes back into a queue). If @runnable is false, the task is leaving the
 *   runnable state, and ops.stopping is the last chance to account for its runtime on this CPU;
 *   ops.quiescent will follow to mark it quiescent, but quiescent should not need to change
 *   accounting. This function should not itself enqueue @p or alter its queued state; those
 *   actions happen via ops.enqueue or by core logic after this returns. It should also avoid
 *   heavy computation or any blocking operations. Generally, ops.stopping completes any
 *   calculations that require knowing how much runtime @p got and possibly resets or updates
 *   fields like p->scx.slice or similar if needed by the scheduler (though typically the core
 *   resets the slice when requeuing).
 *
 * Concurrency / Ordering:
 *   Called in the context of a context switch, often on the same CPU that @p was running on,
 *   with locks held preventing concurrent modifications to that CPU’s runqueue. In normal
 *   cases, ops.stopping is executed on @p’s CPU. However, as noted, it can be invoked on a
 *   different CPU in scenarios like an affine migration: e.g., if a task’s affinity is changed
 *   while it’s running, another CPU might handle the removal (via `dequeue_task_scx`) and thus
 *   call ops.stopping for that task. The implementation should therefore use
 *   `scx_bpf_task_cpu(p)` if it needs to know the original CPU of execution. Only
 *   one ops.stopping will run for a given running period of @p (the next ops.stopping for @p
 *   will occur after a subsequent ops.running). Different CPUs may execute ops.stopping in
 *   parallel for different tasks. The call precedes either an ops.enqueue (if @runnable true)
 *   or ops.quiescent (if @runnable false) for @p in the overall sequence.
 *
 * Invariants:
 *   Must accurately account for all CPU time consumed by @p during its run. If the scheduler
 *   uses a virtual time or credit system, it must update those values now. For example, the
 *   invariant in scx_simple is that the sum of all tasks’ p->scx.dsq_vtime increases roughly
 *   in step with real time weighted by their weights; ops.stopping maintains that by adding the
 *   appropriate amount to @p’s dsq_vtime. The scheduler should preserve any ordering
 *   properties of its runqueue – e.g., if @p’s position in a sorted queue depends on its virtual
 *   runtime, updating that here ensures that when @p is enqueued next, it goes to the correct
 *   position. The scheduler must not modify core state; it should confine its changes to BPF
 *   scheduler state (fields in p->scx or its own data structures). It should not attempt to
 *   directly requeue @p; the core will handle requeueing by calling ops.enqueue (unless the
 *   scheduler uses some custom mechanism). It also should not free any resources here – even if
 *   @p is about to sleep or exit, final cleanup belongs in ops.exit_task or elsewhere. If @p’s
 *   weight or other attributes changed during its run, those are already reflected in p->scx;
 *   ops.stopping just uses the current values. It should avoid floating-point or large divisions
 *   in kernel context; use integer math as in the example. If remote invocation occurs, invariants
 *   include using the correct CPU context for accounting (again, use scx_bpf_task_cpu(p) if needed).
 *
 * Failure / Edge Cases:
 *   No return value. There is no failure path expected for ops.stopping – it’s purely internal
 *   bookkeeping. Edge cases:
 *   - If @p used no CPU time (e.g., it yielded immediately after being scheduled), p->scx.slice
 *     might still be full (or set to zero by yield). The accounting should handle that (in scx_simple,
 *     a yield leads to treating it as full slice used via slice=0 logic).
 *   - If @p’s weight is extremely high or low, the runtime scaling should not overflow 64-bit; in
 *     scx_simple, weights are bounded (1..10000) so the computation is safe from overflow.
 *   - If called from another CPU (affinity change), ensure using the correct CPU’s context if any
 *     per-CPU data (this basic scheduler likely doesn’t have per-CPU accounting beyond global vtime).
 *   - In a scenario where @p is the only task on its CPU and SCX_OPS_ENQ_LAST is not set, the core
 *     might not actually preempt @p at slice end but continue it; in such a case ops.stopping wouldn’t
 *     be called until the task truly stops (so no edge to handle there, it’s by design).
 *   - If @p is exiting, @runnable will be false and ops.stopping will be followed by ops.quiescent and
 *     then ops.exit_task (if implemented). The scheduler might not need to do anything special for exit
 *     beyond regular accounting here.
 *
 * Notes:
 *   This function, paired with ops.running, implements the core of time accounting for the BPF
 *   scheduler’s policy. In many schedulers, ops.stopping is where the “virtual runtime” or other
 *   key scheduling metric is updated for the task. For instance, scx_simple’s approach treats each
 *   time slice as a fixed unit and charges the task’s vruntime in proportion to CPU time used and
 *   inversely proportional to weight. More sophisticated schedulers could measure the
 *   actual elapsed time (using a helper like bpf_ktime_get_ns()) if they needed more precise accounting,
 *   but most examples rely on slice accounting for simplicity. If a task yields or is preempted early,
 *   some schedulers may choose to give it credit for unused time (to be more fair to I/O-bound tasks);
 *   scx_simple does not – it penalizes yielding tasks by treating remaining slice as used.
 *   Such policy decisions are encoded in ops.stopping. Another consideration: ops.stopping can also be
 *   used to detect when a task’s state changes. If @runnable is false here, the scheduler knows the task
 *   is entering sleep; it might record that (though ops.quiescent will also fire). If @runnable is true,
 *   this is a routine time-slice end or preemption. In summary, ops.stopping is central to maintaining
 *   scheduler invariants like fairness and tracking CPU usage in the BPF scheduler.
 */
void BPF_STRUCT_OPS(sched_stopping, struct task_struct *p, bool runnable)
{
}

/*
 * Summary:
 *   Signals that a task is no longer runnable on its current CPU, indicating the end
 *   of @p’s runnable period on that CPU. This is the counterpart to ops.runnable(),
 *   marking that @p has transitioned to a quiescent (not running and not queued) state
 *   on the CPU due to blocking, migration, or other removal.
 *
 * Trigger / Invocation:
 *   Invoked by the SCX core when @p is leaving the runnable state on a CPU. Typical
 *   triggers include @p going to sleep or blocking (SCX_DEQ_SLEEP), @p being migrated
 *   away to a different CPU, or @p being temporarily removed for a scheduling attribute
 *   update (SCX_DEQ_SAVE). It is called after @p has stopped running and is about to
 *   or has been removed from any runqueue on that CPU. If @p was running, ops.quiescent()
 *   follows an ops.stopping(p, false); if @p was dequeued without running (e.g., for
 *   migration or reprioritization), this may be called without an immediately preceding
 *   ops.stopping().
 *
 * Parameters:
 *   @p:
 *     The task becoming quiescent (no longer runnable) on the CPU. Prior to this call,
 *     @p was considered runnable on this CPU (and may have been actively running or
 *     waiting to run). After this call, @p will not be scheduled on this CPU unless
 *     and until it becomes runnable here again in the future.
 *   @deq_flags:
 *     Flags indicating the reason for quiescence, corresponding to SCX_DEQ_* values
 *     (e.g., SCX_DEQ_SLEEP if @p is blocking, SCX_DEQ_SAVE if @p was removed for an
 *     update). These flags mirror those passed to ops.dequeue() if one preceded this
 *     transition, but ops.quiescent may be called even in cases where ops.dequeue()
 *     was not (for example, when @p is dispatched directly to another CPU).
 *
 * Effects:
 *   Allows the BPF scheduler to update its internal state now that @p is no longer
 *   an active candidate for scheduling on this CPU. This typically involves removing
 *   or marking @p as absent from any local runqueue accounting, clearing any CPU-specific
 *   state (such as binding or priority hints) associated with @p, and possibly logging
 *   or measuring the runtime that just concluded. Essentially, the scheduler finalizes
 *   @p’s execution period on this CPU: for instance, it could record how long @p was
 *   runnable or accumulate usage statistics to inform future scheduling decisions.
 *
 * Concurrency / Ordering:
 *   Called with scheduling locks held, serializing with other operations on this CPU’s
 *   runqueue. If @p was running and stopped, this call occurs after ops.stopping() in
 *   the context of the context-switch or scheduling operation that took @p off CPU.
 *   If @p was not running (just queued) and is being removed (e.g., due to migration),
 *   ops.quiescent() may be invoked in that removal path. The callback must not sleep
 *   and should execute briefly. It pairs with a previous ops.runnable() call for this
 *   CPU; no further ops.running() or ops.stopping() will occur for @p on this CPU unless
 *   it becomes runnable here again later.
 *
 * Invariants:
 *   Every ops.runnable() on a CPU has a matching ops.quiescent() to mark the end of
 *   that runnable period (unless the scheduler program is unloaded or @p exits earlier,
 *   in which case cleanup occurs via other paths). After ops.quiescent(), @p is no
 *   longer counted in this CPU’s runnable task set. The scheduler should ensure that
 *   any per-CPU data for @p (like positions in local data structures or counters) are
 *   cleaned up. Note that ops.quiescent is not required to actually dequeue @p (the
 *   core handles the removal); it should simply update the scheduler’s view that @p
 *   is no longer active on this CPU.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If not implemented, the scheduler will
 *   not receive explicit notification when tasks become quiescent, which may lead
 *   to stale internal accounting (e.g., thinking a task is still on a CPU when it
 *   isn’t). It is advisable to implement it if ops.runnable() is implemented, to
 *   maintain balanced state tracking. Edge cases include scenarios where @p’s removal
 *   was handled entirely by the core (e.g., direct dispatch to another CPU without
 *   a prior ops.dequeue()); ops.quiescent may still be called in such cases to inform
 *   BPF that @p left, even though ops.dequeue was not called. The implementation
 *   should be robust to being called when @p is already not present in scheduler
 *   queues (as the core ensures the actual removal). No special handling is needed
 *   beyond updating internal state; double-removal situations are handled by the core
 *   tracking BPF ownership of @p.
 */
void BPF_STRUCT_OPS(sched_quiescent, struct task_struct *p, u64 deq_flags)
{
}

/*
 * Summary:
 *   Handles a voluntary yield of the CPU by a running task, possibly allowing a specific
 *   target task to run in its place. This callback gives the scheduler control over how
 *   a yield by @from is implemented, whether yielding to any task or a particular task.
 *
 * Trigger / Invocation:
 *   Invoked when @from calls yield (either a generic sched_yield or a directed yield
 *   to a particular task). This occurs in @from’s execution context during a scheduling
 *   operation initiated by the yield. The SCX core calls ops.yield() as it prepares
 *   to switch @from out. If @to is NULL, the yield is unspecified (just relinquish CPU
 *   to whoever is available); if @to is non-NULL, it indicates @from specifically wishes
 *   to yield to @to. The callback is executed while @from is still considered running,
 *   typically with the CPU’s runqueue lock held.
 *
 * Parameters:
 *   @from:
 *     The currently running task that is yielding the CPU. This task is an SCX-managed
 *     task that has invoked a yield operation and is in the process of being descheduled.
 *   @to:
 *     The task to yield to, if a specific target was requested (otherwise NULL for a
 *     generic yield). This will be another SCX-managed task that is runnable (or will
 *     soon be runnable). If provided, @to might be intended to run on the same CPU
 *     as @from immediately after yielding.
 *
 * Effects:
 *   If @to is NULL (general yield): The scheduler should ensure that @from does not
 *   immediately resume on this CPU until at least one other ready task has been run.
 *   Typically, the implementation will arrange for @from to be placed at the back of
 *   the scheduling queue (or its time slice marked as consumed) so that other tasks
 *   get priority. The return value in this case is ignored by the core; the scheduler’s
 *   logic (possibly combined with SCX_OPS_ENQ_LAST flag behavior) should delay @from’s
 *   next execution appropriately.
 *
 *   If @to is not NULL (targeted yield): The scheduler can attempt to give @to precedence
 *   on the CPU. If the scheduler can immediately schedule @to to run next (for example,
 *   if @to is waiting on this CPU’s runqueue or can be migrated here), it should implement
 *   that and return true. Otherwise, if it cannot honor the request (e.g., @to is not
 *   readily runnable on this CPU or scheduling a specific handoff is not supported), it
 *   returns false, and the yield will be treated as a normal yield without guarantee of
 *   @to running next.
 *
 * Concurrency / Ordering:
 *   Called as part of a scheduling context switch, typically with interrupts disabled
 *   and the runqueue locked on the CPU of @from. It occurs just before @from is about to
 *   stop running (and before ops.stopping is called for @from). If @to is specified
 *   and the scheduler returns true, the core expects that the scheduler has effectively
 *   arranged for @to to run on this CPU next. The ordering relative to ops.stopping()
 *   is that ops.yield runs while @from is still on-CPU; ops.stopping will be called
 *   afterwards when @from is actually taken off.
 *
 * Invariants:
 *   The scheduler must not attempt to sleep or take non-irq-safe locks here, as this
 *   callback runs inside the core’s scheduling critical section. If returning true
 *   for a directed yield, the scheduler should ensure that @to is indeed runnable and
 *   locally available to run next; otherwise, core behavior may diverge from the caller’s
 *   expectations. For generic yields, the scheduler should guarantee that @from is not
 *   selected to run again immediately on the same CPU; at minimum, @from should be
 *   reinserted in a position that lets at least one other runnable task run first,
 *   if such a task exists.
 *
 * Failure / Edge Cases:
 *   Returning false for a targeted yield simply means the scheduler cannot guarantee
 *   @to will run next; the core will proceed with normal scheduling. If ops.yield is
 *   not implemented, all yields are treated as generic relinquish operations with
 *   default behavior. Edge cases include @to not being runnable or being bound to another
 *   CPU; in such cases, the scheduler should conservatively return false rather than
 *   forcing migration, unless its policy explicitly supports that. Another edge case
 *   is when @from is the only runnable task; a yield in that situation may result in
 *   @from continuing to run, which is acceptable.
 */
bool BPF_STRUCT_OPS(sched_yield, struct task_struct *from, struct task_struct *to)
{
	return false;
}

/*
 * Summary:
 *   Provides an ordering decision between two runnable tasks for core scheduling
 *   (core-sched). It indicates whether @a should be considered to have higher
 *   priority than @b when the core needs to choose an execution order.
 *
 * Trigger / Invocation:
 *   Invoked by the core scheduling subsystem when it needs to determine ordering
 *   between two tasks that may run concurrently on different logical CPUs in a
 *   core-scheduling domain. This may occur irrespective of whether the tasks are
 *   currently queued by the BPF scheduler; the core may query ordering for tasks
 *   that are simply candidates for co-scheduling.
 *
 * Parameters:
 *   @a:
 *     The first task in the comparison. @a is an SCX-managed task that may be
 *     runnable or about to become runnable.
 *   @b:
 *     The second task in the comparison. @b is similarly an SCX-managed task.
 *
 * Effects:
 *   Returns true if @a is considered to have higher priority (should run before)
 *   @b from the perspective of core scheduling; returns false otherwise. The core
 *   may use this to enforce an ordering when running tasks that share hardware
 *   resources (e.g., SMT siblings), potentially to mitigate side channels or to
 *   implement core-level policies. This callback does not directly modify any
 *   scheduler state; it is a pure comparison function.
 *
 * Concurrency / Ordering:
 *   Called in contexts where both @a and @b may be examined concurrently with other
 *   scheduling operations. It must be lockless or use only safe read-side primitives,
 *   since taking heavy locks here can affect scheduling latency. The core may call
 *   it repeatedly as it evaluates different candidate pairs, so it should be quick.
 *   There is no fixed ordering with respect to other callbacks (e.g., ops.enqueue);
 *   it may be invoked whenever the core needs an ordering decision.
 *
 * Invariants:
 *   The decision returned should be consistent for the same pair of tasks given the
 *   same underlying state; it should not depend on transient side effects in this
 *   function. The scheduler should avoid modifying @a or @b or global structures here.
 *   If the scheduler implements a meaningful ordering (e.g., based on weight or
 *   priority), it should ensure that the comparison is antisymmetric and reasonably
 *   stable (if a is before b, then b is not before a in the same state).
 *
 * Failure / Edge Cases:
 *   Returning false indicates that either @b should run first or that the scheduler
 *   has no particular ordering preference. If ops.core_sched_before is not implemented,
 *   the core falls back to its default ordering rules. In this simple scheduler, the
 *   implementation always returns false, meaning no custom core-sched ordering is
 *   applied and the default core behavior is used.
 */
bool BPF_STRUCT_OPS(sched_core_sched_before, struct task_struct *a, struct task_struct *b)
{
	return false;
}

/*
 * Summary:
 *   Updates a task’s weight (scheduling priority or share) within the BPF scheduler.
 *   This callback applies a new weight value to @p, altering how @p will be treated
 *   in scheduling (for example, in proportional share or virtual time calculations).
 *
 * Trigger / Invocation:
 *   Invoked when @p’s scheduling weight is changed externally. This can happen due
 *   to a user action such as changing @p’s nice value or writing to a cgroup’s
 *   cpu.weight, or any operation that adjusts @p’s weight attribute within SCX. The
 *   SCX core calls ops.set_weight() after isolating @p (via ops.dequeue()) so that
 *   the weight change can be applied while @p is not actively scheduled. It is
 *   typically called in process context (e.g., the thread adjusting the priority)
 *   and not from an interrupt.
 *
 * Parameters:
 *   @p:
 *     The task whose weight is being updated. @p is an SCX task that was runnable or
 *     queued, and at the time of this call it has been removed from scheduling queues
 *     (the core ensures @p is dequeued if it was enqueued, to safely change its weight).
 *   @weight:
 *     The new weight value for @p, in the range [1..10000]. This weight represents
 *     @p’s relative scheduling weight (100 being default normal priority if mirroring
 *     cgroup conventions). The value is already validated to be within range by the core.
 *
 * Effects:
 *   The scheduler should update @p’s internal weight to the provided value. In practice,
 *   this often means setting p->scx.weight = weight. Any scheduler-specific state that
 *   depends on @p’s weight (for example, virtual runtime calculations, dynamic time slice
 *   allocations, or position in a weighted fair queue) should be recomputed or adjusted
 *   as needed. Because the core typically dequeues @p before calling this, @p is not in
 *   any runqueue at this moment, so the weight can be changed without immediately
 *   reordering any queue. After returning, the core may re-enqueue @p (via ops.enqueue())
 *   with the new weight in effect.
 *
 * Concurrency / Ordering:
 *   This callback runs in atomic context and must not sleep. The core ensures
 *   serialization of weight updates with respect to scheduling: @p is not actively
 *   running or queued while its weight is being set, preventing race conditions in
 *   updating weight-based metrics. Typically, ops.set_weight() will be followed by
 *   ops.enqueue() (or ops.runnable()) to place @p back if it remains runnable. The
 *   scheduler should not manipulate runqueue structures here beyond updating per-task
 *   weight fields.
 *
 * Invariants:
 *   After this call, @p’s weight attribute in the scheduler must equal the new value.
 *   This ensures that any future scheduling decisions or computations reflect the updated
 *   priority of @p. If the scheduler caches or scales weights (for example, computing a
 *   decay factor or inverse weight for vtime calculations), those cached values should
 *   be updated consistently. The relative ordering of tasks by weight should now include
 *   @p’s new weight: if @p’s weight increased significantly, @p should be able to gain
 *   more CPU time in the future, and vice versa for a weight decrease.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. It is assumed to succeed in updating the
 *   in-memory fields. If not implemented, changes to @p’s weight will not be visible
 *   to the BPF scheduler’s logic (though the core will still update p->scx.weight
 *   internally), potentially causing the scheduler to ignore priority changes. Edge
 *   cases include weight changes for a task that is idle or about to exit (the core
 *   will still call this if applicable, but changing a soon-to-exit task’s weight
 *   has little effect on scheduling).
 */
void BPF_STRUCT_OPS(sched_set_weight, struct task_struct *p, u32 weight)
{
}

/*
 * Summary:
 *   Adjusts a task’s allowed CPU affinity within the scheduler. This callback informs
 *   the BPF scheduler that @p’s CPU mask has changed, so the scheduler can respond
 *   (e.g., by migrating @p or updating any CPU binding state).
 *
 * Trigger / Invocation:
 *   Invoked when @p’s CPU affinity (cpumask) is modified, typically via a system call
 *   (sched_setaffinity) or cgroup cpuset change. The SCX core calls ops.set_cpumask()
 *   after updating @p’s cpus_ptr to the new mask. If @p is currently running or queued
 *   on a CPU that is no longer allowed, the core will take steps to move or dequeue @p
 *   (for example, calling ops.dequeue() and possibly ops.quiescent() for the old CPU)
 *   before this callback. This is called in process context of the changer or a migration
 *   thread, with appropriate locking to prevent concurrent scheduling changes for @p.
 *
 * Parameters:
 *   @p:
 *     The task whose CPU affinity was changed. @p is an SCX-managed task that may need
 *     to move to comply with its new allowed CPU set. By the time of this call, @p’s
 *     task_struct affinity mask (p->cpus_ptr) reflects the updated set of allowed CPUs.
 *   @cpumask:
 *     A pointer to the cpumask representing the new allowed CPUs for @p. This mask
 *     is the new constraint on where @p may run. It is provided as const; the scheduler
 *     should not modify it, but can use it to guide any migration or placement decisions.
 *
 * Effects:
 *   The scheduler should update any internal tracking of @p’s preferred or last CPU,
 *   and ensure that @p is now considered only for the CPUs allowed by @cpumask. If @p
 *   was on a disallowed CPU, the scheduler should arrange for @p to be moved. In practice,
 *   the core might already remove @p from that CPU’s runqueue before calling this, but
 *   the BPF scheduler may need to, for example, push @p into a global queue or another
 *   CPU’s queue that is within the new mask. If @p had a scheduler-specific CPU binding
 *   (like a “sticky” CPU hint or was part of a per-CPU queue structure), those should
 *   be cleared or updated to fit the new mask.
 *
 * Concurrency / Ordering:
 *   Called with the necessary locks such that @p’s current scheduling context is stable
 *   (for example, the core will hold @p’s runqueue lock and possibly other synchronization
 *   to ensure @p isn’t being scheduled while its affinity is changing). The callback
 *   runs in atomic context (not sleepable) and should finish quickly. Typically, it is
 *   called before @p is re-queued or dispatched elsewhere with the new mask, and possibly
 *   after ops.dequeue() if @p was currently enqueued.
 *
 * Invariants:
 *   After this call, the scheduler must treat @p as only runnable on the CPUs allowed
 *   by @cpumask. Any prior CPU preference that conflicts with @cpumask (for instance,
 *   if @p was “anchored” to a CPU now excluded) should be dropped. If the scheduler
 *   maintains per-CPU data for tasks (like membership in a CPU’s runqueue structure),
 *   @p should be removed from any disallowed CPU’s structures. If @p is still runnable,
 *   it should eventually be placed on an allowed CPU’s queue (possibly via core invoking
 *   ops.enqueue() on an allowed CPU or global queue dispatch). The scheduler should
 *   ensure not to violate the new affinity: it should not schedule @p on any CPU outside
 *   @cpumask after this point.
 *
 * Failure / Edge Cases:
 *   This callback does not return a value. If not implemented, the core will still
 *   enforce the affinity at dispatch time (the SCX core will not run @p on disallowed
 *   CPUs), but the BPF scheduler might not proactively redistribute @p, which can lead
 *   to suboptimal load balancing or idle CPUs. Edge cases include masks that temporarily
 *   have no online CPUs (e.g., misconfiguration); in such cases, the core will keep @p
 *   unscheduled until a valid CPU is available, and the scheduler does not need to take
 *   additional action beyond respecting the mask.
 */
void BPF_STRUCT_OPS(sched_set_cpumask, struct task_struct *p, const struct cpumask *cpumask)
{
}

/*
 * Summary:
 *   Notifies the scheduler that a CPU has entered or left the idle state. This allows
 *   the BPF scheduler to track per-CPU idleness and decide how to dispatch tasks
 *   (for example, preferring idle CPUs when assigning work).
 *
 * Trigger / Invocation:
 *   Invoked whenever the SCX core detects that @cpu’s idle state has changed. When
 *   @idle is true, the CPU has become idle (no SCX task currently running); when
 *   @idle is false, the CPU has transitioned from idle to having work. Implementing
 *   this callback generally disables the built-in idle tracking unless
 *   SCX_OPS_KEEP_BUILTIN_IDLE is set; in that case, select_cpu and other callbacks
 *   must use this notification to maintain their own view of idleness.
 *
 * Parameters:
 *   @cpu:
 *     The CPU whose idle state changed.
 *   @idle:
 *     True if the CPU is entering idle; false if it is leaving idle.
 *
 * Effects:
 *   Allows the scheduler to update any internal representation of which CPUs are idle,
 *   which can influence decisions in ops.select_cpu and ops.dispatch. For example,
 *   the scheduler may maintain a bitmap or list of idle CPUs and use it to quickly
 *   find targets for newly runnable tasks. When @idle is true, the scheduler may add
 *   @cpu to its idle set; when false, it should remove @cpu. This callback does not
 *   itself enqueue tasks; it only tracks CPU state.
 *
 * Concurrency / Ordering:
 *   Called in contexts where CPU state is changing, potentially concurrently for
 *   different CPUs. The implementation must be lock-safe and non-blocking. It may
 *   run close in time to ops.dispatch or ops.select_cpu; the scheduler should ensure
 *   that its idle-tracking data structures remain consistent despite such interleaving.
 *
 * Invariants:
 *   After this callback, the scheduler’s internal notion of which CPUs are idle should
 *   match the core’s state for @cpu. If SCX_OPS_KEEP_BUILTIN_IDLE is not set, the
 *   scheduler must rely on these notifications and its own tracking rather than any
 *   built-in idle masks. The scheduler should avoid double-marking or forgetting to
 *   clear @cpu in its idle set to prevent suboptimal scheduling decisions.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If not implemented, the scheduler relies
 *   entirely on built-in idle tracking (if enabled), and ops.select_cpu must be written
 *   accordingly. Edge cases include brief idle transitions where a CPU enters idle and
 *   immediately finds work; the scheduler’s idle bookkeeping should handle such short
 *   intervals without becoming inconsistent.
 */
void BPF_STRUCT_OPS(sched_update_idle, s32 cpu, bool idle)
{
}

/*
 * Summary:
 *   Notifies the scheduler that a CPU previously released to another scheduling class
 *   (e.g., RT or DL) is now available again for SCX scheduling. This allows the BPF
 *   scheduler to resume using @cpu for its tasks.
 *
 * Trigger / Invocation:
 *   Invoked when the SCX core reacquires @cpu after it was temporarily handed off to
 *   another scheduling class for exclusive use. The @args parameter provides context,
 *   such as the reason for reacquisition. This usually follows a prior ops.cpu_release()
 *   for the same CPU.
 *
 * Parameters:
 *   @cpu:
 *     The CPU that is being reacquired for SCX scheduling.
 *   @args:
 *     Pointer to scx_cpu_acquire_args containing information about the acquisition
 *     context (e.g., previous release reason). The scheduler can use this for
 *     diagnostics or to adjust policy.
 *
 * Effects:
 *   The scheduler should update its internal state to mark @cpu as available again
 *   for SCX tasks. If it maintains a set or mask of active CPUs, @cpu should be
 *   added back. Any queued work that was waiting for @cpu’s return can now be
 *   considered for dispatch. In this minimal scheduler, the callback is left empty,
 *   which means the core’s default behavior is relied upon and no special policy is
 *   applied when CPUs return.
 *
 * Concurrency / Ordering:
 *   Typically called in a context serialized with other CPU state changes. It should
 *   not sleep and must be quick. Ordering is such that ops.cpu_acquire() is called
 *   after the core has ensured @cpu is ready to run SCX tasks again, and before any
 *   SCX tasks are actually dispatched there.
 *
 * Invariants:
 *   After ops.cpu_acquire, @cpu should be treated by the scheduler as a valid target
 *   for SCX tasks. Any internal flags indicating that @cpu was unavailable should be
   cleared. If the scheduler tracks load or capacity, it may need to incorporate the
 *   renewed capacity of @cpu.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If not implemented, the scheduler still
 *   benefits from the core’s management of CPU availability, but it may not be aware
 *   of the exact timing of CPU return for internal bookkeeping. Edge cases include
 *   CPUs that are frequently released and reacquired; the scheduler’s state updates
 *   should handle such churn without becoming inconsistent.
 */
void BPF_STRUCT_OPS(sched_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
}

/*
 * Summary:
 *   Notifies the scheduler that a CPU is being taken away from SCX control and given
 *   to another scheduling class (for example, RT or DL). This allows the BPF scheduler
 *   to stop dispatching SCX tasks to @cpu and to migrate or account for any tasks
 *   that were running or queued there.
 *
 * Trigger / Invocation:
 *   Invoked by the SCX core when @cpu must be released to another class. The
 *   scx_cpu_release_args structure in @args indicates the reason, such as a real-time
 *   task requiring exclusive access or CPU hotplug. This callback is called while
 *   the core transitions @cpu away from SCX scheduling.
 *
 * Parameters:
 *   @cpu:
 *     The CPU being released from SCX control.
 *   @args:
 *     Pointer to scx_cpu_release_args providing context (e.g., args->reason).
 *
 * Effects:
 *   The scheduler should update its internal state to mark @cpu as unavailable for
 *   SCX tasks. Any tasks that were queued specifically for @cpu should be migrated
 *   or otherwise handled according to scheduler policy (for example, moving them to
 *   a global queue or to other CPUs if allowed). In this minimal scheduler, the
 *   callback is empty, meaning the core’s default handling is relied upon and tasks
 *   may remain logically associated with @cpu until reacquired.
 *
 * Concurrency / Ordering:
 *   Called during CPU state transitions, often in a context serialized with respect
 *   to scheduling on @cpu. It must not sleep and should execute quickly. Typically,
 *   ops.cpu_release() is called before ops.cpu_acquire() (if the CPU later returns),
 *   and may precede ops.cpu_offline() when a CPU is being hot-unplugged.
 *
 * Invariants:
 *   After this callback, the scheduler should not consider @cpu as a candidate for
 *   dispatching SCX tasks until a corresponding ops.cpu_acquire() is received (or
 *   until CPU hotplug brings it back online). Any per-CPU data structures that assume
 *   @cpu is actively scheduling tasks should be updated accordingly.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. Not implementing it means the scheduler
 *   does not explicitly track CPUs that are temporarily lost to other classes, which
 *   may cause it to overestimate available capacity or leave tasks notionally bound
 *   to a CPU that cannot currently run them. Edge cases include release due to CPU
 *   hotplug (args->reason indicates a stop); the scheduler may want to treat this as
 *   a stronger indication that all tasks must be migrated away.
 */
void BPF_STRUCT_OPS(sched_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
}

/*
 * Summary:
 *   Initializes per-task state for sched_ext. This callback sets up any scheduler-
 *   specific context needed for @p to be managed by the BPF scheduler.
 *
 * Trigger / Invocation:
 *   Called when a task first becomes associated with the SCX scheduler, typically
 *   at scheduler load for existing tasks or at fork time for new tasks. It runs in
 *   a sleepable context and may perform allocations or other blocking operations.
 *
 * Parameters:
 *   @p:
 *     The task entering sched_ext control.
 *   @args:
 *     Initialization arguments provided by the SCX core. These may include information
 *     about how @p is being brought under SCX, but are often unused by simple schedulers.
 *
 * Effects:
 *   Allocates and initializes any per-task data structures the scheduler needs to
 *   track @p. This might involve allocating a struct to store scheduling metrics or
 *   inserting @p into internal maps. In this minimal scheduler, no extra state is
 *   required, so the function returns 0 without doing anything.
 *
 * Concurrency / Ordering:
 *   Invoked before ops.enable() for @p and before @p is scheduled under SCX. The core
 *   ensures that @p is not yet running under the BPF scheduler when this function is
 *   called. It may run concurrently for different tasks on different CPUs, so any
 *   shared data structures updated here must be properly synchronized.
 *
 * Invariants:
 *   On success, any scheduler-specific state for @p should be fully initialized and
 *   ready for use by other callbacks (e.g., ops.enable, ops.enqueue, ops.running).
 *   If initialization fails, returning -errno causes the core to abort bringing @p
 *   under SCX (and possibly abort scheduler load if this happens during initial
 *   attachment).
 *
 * Failure / Edge Cases:
 *   Returns 0 on success or -errno on failure. If a failure occurs (e.g., allocation
 *   failure), the scheduler should leave no partially-initialized state for @p. The
 *   core will not call ops.enable() for @p if init_task fails. In this minimal
 *   implementation, no resources are allocated, so failure is not expected.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	return 0;
}

/*
 * Summary:
 *   Cleans up and releases any scheduler-specific resources associated with a task
 *   that is leaving SCX scheduling, typically because the task is exiting.
 *
 * Trigger / Invocation:
 *   Invoked when a task is being destroyed or otherwise permanently leaving SCX
 *   control. Commonly this is on task exit, but it may also occur when the scheduler
 *   is being unloaded or the task is switched to another scheduling class. It is
 *   called after @p has been disabled from SCX and is no longer runnable or queued.
 *
 * Parameters:
 *   @p:
 *     The task being removed from the BPF scheduler.
 *   @args:
 *     Exit context provided by the SCX core.
 *
 * Effects:
 *   Frees and cleans up any per-task data allocated in ops.init_task() or accumulated
 *   while @p was managed under SCX. This may include deleting map entries, freeing
 *   allocated structures, and removing @p from internal tracking lists. In this minimal
 *   scheduler, no extra state is kept, so the function body is empty.
 *
 * Concurrency / Ordering:
 *   Called in a context serialized with respect to task destruction. It runs after
 *   ops.disable() (if applicable) and after @p has been fully removed from runqueues.
 *   The scheduler may perform deallocations here.
 *
 * Invariants:
 *   After ops.exit_task returns, no scheduler-specific references to @p should remain.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If not implemented when ops.init_task()
 *   allocated resources, leaks may result; simple schedulers that allocate no per-task
 *   resources can safely leave it empty, as done here.
 */
void BPF_STRUCT_OPS(sched_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
}

/*
 * Summary:
 *   Finalizes enabling SCX scheduling for a task after its initial setup, marking it
 *   as fully under BPF scheduler control.
 *
 * Trigger / Invocation:
 *   Invoked after ops.init_task() has successfully completed for @p and the core is
 *   switching @p into the SCHED_EXT class. It may be called during scheduler load or
 *   when a task explicitly moves into SCX scheduling. It runs in process context and
 *   is not sleepable.
 *
 * Parameters:
 *   @p:
 *     The task being enabled for BPF scheduling.
 *
 * Effects:
 *   Provides a hook for any final per-task initialization that depends on @p being
 *   logically part of SCX (for example, initializing virtual runtime relative to
 *   existing tasks). This minimal scheduler does not require additional work here,
 *   so the function body is empty.
 *
 * Concurrency / Ordering:
 *   Called with @p not yet scheduled under SCX; no other callbacks will be operating
 *   on @p concurrently. It is typically followed by @p becoming runnable and being
 *   enqueued via select_cpu/enqueue.
 *
 * Invariants:
 *   After ops.enable, @p should be considered an active SCX task by the scheduler
 *   and accounted for in any global SCX task counts if maintained.
 *
 * Failure / Edge Cases:
 *   This function does not return a value and is expected to succeed. If not
 *   implemented, @p still becomes an SCX task, but the scheduler loses this hook
 *   for last-minute initialization.
 */
void BPF_STRUCT_OPS(sched_enable, struct task_struct *p)
{
}

/*
 * Summary:
 *   Disables SCX scheduling for a task, detaching it from the BPF scheduler so that
 *   it is no longer considered in SCX scheduling decisions.
 *
 * Trigger / Invocation:
 *   Invoked when @p leaves SCX, either because it is exiting, the scheduler is being
 *   unloaded, or @p is being switched back to another scheduling class. It is called
 *   after @p has been stopped and removed from SCX runqueues.
 *
 * Parameters:
 *   @p:
 *     The task being disabled from BPF scheduling.
 *
 * Effects:
 *   Removes @p from any scheduler-internal lists or accounting that treat it as an
 *   active SCX task, ensuring it will not be selected for execution by this scheduler.
 *   In simple schedulers, this may be a no-op, relying on the core to handle all
 *   detachment.
 *
 * Concurrency / Ordering:
 *   Called with @p not actively running under SCX. It is not sleepable and should
 *   execute quickly. For exiting tasks, ops.disable is followed by ops.exit_task for
 *   final cleanup.
 *
 * Invariants:
 *   After ops.disable, @p must not be considered in any SCX scheduling decisions.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If not implemented, the core still removes
 *   @p from SCX, but the scheduler may retain stale references if it maintains global
 *   task lists; in this minimal scheduler, no such lists are kept, so the empty
 *   implementation is safe.
 */
void BPF_STRUCT_OPS(sched_disable, struct task_struct *p)
{
}

/*
 * Summary:
 *   Initializes a cgroup for sched_ext. This callback sets up any scheduler-specific
 *   state needed to manage tasks within @cgrp under the BPF scheduler.
 *
 * Trigger / Invocation:
 *   Called on scheduler load for existing cgroups and when new cgroups are created
 *   while the scheduler is active. It runs in a sleepable context and may perform
 *   allocations or other blocking operations. A non-zero return value aborts the
 *   load or cgroup creation.
 *
 * Parameters:
 *   @cgrp:
 *     The cgroup being initialized for sched_ext.
 *   @args:
 *     Initialization context provided by the SCX core (e.g., hierarchy information),
 *     typically not needed for simple schedulers.
 *
 * Effects:
 *   Allocates and initializes any per-cgroup data structures the scheduler needs,
 *   such as weight or limit tracking. In this minimal scheduler, no extra state is
 *   required, so the function returns 0 without doing anything.
 *
 * Concurrency / Ordering:
 *   Invoked during cgroup creation or scheduler load, serialized with respect to
 *   other operations on @cgrp. It runs before tasks in @cgrp are managed by SCX.
 *
 * Invariants:
 *   On success, any scheduler-specific cgroup state should be ready for use by
 *   other callbacks (such as cgroup_set_weight).
 *
 * Failure / Edge Cases:
 *   Returns 0 on success or -errno on failure. A failure aborts cgroup initialization
 *   or scheduler load for that cgroup. This minimal implementation is not expected to
 *   fail because it allocates no resources.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
	return 0;
}

/*
 * Summary:
 *   Cleans up scheduler-specific state for a cgroup that is being destroyed or is
 *   no longer managed by sched_ext.
 *
 * Trigger / Invocation:
 *   Called when a cgroup is destroyed or when the scheduler is unloading and
 *   detaching from existing cgroups. It runs in a sleepable context.
 *
 * Parameters:
 *   @cgrp:
 *     The cgroup being cleaned up.
 *
 * Effects:
 *   Frees any per-cgroup data allocated in sched_cgroup_init and removes @cgrp from
 *   scheduler-internal tracking. This minimal scheduler allocates no such state, so
 *   the function body is empty.
 *
 * Concurrency / Ordering:
 *   Serialized with respect to other operations on @cgrp. Called after tasks in
 *   @cgrp have been detached from SCX.
 *
 * Invariants:
 *   After this call, no scheduler-specific references to @cgrp should remain.
 *
 * Failure / Edge Cases:
 *   This function does not return a value and is expected to succeed. When no
 *   per-cgroup state is allocated, the empty implementation is sufficient.
 */
void BPF_STRUCT_OPS_SLEEPABLE(sched_cgroup_exit, struct cgroup *cgrp)
{
}

/*
 * Summary:
 *   Prepares for moving a task between cgroups under sched_ext. This callback allows
 *   the scheduler to validate or allocate resources before @p is moved from @from to @to.
 *
 * Trigger / Invocation:
 *   Called before a task’s cgroup membership is changed, while @p is still associated
 *   with @from. It runs in a sleepable context and may allocate memory or perform
 *   other blocking operations. A non-zero return value aborts the move.
 *
 * Parameters:
 *   @p:
 *     The task being moved.
 *   @from:
 *     The current cgroup of @p.
 *   @to:
 *     The destination cgroup.
 *
 * Effects:
 *   The scheduler can perform checks (e.g., admission control) or allocate per-task
 *   resources required in the new cgroup. In this simple scheduler, no special work
 *   is needed, so it returns 0.
 *
 * Concurrency / Ordering:
 *   Called before sched_cgroup_move() and while @p is not on any SCX runqueue.
 *   It runs serialized with respect to other cgroup operations affecting @p.
 *
 * Invariants:
 *   If this callback returns 0, the scheduler must be prepared to complete the move
 *   in sched_cgroup_move; if it returns an error, the move will be canceled and
 *   sched_cgroup_cancel_move() may be called instead.
 *
 * Failure / Edge Cases:
 *   Returns 0 on success or -errno to abort the move. In this minimal implementation,
 *   failures are not expected.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_cgroup_prep_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
	return 0;
}

/*
 * Summary:
 *   Commits a task’s cgroup move after successful preparation, updating any scheduler
 *   state to reflect that @p now belongs to @to instead of @from.
 *
 * Trigger / Invocation:
 *   Called after sched_cgroup_prep_move() has returned success and the core has
 *   ensured @p is dequeued from its old cgroup’s runqueues. It finalizes the move
 *   in the scheduler’s view.
 *
 * Parameters:
 *   @p:
 *     The task being moved.
 *   @from:
 *     The previous cgroup of @p.
 *   @to:
 *     The new cgroup for @p.
 *
 * Effects:
 *   Updates any per-cgroup accounting or membership structures so that @p is now
 *   associated with @to. In this minimal scheduler, no per-cgroup bookkeeping is
 *   maintained, so the function body is empty.
 *
 * Concurrency / Ordering:
 *   Called while @p is dequeued and not running, serialized with respect to other
 *   changes to @p’s cgroup membership. It follows a successful prep_move and will
 *   be paired with a later sched_cgroup_cancel_move only if the move fails after
 *   preparation and before this point (in which case this function is not called).
 *
 * Invariants:
 *   After this call, the scheduler should treat @p as belonging to @to for all
 *   scheduling and accounting purposes.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If not implemented, the scheduler will
 *   not maintain per-cgroup membership state, which is acceptable for schedulers
 *   that do not implement such policies.
 */
void BPF_STRUCT_OPS(sched_cgroup_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
}

/*
 * Summary:
 *   Cancels a previously prepared cgroup move for a task when the move fails, allowing
 *   the scheduler to roll back any tentative state changes.
 *
 * Trigger / Invocation:
 *   Called if a cgroup move that was prepared by sched_cgroup_prep_move() cannot be
 *   completed successfully (for example, due to an error during commit). It runs after
 *   the failure is detected.
 *
 * Parameters:
 *   @p:
 *     The task whose cgroup move failed.
 *   @from:
 *     The original cgroup of @p.
 *   @to:
 *     The destination cgroup that was not successfully applied.
 *
 * Effects:
 *   Reverts any scheduler-specific state that was tentatively applied during
 *   sched_cgroup_prep_move(), restoring @p’s association with @from. In this minimal
 *   scheduler, there is no such state, so the function body is empty.
 *
 * Concurrency / Ordering:
 *   Called after a failed move attempt, serialized with respect to cgroup operations
 *   for @p. It is not called if prep_move succeeded and move was completed; it is only
 *   used on failure paths.
 *
 * Invariants:
 *   After this call, @p should be treated by the scheduler as if the move had never
 *   been attempted; any per-cgroup accounting should reflect @from, not @to.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. Minimal schedulers that do not allocate
 *   per-cgroup state during prep_move can safely leave it empty, as done here.
 */
void BPF_STRUCT_OPS(sched_cgroup_cancel_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
}

/*
 * Summary:
 *   Updates the weight of a cgroup under sched_ext, altering its relative share of
 *   CPU time when the scheduler enforces cgroup-level policies.
 *
 * Trigger / Invocation:
 *   Invoked when a cgroup’s weight is changed (for example, via cgroup interface),
 *   after the core has updated the cgroup’s weight in kernel state.
 *
 * Parameters:
 *   @cgrp:
 *     The cgroup whose weight is being updated.
 *   @weight:
 *     The new weight value [1..10000] for @cgrp.
 *
 * Effects:
 *   Allows the scheduler to adjust any per-cgroup accounting or scheduling parameters
 *   that depend on cgroup weight. In weighted schedulers, this might change how CPU
 *   time is distributed among cgroups. In this minimal scheduler, cgroup weight is not
   used in policy, so the function body is empty.
 *
 * Concurrency / Ordering:
 *   Called in a context serialized with respect to cgroup weight changes.
 *
 * Invariants:
 *   After this callback, any scheduler-maintained notion of cgroup weight (if used)
 *   should match @weight.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If not implemented, the scheduler will
 *   not be aware of cgroup weight changes, which is acceptable for schedulers that
 *   do not implement cgroup-level weighting.
 */
void BPF_STRUCT_OPS(sched_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
}

/*
 * Summary:
 *   Called when a CPU has been brought online to allow the BPF scheduler to
 *   initialize or incorporate that CPU into its scheduling structures.
 *
 * Trigger / Invocation:
 *   Invoked after a CPU is fully online and ready to schedule tasks, during the
 *   CPU hotplug onlining process. It runs in a sleepable context and is called
 *   before SCX starts scheduling tasks on @cpu.
 *
 * Parameters:
 *   @cpu:
 *     The CPU number that just came online.
 *
 * Effects:
 *   The scheduler should set up any per-CPU state or data structures needed for @cpu.
 *   For example, if it maintains per-CPU runqueues, statistics, or timers, they should
 *   be allocated and initialized here. This minimal scheduler does not require such
 *   state for @cpu, so the function body is empty.
 *
 * Concurrency / Ordering:
 *   Runs in the CPU hotplug path, which is serialized for each CPU coming online.
 *   The core will not schedule SCX tasks on @cpu until this function returns, so
 *   initialization can assume @cpu is quiescent with respect to SCX.
 *
 * Invariants:
 *   After ops.cpu_online, @cpu should be fully integrated into any scheduler-internal
 *   structures that depend on the set of online CPUs.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If initialization fails internally, the
 *   scheduler could call scx_bpf_error() to abort, but in this minimal implementation
 *   no failure is expected.
 */
void BPF_STRUCT_OPS_SLEEPABLE(sched_cpu_online, s32 cpu)
{
}

/*
 * Summary:
 *   Called when a CPU is about to go offline to allow the BPF scheduler to clean up
 *   or adjust its state. After this call, @cpu will no longer schedule SCX tasks until
 *   it comes online again.
 *
 * Trigger / Invocation:
 *   Invoked during the CPU hotplug offlining process, after the kernel has stopped
 *   scheduling regular tasks on @cpu and just before @cpu is removed from the scheduler’s
 *   domain. The SCX core ensures that no SCX tasks remain running on @cpu before calling
 *   ops.cpu_offline(). This callback is sleepable.
 *
 * Parameters:
 *   @cpu:
 *     The CPU number that is going offline.
 *
 * Effects:
 *   The scheduler should tear down or mark invalid any CPU-specific structures or data
 *   associated with @cpu, such as per-CPU runqueues or statistics. In this minimal
 *   scheduler, no such structures are maintained, so the function body is empty.
 *
 * Concurrency / Ordering:
 *   Runs in the CPU hotplug thread context for @cpu and can sleep. It is executed after
 *   all tasks have been migrated or stopped on @cpu and before @cpu is fully removed
 *   from the system’s view.
 *
 * Invariants:
 *   After ops.cpu_offline, @cpu should no longer be considered an active SCX CPU by
 *   the scheduler; any idle or active CPU sets maintained by the scheduler should no
 *   longer include @cpu.
 *
 * Failure / Edge Cases:
 *   This function does not return a value. If not implemented, CPUs can still go
 *   offline safely, but any scheduler-maintained per-CPU resources would need to be
 *   statically allocated or reclaimable without explicit cleanup.
 */
void BPF_STRUCT_OPS_SLEEPABLE(sched_cpu_offline, s32 cpu)
{
}

/*
 * Summary:
 *   Performs global initialization for the BPF scheduler when it is registered.
 *   Sets up any global data structures, state, or resources needed before tasks
 *   begin to be scheduled by this scheduler.
 *
 * Trigger / Invocation:
 *   Called once when the BPF scheduler is loaded (attached via SCX_OPS_DEFINE).
 *   This occurs during the scheduler registration process, before any tasks are enabled
 *   or any other scheduler callbacks (except possibly ops.init_task for existing tasks)
 *   are invoked. The kernel calls ops.init in process context as part of activating the
 *   new scheduler. This function is marked sleepable (BPF_STRUCT_OPS_SLEEPABLE) if it
 *   may perform memory allocations or other blocking operations. It runs to completion
 *   before the scheduler begins managing tasks.
 *
 * Parameters:
 *   (none)
 *
 * Effects:
 *   Sets up global scheduler structures and state. For example, this may create custom
 *   dispatch queues or data structures that the scheduler will use. In this scheduler,
 *   if a custom dispatch queue is needed (beyond the default SCX_DSQ_LOCAL/SCX_DSQ_GLOBAL),
 *   it would be created here using `scx_bpf_create_dsq()`. scx_simple does this to
 *   create a shared DSQ with a specific ID. Other possible actions:
 *   initialize global counters, allocate BPF maps or per-CPU structures, set up timers or
 *   kptrs. Essentially, ops.init prepares everything at the global level so that subsequent
 *   operations (enqueue, dispatch, etc.) can use those resources. If this function returns
 *   a non-zero error code, the scheduler attachment is aborted. On success (return 0),
 *   the scheduler proceeds to enable tasks and enter operation. Because it can sleep, ops.init
 *   is the appropriate place for any potentially blocking setup (e.g., allocating memory for a
 *   large data structure).
 *
 * Concurrency / Ordering:
 *   This function is called in a single-threaded context during scheduler registration.
 *   The core will not call any other scheduler callbacks (nor schedule any task under SCX)
 *   until ops.init completes successfully. Thus, no concurrency issues with other ops in this
 *   phase. It is executed before ops.enable is called on any task. If ops.init depends on hardware
 *   state (like number of CPUs or topology), that information is available and stable at this point.
 *   If some parts of initialization logically belong to tasks (per-task state), those are handled in
 *   ops.init_task for each task; ops.init is purely global.
 *
 * Invariants:
 *   After ops.init returns 0, all global structures required by the scheduler must be in a valid state.
 *   For instance, if the scheduler uses a global runqueue, it should be initialized empty. If it uses
 *   custom DSQs, they should be created and ready (scx_bpf_create_dsq returns an ID or error).
 *   If the scheduler maintains global pointers (like scx_nest’s global cpumask pointers for primary/reserve
 *   sets), those should be allocated and set. Any failure should result in a
 *   non-zero return and no partial state should persist (the core will unload the program on failure, and
 *   presumably free any BPF-allocated resources like maps or DSQs). The function must not modify any
 *   scheduler core state; it only prepares BPF-side structures. Also, it must not schedule tasks or perform
 *   any operation on tasks – tasks are still under the previous scheduler until this completes. Typically,
 *   invariants might include: “All needed dispatch queues exist,” “global time baseline set to 0,” or similar.
 *
 * Failure / Edge Cases:
 *   This function returns an int status: 0 for success, or -errno on failure. If it returns
 *   failure, the kernel will refuse to enable the BPF scheduler, and the system will continue with the old
 *   scheduler (or abort the load). Edge cases:
 *   - Memory allocation failure: e.g., if scx_bpf_create_dsq or a bpf_obj_new call fails due to memory, ops.init
 *     should return -ENOMEM or appropriate. The core will handle cleanup (e.g., destroying any DSQs that were
 *     successfully created before the failure).
 *   - Duplicate resource: if the scheduler tried to create a DSQ with an ID that’s already in use (should not
 *     happen if new IDs are chosen uniquely), it would fail.
 *   - If a critical setup step is missed and 0 is returned, the scheduler might malfunction later; thus, all
 *     relevant steps must be done before returning success.
 *   - If the system is under memory pressure or other unusual conditions, ops.init should be prepared for
 *     occasional helper failures and propagate them as error codes. However, it must not partially initialize
 *     state and still return success.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

/*
 * Summary:
 *   Final teardown for the BPF scheduler. Records exit information and performs any
 *   last cleanup after all tasks have been detached from sched_ext.
 *
 * Trigger / Invocation:
 *   Called once when the BPF scheduler is being unregistered (e.g., the userspace
 *   scheduler process exits or a fatal error/timeout triggers a fallback). It is invoked
 *   at the end of the scheduler’s lifecycle, after all tasks have been moved off of SCX
 *   scheduling (or in the process of moving). In normal cases, this is called when the
 *   user explicitly terminates the BPF scheduler (e.g., via ctrl+C of the userspace program,
 *   causing an EXIT), or when a SysRq-S (switch back) or watchdog triggers a scheduler
 *   abort. It may also run during a partial load failure (if something went wrong after
 *   ops.init succeeded), though typically in such case ops.exit might still be called to
 *   allow cleanup.
 *
 * Parameters:
 *   @ei:
 *     A pointer to `struct scx_exit_info` containing information about why the scheduler
 *     is exiting and any relevant data. `ei->type` (or `ei->kind`) indicates the cause:
 *     for example, 0 might mean a normal exit (voluntary unload), a specific code might
 *     mean watchdog timeout, etc. There may also be a pointer to a debug dump or
 *     stats if the scheduler recorded one (the structure can include a buffer and length,
 *     indicated by ops.exit_dump_len, though in this implementation we likely just use the type).
 *
 * Effects:
 *   Allows the scheduler to perform any final logging or cleanup. Commonly, a scheduler will
 *   record the exit reason for debugging or user-space consumption. For instance, scx_simple’s
 *   ops.exit records `ei->type` in a global which the userspace component reads and prints.
 *   If the scheduler allocated global resources (like extra DSQs or timers), this is a place to
 *   release them if needed. However, most resources are tied to BPF maps or kernel objects that will
 *   be freed automatically when the BPF program is unloaded. For example, any DSQs created in ops.init
 *   are automatically destroyed by the core when the scheduler is detached (there isn’t an explicit
 *   scx_bpf_destroy_dsq call in scx_simple’s exit). So explicit freeing is often unnecessary. This
 *   callback runs in atomic context (not marked sleepable), so it should not block. It typically just
 *   writes to some data structures or performs lightweight cleanup. Once this returns, the BPF scheduler
 *   is effectively gone.
 *
 * Concurrency / Ordering:
 *   Called after all tasks have been disabled from SCX (each task gets ops.disable before this, if
 *   those callbacks exist) and after the core has quiesced the scheduler. No other ops callbacks will
 *   be active concurrently with ops.exit; it’s the final call. The CPU(s) executing this are in a safe
 *   context to unload the scheduler (often all other CPUs are idling or running default scheduler by then).
 *   If multiple CPUs were involved in running the scheduler, ops.exit is single-threaded with respect to
 *   the BPF program. It is executed at a point when no new enqueues or dispatches will occur. Ordering relative
 *   to ops.disable: first, tasks get ops.disable (if implemented) to notify their removal, then ops.exit is called
 *   for global teardown. Also, if a scheduler error triggered this unload, ops.dump or ops.dump_cpu/task might
 *   have been called right before ops.exit to collect debug info; ops.exit is after that.
 *
 * Invariants:
 *   By the time ops.exit is called, the scheduler should not have any tasks left in its internal queues.
 *   All tasks have either moved to another scheduler (back to CFS) or are exiting. The scheduler should not
 *   attempt to schedule any new work. Invariants to maintain include consistency of any logged data (for example,
 *   if writing out stats, ensure the buffer is properly terminated or counts are final). If ops.exit modifies any
 *   global variables (like resetting them), it should be mindful that the scheduler is about to be unloaded entirely.
 *   Essentially, invariants are about leaving no dangling pointers or references. If the scheduler had persistent
 *   resources (e.g., allocated via bpf_obj_new and stored as kptrs), it should release them here if they won’t be
 *   auto-released. However, since the whole BPF object is unloading, most resources will free with it. The core’s
 *   internal state for sched_ext will be torn down after this, so no core invariants need maintaining beyond this point.
 *
 * Failure / Edge Cases:
 *   ops.exit does not return a value. It’s expected to always succeed. If it encounters an issue (e.g., if it tried
 *   to write to a userspace buffer that’s unmapped – which shouldn’t happen because any communication would be via
 *   BPF maps or rings that are still accessible), there’s not much it can do except perhaps call scx_bpf_error to
 *   log (though at exit, maybe too late). Edge cases:
 *   - If the scheduler was aborted due to a fatal error, ei->type will reflect that. The scheduler might output extra
 *     info in that case. For example, if `ei->type` indicates a stall, the scheduler could log that it ended due to
 *     a watchdog stall. Typically, `ei->type` is just an integer code; mapping it to a message can be done in userspace.
 *   - If the scheduler is being forcibly removed (SysRq-S or error), tasks might still be technically runnable under
 *     SCX at the instant of calling ops.exit, but the core ensures they’re not actively running. The scheduler should
 *     not attempt to touch those tasks, aside from possibly recording that such an event happened.
 *   - If ops.init never ran (e.g., if load fails early), ops.exit might still be called in some code paths, but in that
 *     case, there’s nothing to do. In practice, ops.exit is only called after a successful init.
 *   - This scheduler likely doesn’t allocate special global resources that need manual freeing here, so there are few
 *     edge cases. If it did (say allocated memory not tied to BPF maps), forgetting to free it here would leak memory
 *     until the module is unloaded (which for BPF happens immediately after exit anyway).
 *
 * Notes:
 *   Many sched_ext example schedulers use ops.exit for debugging. For instance, scx_simple uses a macro UEI_RECORD to
 *   log the exit reason (so that the userspace component can print whether it exited normally or due to an error).
 *   In more complex scenarios, ops.exit could flush any pending telemetry or stats. Because once the scheduler is gone,
 *   any BPF maps or data remain accessible only if the userspace explicitly reads them before the program is freed.
 *   It’s worth noting that by the time ops.exit is called, the system is already switched back to the default scheduler
 *   (or to another sched_ext if being replaced). That means any tasks formerly on BPF queues have been migrated out (likely
 *   in ops.disable or in the kernel’s detach logic). If the scheduler maintained references to tasks (e.g., in a BPF map of
 *   queued tasks), those references are no longer valid once exit is done. So ideally, such maps should be cleared. However,
 *   typical implementations rely on the fact that when the BPF program is destroyed, all maps are destroyed too, releasing
 *   references. If needed, ops.exit could iterate and clean up, but it’s usually not necessary. In summary, ops.exit is mainly
 *   for logging and any final consistency checks. After this, the scheduler’s lifecycle is complete.
 */
void BPF_STRUCT_OPS(sched_exit, struct scx_exit_info *ei)
{
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
