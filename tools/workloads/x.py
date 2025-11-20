#!/usr/bin/env python3
# Headless Gantt-like CPU timeline with distinct colors per task.
# Input lines: "<task> <nsecs> <cpu>" where <task> SWITCHED OFF the CPU at <nsecs>.

import os, sys, time, signal, threading, subprocess as sp
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --- config ---
TRACE_PATH = "bpftrace_trace.txt"
OUT_PNG = "gantt_approx.png"

LAUNCH_WORKLOADS = True
BPFTRACER = "./bpftracer"
SYNTH_BIN = "../../target/debug/synth"
HOG_BIN   = "../../target/debug/hog"
TRACE_INTERVAL = [0, 10]
SYNTH_INTERVAL = [2, 6]
HOG_INTERVAL   = [4, 8]

# Downsampling
TIME_WINDOW_MS   = 0.25  # fixed time window per-CPU; majority by duration
CTXT_PER_SEGMENT = 0     # use if TIME_WINDOW_MS <= 0
MIN_SEG_NS       = 0

MAX_CPUS   = 64
TIME_UNIT  = "ms"
Y_HEIGHT   = 0.8

# --- helpers ---

def _sleep_until(t):
    now = time.monotonic();
    if t > now: time.sleep(t - now)

def _killpg(p):
    try: os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError: pass

def _run_scheduled(cmd, start_after, end_after, stdout=None):
    start = T0 + start_after; stop = T0 + end_after
    _sleep_until(start)
    p = sp.Popen(cmd, stdout=stdout if stdout else sp.DEVNULL,
                 stderr=sp.STDOUT if stdout else sp.DEVNULL,
                 text=True, preexec_fn=os.setsid)
    _sleep_until(stop)
    _killpg(p)

def maybe_launch():
    if not LAUNCH_WORKLOADS: return
    tf = open(TRACE_PATH, "w", buffering=1)
    ts = []
    def spawn(cmd, ivl, cap=False):
        def target(): _run_scheduled(cmd, ivl[0], ivl[1], stdout=(tf if cap else None))
        t = threading.Thread(target=target, daemon=True); t.start(); ts.append(t)
    spawn([BPFTRACER], TRACE_INTERVAL, cap=True)
    spawn([SYNTH_BIN], SYNTH_INTERVAL)
    spawn([HOG_BIN],   HOG_INTERVAL)
    for t in ts: t.join()
    tf.close()

# --- parsing & intervals ---

def parse_trace(path):
    ev = []
    with open(path, 'r') as f:
        for ln in f:
            p = ln.strip().split()
            if len(p) < 3: continue
            task = p[0]
            try:
                t = int(p[1]); cpu = int(p[2])
            except ValueError:
                continue
            ev.append((task, t, cpu))
    if not ev: return [], 0, 0
    ev.sort(key=lambda x: x[1])
    return ev, ev[0][1], ev[-1][1]

def to_unit(ns):
    if TIME_UNIT == 'ns': return ns
    if TIME_UNIT == 'us': return ns/1e3
    if TIME_UNIT == 'ms': return ns/1e6
    raise ValueError('bad unit')

# Build atomic per-CPU intervals per sched_switch semantics
# Each line identifies the task that ran from last_t[cpu] to this t.

def atomic_intervals(events):
    per_cpu = defaultdict(list)
    last_t = {}
    for task, t, cpu in events:
        if cpu in last_t and t > last_t[cpu]:
            per_cpu[cpu].append((task, last_t[cpu], t))
        last_t[cpu] = t
    return per_cpu

# Downsampling

def group_by_time(ints, win_ns, min_ns=0):
    if not ints: return []
    start = ints[0][1]; end = ints[-1][2]
    if end <= start: return []
    out = []
    i = 0
    w0 = start
    while w0 < end:
        w1 = min(end, w0 + win_ns)
        dur = defaultdict(int)
        j = i
        while j < len(ints):
            task, s, e = ints[j]
            if e <= w0: j += 1; continue
            if s >= w1: break
            seg_s = max(s, w0); seg_e = min(e, w1)
            if seg_e > seg_s: dur[task] += seg_e - seg_s
            if e <= w1: j += 1
            else: break
        if dur:
            maj = max(dur.items(), key=lambda kv: kv[1])[0]
            if (w1 - w0) >= min_ns: out.append((maj, w0, w1))
        w0 = w1
        while i < len(ints) and ints[i][2] <= w0: i += 1
    # coalesce
    if not out: return out
    merged = [out[0]]
    for tsk, s, e in out[1:]:
        lt, ls, le = merged[-1]
        if tsk == lt and s <= le: merged[-1] = (lt, ls, max(le, e))
        else: merged.append((tsk, s, e))
    return merged

# --- plotting ---

def plot_gantt(groups, origin_ns, out_png):
    cpus = sorted([c for c,v in groups.items() if v])[:MAX_CPUS]
    if not cpus:
        print("No CPUs to plot."); return

    # Deterministic distinct colors per TASK using axes.prop_cycle
    all_tasks = []
    for c in cpus:
        for t, _, _ in groups[c]:
            if t not in all_tasks: all_tasks.append(t)
    color_cycle = plt.rcParams['axes.prop_cycle'].by_key().get('color', ['C0','C1','C2','C3','C4','C5','C6','C7','C8','C9'])
    cmap = {task: color_cycle[i % len(color_cycle)] for i, task in enumerate(all_tasks)}

    fig, ax = plt.subplots(figsize=(12, max(3, 0.45*len(cpus))))
    yidx = {c:i for i,c in enumerate(cpus)}
    used = set()
    for c in cpus:
        yi = yidx[c]
        for task, s, e in groups[c]:
            start = to_unit(s - origin_ns); dur = to_unit(e - s)
            if dur <= 0: continue
            face = cmap[task]
            lbl = task if task not in used else None
            ax.broken_barh([(start, dur)], (yi - Y_HEIGHT/2.0, Y_HEIGHT), facecolors=face, edgecolors='none', label=lbl)
            if lbl: used.add(task)

    ax.set_ylim(-0.5, len(cpus)-0.5)
    ax.set_yticks(list(range(len(cpus))))
    ax.set_yticklabels([str(c) for c in cpus])
    ax.set_xlabel(f"time ({TIME_UNIT})"); ax.set_ylabel("CPU")
    ax.set_title("Per-CPU Timeline (Gantt approx)")
    h, l = ax.get_legend_handles_labels()
    if h:
        d = dict(zip(l, h)); ax.legend(d.values(), d.keys(), loc='best')
    for s in ("top","right"): ax.spines[s].set_visible(False)
    fig.tight_layout(); fig.savefig(out_png, dpi=150); plt.close(fig)

# --- main ---

def main():
    global T0; T0 = time.monotonic()
    if LAUNCH_WORKLOADS: maybe_launch()
    if not os.path.exists(TRACE_PATH):
        print(f"Trace not found: {TRACE_PATH}", file=sys.stderr); sys.exit(1)

    events, tmin, tmax = parse_trace(TRACE_PATH)
    if not events:
        print("No events parsed.", file=sys.stderr); sys.exit(1)

    per_cpu = atomic_intervals(events)
    grouped = {}
    if TIME_WINDOW_MS and TIME_WINDOW_MS > 0:
        win_ns = int(TIME_WINDOW_MS * 1e6)
        for cpu, ints in per_cpu.items():
            grouped[cpu] = group_by_time(ints, win_ns, MIN_SEG_NS)
    elif CTXT_PER_SEGMENT and CTXT_PER_SEGMENT > 0:
        # fallback to no downsampling if not implemented here
        grouped = per_cpu
    else:
        grouped = per_cpu

    grouped = {c:v for c,v in grouped.items() if v}
    if not grouped:
        print("No intervals to plot after grouping.", file=sys.stderr); sys.exit(1)

    plot_gantt(grouped, origin_ns=tmin, out_png=OUT_PNG)
    print(f"Wrote {OUT_PNG}")

if __name__ == '__main__':
    main()
