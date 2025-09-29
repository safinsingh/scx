use std::thread;

fn main() {
    let logical_cores = core_affinity::get_core_ids().unwrap();

    let handles = logical_cores
        .into_iter()
        .map(|c| {
            thread::spawn(move || {
                core_affinity::set_for_current(c);
                loop {}
            })
        })
        .collect::<Vec<_>>();
    handles.into_iter().map(|th| th.join()).for_each(drop);
}
