// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#[allow(bare_trait_objects)]

mod bridge;
use bridge::*;

use std::time::{Duration, Instant};

/// Waits for IBD to complete, to get stuck, or shutdown to be initiated. This should be called
/// prior to any background block fetchers initiating connections.
pub fn await_ibd_complete_or_stalled() {
    // Wait until we have finished IBD or aren't making any progress before kicking off
    // redundant sync.
    let mut last_tip = BlockIndex::tip();
    let mut last_tip_change = Instant::now();
    while unsafe { !rusty_ShutdownRequested() } {
        std::thread::sleep(Duration::from_millis(500));
        if unsafe { !rusty_IsInitialBlockDownload() } { break; }
        let new_tip = BlockIndex::tip();
        if new_tip != last_tip {
            last_tip = new_tip;
            last_tip_change = Instant::now();
        } else if (Instant::now() - last_tip_change) > Duration::from_secs(600) {
            break;
        }
    }
}
