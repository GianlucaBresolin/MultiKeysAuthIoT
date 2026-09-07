pub fn now_millis() -> i64 {
    let cntpct: u64;
    let cntfrq: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) cntpct);
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) cntfrq);
    }
    ((cntpct as u128 * 1000) / cntfrq as u128) as i64
}