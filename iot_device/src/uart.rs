const UART0_BASE: usize = 0x0900_0000;

pub fn putc(c: u8) {
    unsafe {
        core::ptr::write_volatile(UART0_BASE as *mut u8, c);
    }
}

pub fn puts(s: &str) {
    for b in s.bytes() {
        putc(b);
    }
}