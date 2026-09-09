const UART0_BASE: usize = 0x0900_0000;

#[unsafe(no_mangle)]
pub extern "Rust" fn uart_puts(s: &str) {
    puts(s);
}

#[unsafe(no_mangle)]
pub extern "Rust" fn uart_put_hex(value: usize) {
    put_hex(&value.to_le_bytes());
}

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

pub fn put_hex(bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        putc(HEX[(b >> 4) as usize]);
        putc(HEX[(b & 0x0F) as usize]);
    }
    puts("\r\n");
}