use core::arch::asm;

#[repr(align(2048))]
struct VectorTable([u8; 2048]);

#[unsafe(no_mangle)]
pub extern "C" fn sync_exception_handler() -> ! {
    let esr: u64;
    let elr: u64;
    let far: u64;
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr);
        asm!("mrs {}, elr_el1", out(reg) elr);
        asm!("mrs {}, far_el1", out(reg) far);
    }
    crate::uart::puts("SYNC EXCEPTION\r\nESR_EL1: ");
    crate::uart::put_hex(&esr.to_le_bytes());
    crate::uart::puts("\r\nELR_EL1: ");
    crate::uart::put_hex(&elr.to_le_bytes());
    crate::uart::puts("\r\nFAR_EL1: ");
    crate::uart::put_hex(&far.to_le_bytes());
    crate::uart::puts("\r\n");
    loop {
        unsafe { asm!("wfe") };
    }
}

pub unsafe fn init() {
    unsafe extern "C" {
        static vector_table: u8;
    }
    let addr = core::ptr::addr_of!(vector_table) as u64;
    unsafe { asm!("msr vbar_el1, {}", in(reg) addr) };
}