use core::arch::asm;

#[unsafe(no_mangle)]
pub extern "C" fn sync_exception_handler() -> ! {
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