// mmu.rs
use core::arch::asm;

#[repr(align(4096))]
struct PageTable([u64; 512]);

static mut L1_TABLE: PageTable = PageTable([0; 512]);

const ATTR_DEVICE_NGNRNE: u64 = 0x00;
const ATTR_NORMAL_WB: u64 = 0xFF;

const DESC_VALID: u64 = 1 << 0;
const DESC_BLOCK: u64 = 0 << 1; // bit[1]=0 => block descriptor a L1
const DESC_AF: u64 = 1 << 10;    // access flag, obbligatorio o si prende un fault
const DESC_INNER_SHAREABLE: u64 = 3 << 8;

pub unsafe fn init() {
    let l1 = core::ptr::addr_of_mut!(L1_TABLE.0);

    // entry 0: 0x0000_0000 .. 0x3FFF_FFFF -> Device (index 0 in MAIR)
    (*l1)[0] = (0x00000000u64)
        | DESC_VALID | DESC_BLOCK | DESC_AF
        | (0 << 2); // AttrIndx = 0

    // entry 1: 0x4000_0000 .. 0x7FFF_FFFF -> Normal WB (index 1 in MAIR)
    (*l1)[1] = (0x40000000u64)
        | DESC_VALID | DESC_BLOCK | DESC_AF | DESC_INNER_SHAREABLE
        | (1 << 2); // AttrIndx = 1

    let mair: u64 = ATTR_DEVICE_NGNRNE | (ATTR_NORMAL_WB << 8);
    asm!("msr mair_el1, {}", in(reg) mair);

    // TCR_EL1: T0SZ=25 (39-bit VA), 4KB granule, IPS impostato in base a RAM
    let tcr: u64 = (25 << 0)      // T0SZ
        | (0b00 << 14)            // TG0 = 4KB
        | (0b11 << 12)            // SH0 = inner shareable
        | (0b01 << 10)            // ORGN0 = WB
        | (0b01 << 8)             // IRGN0 = WB
        | (0b000 << 32);          // IPS = 32-bit PA (sufficiente, RAM finisce a 0x48000000)
    asm!("msr tcr_el1, {}", in(reg) tcr);

    let ttbr0 = l1 as u64;
    asm!("msr ttbr0_el1, {}", in(reg) ttbr0);

    asm!("isb");

    let mut sctlr: u64;
    asm!("mrs {}, sctlr_el1", out(reg) sctlr);
    sctlr |= 1 << 0;  // M, abilita MMU
    sctlr |= 1 << 2;  // C, cache dati
    sctlr |= 1 << 12; // I, cache istruzioni
    asm!("dsb sy");
    asm!("msr sctlr_el1, {}", in(reg) sctlr);
    asm!("isb");
}