use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use virtio_drivers::{BufferDirection, Hal, PhysAddr, PAGE_SIZE};

unsafe extern "C" {
    static __dma_start: u8;
}

const DMA_POOL_SIZE: usize = 0x400000;

static DMA_OFFSET: AtomicUsize = AtomicUsize::new(0);

pub struct MyHal;

unsafe impl Hal for MyHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let size = pages * PAGE_SIZE;
        let offset = DMA_OFFSET.fetch_add(size, Ordering::SeqCst);

        assert!(offset + size <= DMA_POOL_SIZE, "DMA pool exhausted");

        let ptr = unsafe {
            core::ptr::addr_of!(__dma_start)
                .cast_mut()
                .add(offset)
        };

        assert_eq!(ptr as usize % PAGE_SIZE, 0);

        let paddr = ptr as usize as PhysAddr;
        
        (paddr, NonNull::new(ptr).unwrap())
    }

    unsafe fn dma_dealloc(
        _paddr: PhysAddr,
        _vaddr: NonNull<u8>,
        _pages: usize,
    ) -> i32 {
        0
    }

    unsafe fn mmio_phys_to_virt(
        paddr: PhysAddr,
        _size: usize,
    ) -> NonNull<u8> {
        NonNull::new(paddr as *mut u8).unwrap()
    }

    unsafe fn share(
        buffer: NonNull<[u8]>,
        _direction: BufferDirection,
    ) -> PhysAddr {
        let raw = buffer.as_ptr();
        let vaddr = raw as *mut u8 as usize;
        vaddr as PhysAddr
    }

    unsafe fn unshare(
        _paddr: PhysAddr,
        _buffer: NonNull<[u8]>,
        _direction: BufferDirection,
    ) {}
}