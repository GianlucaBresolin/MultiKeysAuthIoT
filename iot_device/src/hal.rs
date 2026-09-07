use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use virtio_drivers::{BufferDirection, Hal, PhysAddr, PAGE_SIZE};

const DMA_POOL_SIZE: usize = 64 * PAGE_SIZE; // 256 KiB

#[repr(align(4096))]
struct DmaPool([u8; DMA_POOL_SIZE]);

static mut DMA_POOL: DmaPool = DmaPool([0u8; DMA_POOL_SIZE]);
static DMA_OFFSET: AtomicUsize = AtomicUsize::new(0);

pub struct MyHal;

unsafe impl Hal for MyHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let size = pages * PAGE_SIZE;
        let offset = DMA_OFFSET.fetch_add(size, Ordering::SeqCst);
        assert!(offset + size <= DMA_POOL_SIZE, "DMA pool exhausted");

        let ptr = unsafe { DMA_POOL.0.as_mut_ptr().add(offset) };
        let paddr = ptr as usize as PhysAddr;
        let vaddr = NonNull::new(ptr).unwrap();
        (paddr, vaddr)
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        0 // bump allocator: no real dealloc
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        NonNull::new(paddr as *mut u8).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        buffer.as_ptr() as *mut u8 as usize as PhysAddr
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}