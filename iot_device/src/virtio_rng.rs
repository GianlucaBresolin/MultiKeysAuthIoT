use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::{DeviceType, Transport};
use virtio_drivers::device::rng::VirtIORng;
use virtio_drivers::Hal;
use rand_core::{TryRng};
use core::convert::Infallible;

const VIRTIO_MMIO_BASE: usize = 0x0A00_0000;
const VIRTIO_MMIO_STRIDE: usize = 0x200;
const VIRTIO_MMIO_SLOTS: usize = 32;

pub fn find_rng_transport() -> MmioTransport<'static> {
    for i in 0..VIRTIO_MMIO_SLOTS {
        let addr = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        let header = unsafe { &mut *(addr as *mut VirtIOHeader) };
        if let Ok(transport) = unsafe { MmioTransport::new(header.into(), VIRTIO_MMIO_STRIDE) } {
            if transport.device_type() == DeviceType::EntropySource {
                return transport;
            }
        }
    }
    panic!("virtio-rng device not found");
}

pub struct VirtioRngDevice<H: Hal, T: Transport> {
    inner: VirtIORng<H, T>,
}

impl<H: Hal, T: Transport> VirtioRngDevice<H, T> {
    pub fn new(inner: VirtIORng<H, T>) -> Self {
        Self { inner }
    }
}

impl<H: Hal, T: Transport> TryRng for VirtioRngDevice<H, T> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.inner
            .request_entropy(&mut buf)
            .expect("virtio-rng entropy request failed");
        Ok(u32::from_ne_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.inner
            .request_entropy(&mut buf)
            .expect("virtio-rng entropy request failed");
        Ok(u64::from_ne_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.inner
            .request_entropy(dest)
            .expect("virtio-rng entropy request failed");
        Ok(())
    }
}