use virtio_drivers::device::net::VirtIONet;
use virtio_drivers::transport::Transport;
use virtio_drivers::Hal;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};

const VIRTIO_NET_MMIO_ADDR: usize = 0x0A00_0000;
const VIRTIO_MMIO_STRIDE: usize = 0x200;

pub fn init_net_transport() -> MmioTransport<'static> {
    let header = unsafe { &mut *(VIRTIO_NET_MMIO_ADDR as *mut VirtIOHeader) };
    unsafe { MmioTransport::new(header.into(), VIRTIO_MMIO_STRIDE) }
        .expect("virtio-net mmio init failed")
}

pub struct VirtioNetDevice<H: Hal, T: Transport> {
    inner: VirtIONet<H, T, 16>,
}

impl<H: Hal, T: Transport> VirtioNetDevice<H, T> {
    pub fn new(inner: VirtIONet<H, T, 16>) -> Self {
        Self { inner }
    }
}

impl<H: Hal, T: Transport> Device for VirtioNetDevice<H, T> {
    type RxToken<'a> = VirtioRxToken<'a, H, T> where Self: 'a;
    type TxToken<'a> = VirtioTxToken<'a, H, T> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.inner.can_recv() {
            let ptr: *mut VirtIONet<H, T, 16> = &mut self.inner;
            // SAFETY: RxToken and TxToken are consumed sequentially, never
            // concurrently, so it is safe to create two mutable references to
            // the same VirtIONet instance. 
            Some((
                VirtioRxToken(unsafe { &mut *ptr }), 
                VirtioTxToken(unsafe { &mut *ptr }),
                ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.inner.can_send() {
            Some(VirtioTxToken(&mut self.inner))
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ethernet;
        caps
    }
}

pub struct VirtioRxToken<'a, H: Hal, T: Transport>(&'a mut VirtIONet<H, T, 16>);
pub struct VirtioTxToken<'a, H: Hal, T: Transport>(&'a mut VirtIONet<H, T, 16>);

impl<'a, H: Hal, T: Transport> RxToken for VirtioRxToken<'a, H, T> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = self.0.receive().expect("recv failed");
        let result = f(buf.packet_mut());
        self.0.recycle_rx_buffer(buf).expect("recycle failed");
        result
    }
}

impl<'a, H: Hal, T: Transport> TxToken for VirtioTxToken<'a, H, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut tx_buf = self.0.new_tx_buffer(len);
        let result = f(tx_buf.packet_mut());
        self.0.send(tx_buf).expect("send failed");
        result
    }
}

