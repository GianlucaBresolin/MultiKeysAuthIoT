use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use crate::coap_utils;
use smoltcp::socket::udp;
use smoltcp::iface::SocketHandle;
use smoltcp::iface::SocketSet;
use smoltcp::wire::IpEndpoint;
use smoltcp::iface::Interface;
use smoltcp::phy::Device;
use smoltcp::time::Instant;

pub enum CommResponse {
    Ack,
    AuthSessionTimeout,
    Unknown(Vec<u8>),
}

pub struct CommunicationManager<'a> {
    sockets: SocketSet<'a>,
    udp_handle: SocketHandle,
    message_id: u16,
    coap_buf: [u8; 256],
    server_endpoint: IpEndpoint,
}

impl<'a> CommunicationManager<'a> {
    /// Create a CommunicationManager by taking ownership of a SocketSet. The function will create and register
    /// a UDP socket bound to local_port inside the provided SocketSet, and then return a CommunicationManager
    /// that owns the SocketSet.
    pub fn new(mut sockets: SocketSet<'a>, local_port: u16, server_endpoint: IpEndpoint) -> Self {
        // create UDP socket buffers and leak them to 'static so they live long enough for the socket
        let rx_meta_vec = vec![udp::PacketMetadata::EMPTY; 4];
        let rx_buf_vec = vec![0u8; 2048];
        let tx_meta_vec = vec![udp::PacketMetadata::EMPTY; 4];
        let tx_buf_vec = vec![0u8; 2048];

        // convert to boxed slices and leak to obtain &'static mut slices
        let rx_meta_box = rx_meta_vec.into_boxed_slice();
        let rx_meta_leak: &'static mut [udp::PacketMetadata] = Box::leak(rx_meta_box);
        let rx_buf_box = rx_buf_vec.into_boxed_slice();
        let rx_buf_leak: &'static mut [u8] = Box::leak(rx_buf_box);
        let tx_meta_box = tx_meta_vec.into_boxed_slice();
        let tx_meta_leak: &'static mut [udp::PacketMetadata] = Box::leak(tx_meta_box);
        let tx_buf_box = tx_buf_vec.into_boxed_slice();
        let tx_buf_leak: &'static mut [u8] = Box::leak(tx_buf_box);

        let rx_buffer = udp::PacketBuffer::new(rx_meta_leak, rx_buf_leak);
        let tx_buffer = udp::PacketBuffer::new(tx_meta_leak, tx_buf_leak);
        let udp_socket = udp::Socket::new(rx_buffer, tx_buffer);

        let handle = sockets.add(udp_socket);
        sockets.get_mut::<udp::Socket>(handle).bind(local_port).ok();

        Self {
            sockets,
            udp_handle: handle,
            message_id: 0,
            coap_buf: [0u8; 256],
            server_endpoint,
        }
    }

    /// Poll the network interface using the internal SocketSet. This lets CommunicationManager own the sockets
    /// while the caller provides the interface and device.
    pub fn poll<DeviceT>(&mut self, iface: &mut Interface, net: &mut DeviceT, timestamp: Instant)
    where
        DeviceT: Device,
    {
        iface.poll(timestamp, net, &mut self.sockets);
    }

    /// Send a CoAP payload to the server using the internal socket stored in the SocketSet.
    /// Returns true if sent.
    pub fn send_to_server(&mut self, payload: &[u8]) -> bool {
        if let Some(len) = coap_utils::build_coap_non_post(self.message_id, payload, &mut self.coap_buf)
        {
            if let Ok(_) = self.sockets.get_mut::<udp::Socket>(self.udp_handle).send_slice(&self.coap_buf[..len], self.server_endpoint) {
                self.message_id = self.message_id.wrapping_add(1);
                return true;
            }
        }
        false
    }

    /// Send payload and attempt to receive a CoAP payload response; returns the extracted payload or None.
    pub fn send_and_receive(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let sent = self.send_to_server(payload);
        if !sent {
            return None;
        }
        // attempt to read immediately (caller should ensure poll is called regularly)
        if let Ok((data, _endpoint)) = self.sockets.get_mut::<udp::Socket>(self.udp_handle).recv() {
            if let Some(coap_payload) = coap_utils::extract_coap_payload(data) {
                return Some(coap_payload.to_vec());
            }
        }
        None
    }

    /// Non-blocking receive attempt: returns the next CoAP payload if available (parsed into CommResponse).
    pub fn try_receive_parsed(&mut self) -> Option<CommResponse> {
        if let Ok((data, _endpoint)) = self.sockets.get_mut::<udp::Socket>(self.udp_handle).recv() {
            if let Some(coap_payload) = coap_utils::extract_coap_payload(data) {
                match coap_utils::parse_response(coap_payload) {
                    crate::coap_utils::ServerResponse::Ack => return Some(CommResponse::Ack),
                    crate::coap_utils::ServerResponse::AuthSessionTimeout => return Some(CommResponse::AuthSessionTimeout),
                    crate::coap_utils::ServerResponse::Unknown => return Some(CommResponse::Unknown(coap_payload.to_vec())),
                }
            }
        }
        None
    }

    /// Check whether internal socket can send right now.
    pub fn can_send(&mut self) -> bool {
        self.sockets.get_mut::<udp::Socket>(self.udp_handle).can_send()
    }
}
