#![no_std]
#![no_main]
 
mod config;
mod crypto;
mod secure_store;
mod auth_manager;
mod virtio_rng;
mod virtio_net;
mod hal;
mod uart;
mod clock;
mod communication_manager;
mod coap_utils;
 
use core::arch::global_asm;
use linked_list_allocator::LockedHeap;
extern crate alloc;
use alloc::vec;
use communication_manager::CommResponse;

use virtio_drivers::device::net::VirtIONet;
use virtio_drivers::device::rng::VirtIORng;
use virtio_drivers::transport::mmio::MmioTransport;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use virtio_rng::VirtioRngDevice;
use virtio_net::VirtioNetDevice;
use secure_store::DeviceKeyStore;
use hal::MyHal;
use auth_manager::AuthManager;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

const MAC_ADDR: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const LOCAL_IP: (u8, u8, u8, u8) = (172, 20, 0, 3);
const LOCAL_PORT: u16 = 5683;

const SERVER_IP: (u8, u8, u8, u8) = (172, 20, 0, 2);
const SERVER_PORT: u16 = 5683;
 
global_asm!(
    r#"
    .section .text._start
    .global _start
_start:
    // Azzera la .bss (variabili statiche non inizializzate).
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:
    cmp x0, x1
    b.ge 2f
    str xzr, [x0], #8
    b 1b
2:
    ldr x0, =__stack_top
    mov sp, x0
    bl _start_main
3:
    wfe
    b 3b
    "#
);
 
#[unsafe(no_mangle)]
pub extern "C" fn _start_main() -> ! {
    main();
}

fn main() -> ! {
    unsafe {
        ALLOCATOR.lock().init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }

    // Init Network Driver
    let net_transport = virtio_net::init_net_transport();
    let virtio_net = VirtIONet::<MyHal, MmioTransport, 16>::new(net_transport, 2048)
        .expect("virtio-net init failed");
    let mut net = VirtioNetDevice::new(virtio_net);

    // Init RNG Driver
    let rng_transport = virtio_rng::find_rng_transport();
    let virtio_rng = VirtIORng::<MyHal, MmioTransport>::new(rng_transport)
        .expect("virtio-rng init failed");
    let mut rng_dev = VirtioRngDevice::new(virtio_rng);
    
    // Init keys and secure store
    let keys  = config::read_initial_keys();
    let key_count = keys.len();
    let skey = config::read_skey();

    let mut key_store = DeviceKeyStore::init(*skey);
    key_store
        .store_keys(keys, key_count, &mut rng_dev)
        .expect("Failed to encrypt and store device keys");

    // Config SMOLTCP interface
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(MAC_ADDR)));
    let mut iface = Interface::new(config, &mut net, Instant::from_millis(0));
    iface.update_ip_addrs(|ips| {
        ips.push(IpCidr::new(
            IpAddress::v4(LOCAL_IP.0, LOCAL_IP.1, LOCAL_IP.2, LOCAL_IP.3),
            24,
        ))
        .unwrap();
    });

    let mut socket_storage = vec![];
    let sockets = SocketSet::new(&mut socket_storage[..]);

    // Server Endpoint
    let server_endpoint = IpEndpoint::new(
        IpAddress::v4(SERVER_IP.0, SERVER_IP.1, SERVER_IP.2, SERVER_IP.3),
        SERVER_PORT,
    );

    // Init Communication Manager
    let comm_manager = communication_manager::CommunicationManager::new(sockets, LOCAL_PORT, server_endpoint);

    // Init Auth Session Manager 
    let iot_uid: u8 = config::read_iot_uid();
    let p: u8 = config::read_p();
    let mut auth_manager = AuthManager::new(&mut key_store, rng_dev, comm_manager, iot_uid, p);

    auth_manager.init_auth_session();

    const TELEMETRY_INTERVAL_MS: i64 = 5000;
    let mut next_send_at: i64 = 0;
    let mut telemtry_data: u64 = 0;

    loop {
        let now_ms = clock::now_millis();
        let timestamp = Instant::from_millis(now_ms);

        auth_manager.poll(&mut iface, &mut net, timestamp);

        // Send IoT telemetry data to server via CommunicationManager (delegate
        // through AuthManager)
        if auth_manager.can_send() && now_ms >= next_send_at {
            let payload = telemtry_data.to_be_bytes();
            let _sent = auth_manager.send_telemetry(&payload);
        }

        // Server response handling (non-blocking receive via CommunicationManager)
        if let Some(msg) = auth_manager.try_receive_parsed() {
            match msg {
                CommResponse::Ack => {
                    // the payload that was acknowledged is the telemetry value we sent previously
                    let acked = telemtry_data.to_be_bytes();
                    auth_manager.append_acked_telemetry(&acked);

                    next_send_at = clock::now_millis() + TELEMETRY_INTERVAL_MS;
                    telemtry_data += 1;
                }
                CommResponse::AuthSessionTimeout => {
                    let _ = auth_manager.update_keys();
                    uart::puts("AuthManager: session timeout, keys updated\r\n");
                    auth_manager.init_auth_session();
                    next_send_at = clock::now_millis() + TELEMETRY_INTERVAL_MS;
                }
                CommResponse::Unknown(_payload) => {
                    uart::puts("ERROR: unknown CoAP response payload\r\n");
                }
            }
        }
    }
}
 
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
 