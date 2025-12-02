use crate::transports::dtls::{DtlsState, DtlsTransport};
use crate::transports::ice::stun::random_u32;
use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tracing::{debug, trace, warn};

// DCEP Constants
const DATA_CHANNEL_PPID_DCEP: u32 = 50;
const DATA_CHANNEL_PPID_STRING: u32 = 51;
const DATA_CHANNEL_PPID_BINARY: u32 = 53;

const DCEP_TYPE_OPEN: u8 = 0x03;
const DCEP_TYPE_ACK: u8 = 0x02;

#[derive(Debug, Clone)]
pub struct DataChannelOpen {
    pub message_type: u8,
    pub channel_type: u8,
    pub priority: u16,
    pub reliability_parameter: u32,
    pub label: String,
    pub protocol: String,
}

impl DataChannelOpen {
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.message_type);
        buf.put_u8(self.channel_type);
        buf.put_u16(self.priority);
        buf.put_u32(self.reliability_parameter);

        let label_bytes = self.label.as_bytes();
        buf.put_u16(label_bytes.len() as u16);

        let protocol_bytes = self.protocol.as_bytes();
        buf.put_u16(protocol_bytes.len() as u16);

        buf.put_slice(label_bytes);
        buf.put_slice(protocol_bytes);

        buf.to_vec()
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        let mut buf = Bytes::copy_from_slice(data);
        if buf.remaining() < 12 {
            return Err(anyhow::anyhow!("DCEP Open message too short"));
        }

        let message_type = buf.get_u8();
        if message_type != DCEP_TYPE_OPEN {
            return Err(anyhow::anyhow!("Invalid DCEP message type"));
        }

        let channel_type = buf.get_u8();
        let priority = buf.get_u16();
        let reliability_parameter = buf.get_u32();
        let label_len = buf.get_u16() as usize;
        let protocol_len = buf.get_u16() as usize;

        if buf.remaining() < label_len + protocol_len {
            return Err(anyhow::anyhow!("DCEP Open message too short for payload"));
        }

        let label_bytes = buf.split_to(label_len);
        let protocol_bytes = buf.split_to(protocol_len);

        let label = String::from_utf8(label_bytes.to_vec())?;
        let protocol = String::from_utf8(protocol_bytes.to_vec())?;

        Ok(Self {
            message_type,
            channel_type,
            priority,
            reliability_parameter,
            label,
            protocol,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DataChannelAck {
    pub message_type: u8,
}

impl DataChannelAck {
    pub fn marshal(&self) -> Vec<u8> {
        vec![self.message_type]
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(anyhow::anyhow!("DCEP Ack message too short"));
        }
        let message_type = data[0];
        if message_type != DCEP_TYPE_ACK {
            return Err(anyhow::anyhow!("Invalid DCEP message type"));
        }
        Ok(Self { message_type })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpState {
    New,
    Connecting,
    Connected,
    Closed,
}

#[derive(Debug, Clone)]
pub enum DataChannelEvent {
    Open,
    Message(Bytes),
    Close,
}

pub struct DataChannel {
    pub id: u16,
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub negotiated: bool,
    pub state: AtomicUsize,
    pub next_ssn: AtomicU16,
    tx: Mutex<Option<mpsc::UnboundedSender<DataChannelEvent>>>,
    rx: TokioMutex<mpsc::UnboundedReceiver<DataChannelEvent>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum DataChannelState {
    Connecting = 0,
    Open = 1,
    Closing = 2,
    Closed = 3,
}

impl From<usize> for DataChannelState {
    fn from(v: usize) -> Self {
        match v {
            0 => DataChannelState::Connecting,
            1 => DataChannelState::Open,
            2 => DataChannelState::Closing,
            3 => DataChannelState::Closed,
            _ => DataChannelState::Closed,
        }
    }
}

// SCTP Constants
const SCTP_COMMON_HEADER_SIZE: usize = 12;
const CHUNK_HEADER_SIZE: usize = 4;

// Chunk Types
const CT_DATA: u8 = 0;
const CT_INIT: u8 = 1;
const CT_INIT_ACK: u8 = 2;
const CT_SACK: u8 = 3;
const CT_HEARTBEAT: u8 = 4;
const CT_HEARTBEAT_ACK: u8 = 5;
#[allow(unused)]
const CT_ABORT: u8 = 6;
#[allow(unused)]
const CT_SHUTDOWN: u8 = 7;
#[allow(unused)]
const CT_SHUTDOWN_ACK: u8 = 8;
#[allow(unused)]
const CT_ERROR: u8 = 9;
const CT_COOKIE_ECHO: u8 = 10;
const CT_COOKIE_ACK: u8 = 11;

struct SctpInner {
    dtls_transport: Arc<DtlsTransport>,
    state: Arc<Mutex<SctpState>>,
    data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
    local_port: u16,
    remote_port: u16,
    verification_tag: AtomicU32,
    remote_verification_tag: AtomicU32,
    next_tsn: AtomicU32,
    cumulative_tsn_ack: AtomicU32,
    new_data_channel_tx: Option<mpsc::UnboundedSender<Arc<DataChannel>>>,
    sack_counter: AtomicU8,
    is_client: bool,
}

struct SctpCleanupGuard<'a> {
    inner: &'a SctpInner,
}

impl<'a> Drop for SctpCleanupGuard<'a> {
    fn drop(&mut self) {
        *self.inner.state.lock().unwrap() = SctpState::Closed;

        let channels = self.inner.data_channels.lock().unwrap();
        for weak_dc in channels.iter() {
            if let Some(dc) = weak_dc.upgrade() {
                let old_state = dc
                    .state
                    .swap(DataChannelState::Closed as usize, Ordering::SeqCst);
                if old_state != DataChannelState::Closed as usize {
                    dc.send_event(DataChannelEvent::Close);
                    dc.close_channel();
                }
            }
        }
    }
}

pub struct SctpTransport {
    inner: Arc<SctpInner>,
    close_tx: Arc<tokio::sync::Notify>,
}

impl SctpTransport {
    pub fn new(
        dtls_transport: Arc<DtlsTransport>,
        incoming_data_rx: mpsc::Receiver<Bytes>,
        data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
        local_port: u16,
        remote_port: u16,
        new_data_channel_tx: Option<mpsc::UnboundedSender<Arc<DataChannel>>>,
        is_client: bool,
    ) -> (
        Arc<Self>,
        impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let inner = Arc::new(SctpInner {
            dtls_transport,
            state: Arc::new(Mutex::new(SctpState::New)),
            data_channels,
            local_port,
            remote_port,
            verification_tag: AtomicU32::new(0),
            remote_verification_tag: AtomicU32::new(0),
            next_tsn: AtomicU32::new(0),
            cumulative_tsn_ack: AtomicU32::new(0),
            new_data_channel_tx,
            sack_counter: AtomicU8::new(0),
            is_client,
        });

        let close_tx = Arc::new(tokio::sync::Notify::new());
        let close_rx = close_tx.clone();

        let transport = Arc::new(Self {
            inner: inner.clone(),
            close_tx,
        });

        let inner_clone = inner.clone();
        let runner = async move {
            inner_clone.run_loop(close_rx, incoming_data_rx).await;
        };

        (transport, runner)
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> Result<()> {
        self.inner.send_data(channel_id, data).await
    }

    pub async fn send_text(&self, channel_id: u16, data: impl AsRef<str>) -> Result<()> {
        self.inner.send_text(channel_id, data).await
    }

    pub async fn send_dcep_open(&self, dc: &DataChannel) -> Result<()> {
        self.inner.send_dcep_open(dc).await
    }
}

impl Drop for SctpTransport {
    fn drop(&mut self) {
        self.close_tx.notify_waiters();
    }
}

impl SctpInner {
    async fn run_loop(
        &self,
        close_rx: Arc<tokio::sync::Notify>,
        mut incoming_data_rx: mpsc::Receiver<Bytes>,
    ) {
        *self.state.lock().unwrap() = SctpState::Connecting;

        // Guard to ensure cleanup happens on drop (cancellation)
        let _guard = SctpCleanupGuard { inner: self };

        // Wait for DTLS to be connected
        let mut dtls_state_rx = self.dtls_transport.subscribe_state();
        loop {
            let state = dtls_state_rx.borrow_and_update().clone();
            if let DtlsState::Connected(_, _) = state {
                break;
            }
            if let DtlsState::Failed | DtlsState::Closed = state {
                warn!("DTLS failed or closed before SCTP start");
                return;
            }
            if dtls_state_rx.changed().await.is_err() {
                return;
            }
        }

        if self.is_client {
            if let Err(e) = self.send_init().await {
                warn!("Failed to send SCTP INIT: {}", e);
            }
        }

        loop {
            tokio::select! {
                _ = close_rx.notified() => break,
                res = incoming_data_rx.recv() => {
                    match res {
                        Some(packet) => {
                            if let Err(e) = self.handle_packet(packet).await {
                                warn!("SCTP handle packet error: {}", e);
                            }
                        }
                        None => {
                            warn!("SCTP loop error: Channel closed");
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn send_init(&self) -> Result<()> {
        let local_tag = random_u32();
        self.verification_tag.store(local_tag, Ordering::SeqCst);

        let initial_tsn = random_u32();
        self.next_tsn.store(initial_tsn, Ordering::SeqCst);

        let mut init_params = BytesMut::new();
        // Initiate Tag
        init_params.put_u32(local_tag);
        // a_rwnd
        init_params.put_u32(128 * 1024);
        // Outbound streams
        init_params.put_u16(10);
        // Inbound streams
        init_params.put_u16(10);
        // Initial TSN
        init_params.put_u32(initial_tsn);

        // Optional: Supported Address Types (IPv4)
        init_params.put_u16(12); // Type 12
        init_params.put_u16(6); // Length 6
        init_params.put_u16(5); // IPv4
        init_params.put_u16(0); // Padding

        self.send_chunk(CT_INIT, 0, init_params.freeze(), 0).await
    }

    async fn handle_packet(&self, packet: Bytes) -> Result<()> {
        if packet.len() < SCTP_COMMON_HEADER_SIZE {
            return Ok(());
        }

        let mut buf = packet;
        let _src_port = buf.get_u16();
        let _dst_port = buf.get_u16();
        let verification_tag = buf.get_u32();
        let _checksum = buf.get_u32();

        // Verify checksum (TODO)

        while buf.has_remaining() {
            if buf.remaining() < CHUNK_HEADER_SIZE {
                break;
            }
            let chunk_type = buf.get_u8();
            let chunk_flags = buf.get_u8();
            let chunk_length = buf.get_u16() as usize;

            // println!("SCTP Chunk: type={} len={}", chunk_type, chunk_length);

            if chunk_length < CHUNK_HEADER_SIZE
                || buf.remaining() < chunk_length - CHUNK_HEADER_SIZE
            {
                break;
            }

            let chunk_value = buf.split_to(chunk_length - CHUNK_HEADER_SIZE);

            // Padding
            let padding = (4 - (chunk_length % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }

            match chunk_type {
                CT_INIT => self.handle_init(verification_tag, chunk_value).await?,
                CT_INIT_ACK => self.handle_init_ack(chunk_value).await?,
                CT_COOKIE_ECHO => self.handle_cookie_echo(chunk_value).await?,
                CT_COOKIE_ACK => self.handle_cookie_ack(chunk_value).await?,
                CT_DATA => self.handle_data(chunk_flags, chunk_value).await?,
                CT_SACK => self.handle_sack(chunk_value).await?,
                CT_HEARTBEAT => self.handle_heartbeat(chunk_value).await?,
                _ => {
                    trace!("Unhandled SCTP chunk type: {}", chunk_type);
                }
            }
        }
        Ok(())
    }

    async fn handle_init(&self, _remote_tag: u32, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 16 {
            // Fixed params
            return Ok(());
        }
        let initiate_tag = buf.get_u32();
        let _a_rwnd = buf.get_u32();
        let _outbound_streams = buf.get_u16();
        let _inbound_streams = buf.get_u16();
        let initial_tsn = buf.get_u32();

        self.remote_verification_tag
            .store(initiate_tag, Ordering::SeqCst);
        self.cumulative_tsn_ack
            .store(initial_tsn.wrapping_sub(1), Ordering::SeqCst);

        // Generate local tag
        let local_tag = random_u32();
        self.verification_tag.store(local_tag, Ordering::SeqCst);

        // Send INIT ACK
        // We need to construct a cookie. For simplicity, we'll just echo back some dummy data.
        let cookie = b"dummy_cookie";

        let mut init_ack_params = BytesMut::new();
        // Initiate Tag
        init_ack_params.put_u32(local_tag);
        // a_rwnd
        init_ack_params.put_u32(128 * 1024);
        // Outbound streams
        init_ack_params.put_u16(10);
        // Inbound streams
        init_ack_params.put_u16(10);
        // Initial TSN
        let initial_tsn = random_u32();
        self.next_tsn.store(initial_tsn, Ordering::SeqCst);
        init_ack_params.put_u32(initial_tsn);

        // State Cookie Parameter (Type 7)
        init_ack_params.put_u16(7);
        init_ack_params.put_u16(4 + cookie.len() as u16);
        init_ack_params.put_slice(cookie);
        // Padding for cookie
        let padding = (4 - (cookie.len() % 4)) % 4;
        for _ in 0..padding {
            init_ack_params.put_u8(0);
        }

        self.send_chunk(CT_INIT_ACK, 0, init_ack_params.freeze(), initiate_tag)
            .await?;
        Ok(())
    }

    async fn handle_init_ack(&self, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 16 {
            return Ok(());
        }
        let initiate_tag = buf.get_u32();
        let _a_rwnd = buf.get_u32();
        let _outbound_streams = buf.get_u16();
        let _inbound_streams = buf.get_u16();
        let initial_tsn = buf.get_u32();

        self.remote_verification_tag
            .store(initiate_tag, Ordering::SeqCst);
        self.cumulative_tsn_ack
            .store(initial_tsn.wrapping_sub(1), Ordering::SeqCst);

        // Parse parameters to find Cookie
        let mut cookie = None;
        while buf.remaining() >= 4 {
            let param_type = buf.get_u16();
            let param_len = buf.get_u16() as usize;
            if param_len < 4 || buf.remaining() < param_len - 4 {
                break;
            }
            let param_value = buf.split_to(param_len - 4);

            // Padding
            let padding = (4 - (param_len % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }

            if param_type == 7 {
                // State Cookie
                cookie = Some(param_value);
            }
        }

        if let Some(cookie_bytes) = cookie {
            let tag = self.remote_verification_tag.load(Ordering::SeqCst);
            self.send_chunk(CT_COOKIE_ECHO, 0, cookie_bytes, tag)
                .await?;
        }

        Ok(())
    }

    async fn handle_cookie_ack(&self, _chunk: Bytes) -> Result<()> {
        *self.state.lock().unwrap() = SctpState::Connected;

        let channels_to_process = {
            let mut channels = self.data_channels.lock().unwrap();
            let mut to_process = Vec::new();
            channels.retain(|weak_dc| {
                if let Some(dc) = weak_dc.upgrade() {
                    to_process.push(dc);
                    true
                } else {
                    false
                }
            });
            to_process
        };

        for dc in channels_to_process {
            if dc.negotiated {
                dc.state
                    .store(DataChannelState::Open as usize, Ordering::SeqCst);
                dc.send_event(DataChannelEvent::Open);
            } else {
                let state = dc.state.load(Ordering::SeqCst);
                if state == DataChannelState::Connecting as usize {
                    if let Err(e) = self.send_dcep_open(&dc).await {
                        warn!("Failed to send DCEP OPEN: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_sack(&self, _chunk: Bytes) -> Result<()> {
        // TODO: Handle SACK for retransmission
        Ok(())
    }

    async fn handle_cookie_echo(&self, _chunk: Bytes) -> Result<()> {
        // Send COOKIE ACK
        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.send_chunk(CT_COOKIE_ACK, 0, Bytes::new(), tag).await?;

        *self.state.lock().unwrap() = SctpState::Connected;

        let channels_to_process = {
            let mut channels = self.data_channels.lock().unwrap();
            let mut to_process = Vec::new();
            channels.retain(|weak_dc| {
                if let Some(dc) = weak_dc.upgrade() {
                    to_process.push(dc);
                    true
                } else {
                    false
                }
            });
            to_process
        };

        for dc in channels_to_process {
            if dc.negotiated {
                dc.state
                    .store(DataChannelState::Open as usize, Ordering::SeqCst);
                dc.send_event(DataChannelEvent::Open);
            } else {
                let state = dc.state.load(Ordering::SeqCst);
                if state == DataChannelState::Connecting as usize {
                    if let Err(e) = self.send_dcep_open(&dc).await {
                        warn!("Failed to send DCEP OPEN: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_heartbeat(&self, chunk: Bytes) -> Result<()> {
        // Send HEARTBEAT ACK with same info
        // ...

        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.send_chunk(CT_HEARTBEAT_ACK, 0, chunk, tag).await?;
        Ok(())
    }

    async fn handle_data(&self, _flags: u8, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 12 {
            return Ok(());
        }
        let tsn = buf.get_u32();
        let stream_id = buf.get_u16();
        let _stream_seq = buf.get_u16();
        let payload_proto = buf.get_u32();

        let user_data = buf;

        // Deduplication and Ordering Check
        let cumulative_ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
        let diff = tsn.wrapping_sub(cumulative_ack);

        let should_drop = if diff == 0 || diff > 0x80000000 {
            // Duplicate or Old
            true
        } else if diff == 1 {
            // Next in sequence
            self.cumulative_tsn_ack.store(tsn, Ordering::SeqCst);
            false
        } else {
            // Gap
            true
        };

        if should_drop {
            let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
            self.send_sack(ack).await?;
            return Ok(());
        }

        // Send SACK (Delayed Ack: every 2 packets)
        let count = self.sack_counter.fetch_add(1, Ordering::Relaxed);
        if count >= 1 {
            self.sack_counter.store(0, Ordering::Relaxed);
            let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
            self.send_sack(ack).await?;
        }

        if payload_proto == DATA_CHANNEL_PPID_DCEP {
            self.handle_dcep(stream_id, user_data).await?;
            return Ok(());
        }

        let found_dc = {
            let channels = self.data_channels.lock().unwrap();
            channels
                .iter()
                .find_map(|weak_dc| weak_dc.upgrade().filter(|dc| dc.id == stream_id))
        };

        if let Some(dc) = found_dc {
            dc.send_event(DataChannelEvent::Message(user_data));
        }

        Ok(())
    }

    async fn handle_dcep(&self, stream_id: u16, data: Bytes) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let msg_type = data[0];
        match msg_type {
            DCEP_TYPE_OPEN => {
                let open = DataChannelOpen::unmarshal(&data)?;
                trace!("Received DCEP OPEN: {:?}", open);

                let mut found = false;
                {
                    let channels = self.data_channels.lock().unwrap();
                    for weak_dc in channels.iter() {
                        if let Some(dc) = weak_dc.upgrade() {
                            if dc.id == stream_id {
                                found = true;
                                break;
                            }
                        }
                    }
                }

                if !found {
                    // Create new channel
                    let config = DataChannelConfig {
                        label: open.label.clone(),
                        protocol: open.protocol,
                        ordered: (open.channel_type & 0x80) == 0,
                        max_retransmits: if (open.channel_type & 0x03) == 0x01
                            || (open.channel_type & 0x03) == 0x81
                        {
                            Some(open.reliability_parameter as u16)
                        } else {
                            None
                        },
                        max_packet_life_time: if (open.channel_type & 0x03) == 0x02
                            || (open.channel_type & 0x03) == 0x82
                        {
                            Some(open.reliability_parameter as u16)
                        } else {
                            None
                        },
                        negotiated: None,
                    };

                    let dc = Arc::new(DataChannel::new(stream_id, config));
                    dc.state
                        .store(DataChannelState::Open as usize, Ordering::SeqCst);
                    dc.send_event(DataChannelEvent::Open);

                    {
                        let mut channels = self.data_channels.lock().unwrap();
                        channels.push(Arc::downgrade(&dc));
                    }

                    if let Some(tx) = &self.new_data_channel_tx {
                        let _ = tx.send(dc.clone());
                    } else {
                        debug!(
                            "New DataChannel created from DCEP: id={} label={} (no listener)",
                            stream_id, open.label
                        );
                    }
                }

                // Send ACK
                self.send_dcep_ack(stream_id).await?;
            }
            DCEP_TYPE_ACK => {
                trace!("Received DCEP ACK for stream {}", stream_id);
                let channels = self.data_channels.lock().unwrap();
                for weak_dc in channels.iter() {
                    if let Some(dc) = weak_dc.upgrade() {
                        if dc.id == stream_id {
                            if dc
                                .state
                                .compare_exchange(
                                    DataChannelState::Connecting as usize,
                                    DataChannelState::Open as usize,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .is_ok()
                            {
                                dc.send_event(DataChannelEvent::Open);
                            }
                            break;
                        }
                    }
                }
            }
            _ => {
                debug!("Unknown DCEP message type: {}", msg_type);
            }
        }
        Ok(())
    }

    async fn send_sack(&self, cumulative_tsn_ack: u32) -> Result<()> {
        let mut sack = BytesMut::new();
        sack.put_u32(cumulative_tsn_ack); // Cumulative TSN Ack
        sack.put_u32(1024 * 1024); // a_rwnd
        sack.put_u16(0); // Number of Gap Ack Blocks
        sack.put_u16(0); // Number of Duplicate TSNs

        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.send_chunk(CT_SACK, 0, sack.freeze(), tag).await
    }

    async fn send_chunk(
        &self,
        type_: u8,
        flags: u8,
        value: Bytes,
        verification_tag: u32,
    ) -> Result<()> {
        let value_len = value.len();
        let padding = (4 - (value_len % 4)) % 4;
        let total_len = SCTP_COMMON_HEADER_SIZE + CHUNK_HEADER_SIZE + value_len + padding;

        let mut packet = BytesMut::with_capacity(total_len);

        // Common Header
        packet.put_u16(self.local_port);
        packet.put_u16(self.remote_port);
        packet.put_u32(verification_tag);
        packet.put_u32(0); // Checksum placeholder

        // Chunk
        packet.put_u8(type_);
        packet.put_u8(flags);
        packet.put_u16((CHUNK_HEADER_SIZE + value_len) as u16);
        packet.put_slice(&value);

        // Padding
        for _ in 0..padding {
            packet.put_u8(0);
        }

        // Calculate Checksum (CRC32c)
        let checksum = crc32c::crc32c(&packet);

        let checksum_bytes = checksum.to_le_bytes();

        packet[8] = checksum_bytes[0];
        packet[9] = checksum_bytes[1];
        packet[10] = checksum_bytes[2];
        packet[11] = checksum_bytes[3];

        self.dtls_transport.send(packet.freeze()).await
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> Result<()> {
        self.send_data_raw(channel_id, DATA_CHANNEL_PPID_BINARY, data)
            .await
    }

    pub async fn send_text(&self, channel_id: u16, data: impl AsRef<str>) -> Result<()> {
        self.send_data_raw(
            channel_id,
            DATA_CHANNEL_PPID_STRING,
            data.as_ref().as_bytes(),
        )
        .await
    }

    pub async fn send_data_raw(&self, channel_id: u16, ppid: u32, data: &[u8]) -> Result<()> {
        // Calculate total size
        // Common Header: 12
        // Chunk Header: 4
        // TSN: 4, StreamID: 2, StreamSeq: 2, PPID: 4 = 12
        // Data: N
        // Padding: 0-3

        let data_len = data.len();
        let chunk_value_len = 12 + data_len;
        let chunk_len = 4 + chunk_value_len;
        let padding = (4 - (chunk_len % 4)) % 4;
        let total_len = 12 + chunk_len + padding;

        let mut buf = BytesMut::with_capacity(total_len);

        // Common Header
        buf.put_u16(self.local_port);
        buf.put_u16(self.remote_port);
        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        buf.put_u32(tag);
        buf.put_u32(0); // Checksum placeholder (offset 8)

        // Chunk Header (DATA)
        buf.put_u8(CT_DATA);
        buf.put_u8(0x03); // Flags: B|E
        buf.put_u16(chunk_len as u16);

        // DATA Chunk Value
        let tsn = self.next_tsn.fetch_add(1, Ordering::SeqCst);

        let ssn = {
            let channels = self.data_channels.lock().unwrap();
            let found_dc = channels
                .iter()
                .find_map(|weak_dc| weak_dc.upgrade().filter(|dc| dc.id == channel_id));

            if let Some(dc) = found_dc {
                dc.next_ssn.fetch_add(1, Ordering::SeqCst)
            } else {
                0
            }
        };

        buf.put_u32(tsn);
        buf.put_u16(channel_id);
        buf.put_u16(ssn);
        buf.put_u32(ppid);
        buf.put_slice(data);

        // Padding
        for _ in 0..padding {
            buf.put_u8(0);
        }

        // CRC32c
        let checksum = crc32c::crc32c(&buf);
        let checksum_bytes = checksum.to_le_bytes();
        buf[8] = checksum_bytes[0];
        buf[9] = checksum_bytes[1];
        buf[10] = checksum_bytes[2];
        buf[11] = checksum_bytes[3];

        self.dtls_transport.send(buf.freeze()).await
    }

    pub async fn send_dcep_open(&self, dc: &DataChannel) -> Result<()> {
        let channel_type = if dc.ordered {
            if dc.max_retransmits.is_some() {
                0x01 // DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT
            } else if dc.max_packet_life_time.is_some() {
                0x02 // DATA_CHANNEL_PARTIAL_RELIABLE_TIMED
            } else {
                0x00 // DATA_CHANNEL_RELIABLE
            }
        } else {
            if dc.max_retransmits.is_some() {
                0x81 // DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED
            } else if dc.max_packet_life_time.is_some() {
                0x82 // DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED
            } else {
                0x80 // DATA_CHANNEL_RELIABLE_UNORDERED
            }
        };

        let reliability_parameter = if let Some(r) = dc.max_retransmits {
            r as u32
        } else if let Some(t) = dc.max_packet_life_time {
            t as u32
        } else {
            0
        };

        let open = DataChannelOpen {
            message_type: DCEP_TYPE_OPEN,
            channel_type,
            priority: 0,
            reliability_parameter,
            label: dc.label.clone(),
            protocol: dc.protocol.clone(),
        };

        let payload = open.marshal();
        self.send_data_raw(dc.id, DATA_CHANNEL_PPID_DCEP, &payload)
            .await
    }

    pub async fn send_dcep_ack(&self, channel_id: u16) -> Result<()> {
        let ack = DataChannelAck {
            message_type: DCEP_TYPE_ACK,
        };
        let payload = ack.marshal();
        self.send_data_raw(channel_id, DATA_CHANNEL_PPID_DCEP, &payload)
            .await
    }
}

#[derive(Debug, Clone, Default)]
pub struct DataChannelConfig {
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub negotiated: Option<u16>,
}

impl DataChannel {
    pub fn new(id: u16, config: DataChannelConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            id,
            label: config.label,
            protocol: config.protocol,
            ordered: config.ordered,
            max_retransmits: config.max_retransmits,
            max_packet_life_time: config.max_packet_life_time,
            negotiated: config.negotiated.is_some(),
            state: AtomicUsize::new(DataChannelState::Connecting as usize),
            next_ssn: AtomicU16::new(0),
            tx: Mutex::new(Some(tx)),
            rx: TokioMutex::new(rx),
        }
    }

    pub async fn recv(&self) -> Option<DataChannelEvent> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }

    pub(crate) fn send_event(&self, event: DataChannelEvent) {
        if let Some(tx) = &*self.tx.lock().unwrap() {
            let _ = tx.send(event);
        }
    }

    pub(crate) fn close_channel(&self) {
        *self.tx.lock().unwrap() = None;
    }
}
