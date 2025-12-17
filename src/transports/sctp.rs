use crate::transports::dtls::{DtlsState, DtlsTransport};
use crate::transports::ice::stun::random_u32;
use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as TokioMutex, Notify, mpsc};
use tracing::{debug, info, trace, warn};

// DCEP Constants
const DATA_CHANNEL_PPID_DCEP: u32 = 50;
const DATA_CHANNEL_PPID_STRING: u32 = 51;
const DATA_CHANNEL_PPID_BINARY: u32 = 53;

const DCEP_TYPE_OPEN: u8 = 0x03;
const DCEP_TYPE_ACK: u8 = 0x02;

// RTO Constants (RFC 4960)
const RTO_INITIAL: f64 = 3.0;
const RTO_MIN: f64 = 1.0;
const RTO_MAX: f64 = 60.0;
const RTO_ALPHA: f64 = 0.125;
const RTO_BETA: f64 = 0.25;

// Flow Control Constants
const CWND_INITIAL: usize = 1200 * 10; // Start with ~10 packets

#[derive(Debug, Clone)]
struct ChunkRecord {
    payload: Bytes,
    sent_time: Instant,
    transmit_count: u32,
    missing_reports: u8,
}

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
    pub max_payload_size: usize,
    pub negotiated: bool,
    pub state: AtomicUsize,
    pub next_ssn: AtomicU16,
    tx: Mutex<Option<mpsc::UnboundedSender<DataChannelEvent>>>,
    rx: TokioMutex<mpsc::UnboundedReceiver<DataChannelEvent>>,
    reassembly_buffer: Mutex<Vec<u8>>,
    pub(crate) send_lock: TokioMutex<()>,
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
const LOCAL_RWND_BYTES: usize = 1024 * 1024;
const DUP_THRESH: u8 = 3;

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

#[derive(Debug)]
struct RtoCalculator {
    srtt: f64,
    rttvar: f64,
    rto: f64,
}

impl RtoCalculator {
    fn new() -> Self {
        Self {
            srtt: 0.0,
            rttvar: 0.0,
            rto: RTO_INITIAL,
        }
    }

    fn update(&mut self, rtt: f64) {
        if self.srtt == 0.0 {
            self.srtt = rtt;
            self.rttvar = rtt / 2.0;
        } else {
            self.rttvar = (1.0 - RTO_BETA) * self.rttvar + RTO_BETA * (self.srtt - rtt).abs();
            self.srtt = (1.0 - RTO_ALPHA) * self.srtt + RTO_ALPHA * rtt;
        }
        self.rto = (self.srtt + 4.0 * self.rttvar).clamp(RTO_MIN, RTO_MAX);
    }

    fn backoff(&mut self) {
        self.rto = (self.rto * 2.0).min(RTO_MAX);
    }
}

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
    sent_queue: Mutex<BTreeMap<u32, ChunkRecord>>,
    received_queue: Mutex<BTreeMap<u32, (u8, Bytes)>>,

    // RTO State
    rto_state: Mutex<RtoCalculator>,

    // Flow Control
    flight_size: AtomicUsize,
    cwnd: AtomicUsize,
    ssthresh: AtomicUsize,
    peer_rwnd: AtomicU32, // Peer's Advertised Receiver Window
    timer_notify: Arc<Notify>,
    flow_control_notify: Arc<Notify>,
    ack_delay_ms: AtomicU32,
    ack_scheduled: AtomicBool,
    last_gap_sig: AtomicU32,
    dups_buffer: Mutex<Vec<u32>>, // duplicate TSNs to include in next SACK
    last_immediate_sack: Mutex<Option<Instant>>, // throttle immediate SACKs
}

struct SctpCleanupGuard<'a> {
    inner: &'a SctpInner,
}

/// Build Gap Ack Blocks from buffered out-of-order packets so the peer knows
/// exactly which TSNs we have received beyond the cumulative ack. We limit the
/// number of blocks to keep the SACK compact and stay within 16-bit offsets.
fn build_gap_ack_blocks_from_map(
    received: &BTreeMap<u32, (u8, Bytes)>,
    cumulative_tsn_ack: u32,
) -> Vec<(u16, u16)> {
    let mut blocks: Vec<(u16, u16)> = Vec::new();
    let mut current: Option<(u32, u32)> = None;

    for &tsn in received.keys() {
        // Ignore any TSN that is already cumulatively acked or would wrap.
        if tsn <= cumulative_tsn_ack {
            continue;
        }

        match current {
            Some((start, end)) if tsn == end.wrapping_add(1) => {
                current = Some((start, tsn));
            }
            Some((start, end)) => {
                let start_off = start.wrapping_sub(cumulative_tsn_ack);
                let end_off = end.wrapping_sub(cumulative_tsn_ack);
                if start_off <= u16::MAX as u32 && end_off <= u16::MAX as u32 {
                    blocks.push((start_off as u16, end_off as u16));
                }
                current = Some((tsn, tsn));
            }
            None => {
                current = Some((tsn, tsn));
            }
        }

        if blocks.len() >= 16 {
            break; // keep SACK compact
        }
    }

    if blocks.len() < 16 {
        if let Some((start, end)) = current {
            let start_off = start.wrapping_sub(cumulative_tsn_ack);
            let end_off = end.wrapping_sub(cumulative_tsn_ack);
            if start_off <= u16::MAX as u32 && end_off <= u16::MAX as u32 {
                blocks.push((start_off as u16, end_off as u16));
            }
        }
    }

    blocks
}

#[derive(Debug, Default, PartialEq)]
struct SackOutcome {
    flight_reduction: usize,
    rtt_samples: Vec<f64>,
    retransmit: Vec<(u32, Bytes)>,
    head_moved: bool,
}

fn apply_sack_to_sent_queue(
    sent_queue: &mut BTreeMap<u32, ChunkRecord>,
    cumulative_tsn_ack: u32,
    gap_blocks: &[(u16, u16)],
    now: Instant,
) -> SackOutcome {
    let before_head = sent_queue.keys().next().cloned();

    let mut max_reported = cumulative_tsn_ack;
    for (_start, end) in gap_blocks {
        let block_end = cumulative_tsn_ack.wrapping_add(*end as u32);
        if block_end > max_reported {
            max_reported = block_end;
        }
    }

    let mut outcome = SackOutcome::default();

    // Remove everything that the SACK explicitly acknowledges.
    let mut to_remove = Vec::new();
    for (&tsn, record) in sent_queue.iter() {
        let gap_acked = gap_blocks.iter().any(|(start, end)| {
            let s = cumulative_tsn_ack.wrapping_add(*start as u32);
            let e = cumulative_tsn_ack.wrapping_add(*end as u32);
            tsn >= s && tsn <= e
        });

        if tsn <= cumulative_tsn_ack || gap_acked {
            outcome.flight_reduction += record.payload.len();
            if record.transmit_count == 0 {
                outcome
                    .rtt_samples
                    .push(now.duration_since(record.sent_time).as_secs_f64());
            }
            to_remove.push(tsn);
        }
    }

    for tsn in to_remove {
        sent_queue.remove(&tsn);
    }

    // Mark missing reports and schedule fast retransmits.
    for (&tsn, record) in sent_queue.iter_mut() {
        let gap_acked = gap_blocks.iter().any(|(start, end)| {
            let s = cumulative_tsn_ack.wrapping_add(*start as u32);
            let e = cumulative_tsn_ack.wrapping_add(*end as u32);
            tsn >= s && tsn <= e
        });

        if tsn <= max_reported && tsn > cumulative_tsn_ack && !gap_acked {
            record.missing_reports = record.missing_reports.saturating_add(1);
        } else {
            record.missing_reports = 0;
        }

        if record.missing_reports >= DUP_THRESH {
            record.missing_reports = 0;
            record.transmit_count += 1;
            record.sent_time = now;
            outcome.retransmit.push((tsn, record.payload.clone()));
        }
    }

    let after_head = sent_queue.keys().next().cloned();
    outcome.head_moved = before_head != after_head;

    outcome
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
            sent_queue: Mutex::new(BTreeMap::new()),
            received_queue: Mutex::new(BTreeMap::new()),
            rto_state: Mutex::new(RtoCalculator::new()),
            flight_size: AtomicUsize::new(0),
            cwnd: AtomicUsize::new(CWND_INITIAL),
            ssthresh: AtomicUsize::new(usize::MAX),
            peer_rwnd: AtomicU32::new(1024 * 1024), // Default 1MB until we hear otherwise
            timer_notify: Arc::new(Notify::new()),
            flow_control_notify: Arc::new(Notify::new()),
            ack_delay_ms: AtomicU32::new(200),
            ack_scheduled: AtomicBool::new(false),
            last_gap_sig: AtomicU32::new(0),
            dups_buffer: Mutex::new(Vec::new()),
            last_immediate_sack: Mutex::new(None),
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

    pub fn buffered_amount(&self) -> usize {
        self.inner.flight_size.load(Ordering::SeqCst)
    }
}

impl Drop for SctpTransport {
    fn drop(&mut self) {
        self.close_tx.notify_waiters();
    }
}

impl SctpInner {
    fn compute_ack_delay_ms(&self, has_gap: bool) -> u32 {
        if !has_gap {
            return 200;
        }
        let srtt = self.rto_state.lock().unwrap().srtt;
        if srtt == 0.0 {
            return 50;
        }
        let ms = (srtt * 1000.0 * 0.25).round() as u32;
        ms.clamp(20, 200)
    }

    fn gap_signature(&self, cumulative_tsn_ack: u32) -> u32 {
        let blocks = self.build_gap_ack_blocks(cumulative_tsn_ack);
        let mut sig: u32 = 0x9E37_79B9; // golden ratio constant seed
        for (s, e) in blocks {
            let pair = ((s as u32) << 16) | (e as u32);
            // mix
            sig = sig.wrapping_add(pair ^ (pair.rotate_left(13)));
            sig ^= sig.rotate_left(7);
        }
        sig
    }
    async fn run_loop(
        &self,
        close_rx: Arc<tokio::sync::Notify>,
        mut incoming_data_rx: mpsc::Receiver<Bytes>,
    ) {
        debug!("SctpTransport run_loop started");
        *self.state.lock().unwrap() = SctpState::Connecting;

        // Guard to ensure cleanup happens on drop (cancellation)
        let _guard = SctpCleanupGuard { inner: self };

        // Wait for DTLS to be connected
        let mut dtls_state_rx = self.dtls_transport.subscribe_state();
        loop {
            let state = dtls_state_rx.borrow_and_update().clone();
            if let DtlsState::Connected(_, _) = state {
                debug!("SCTP: DTLS connected, starting SCTP");
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

        let mut sack_deadline: Option<Instant> = None;

        loop {
            let now = Instant::now();

            // 1. Calculate RTO Timeout
            let rto_timeout = {
                let sent_queue = self.sent_queue.lock().unwrap();
                if let Some((_, record)) = sent_queue.iter().next() {
                    let rto = self.rto_state.lock().unwrap().rto;
                    let expiry = record.sent_time + Duration::from_secs_f64(rto);
                    if expiry > now {
                        expiry - now
                    } else {
                        Duration::from_millis(1)
                    }
                } else {
                    Duration::from_secs(3600)
                }
            };

            // 2. Calculate SACK Timeout
            let sack_timeout = if self.sack_counter.load(Ordering::Relaxed) > 0 {
                if sack_deadline.is_none() {
                    let delay = self.ack_delay_ms.load(Ordering::Relaxed);
                    sack_deadline = Some(now + Duration::from_millis(delay as u64));
                }
                let deadline = sack_deadline.unwrap();
                if deadline > now {
                    deadline - now
                } else {
                    Duration::from_millis(1)
                }
            } else {
                sack_deadline = None;
                Duration::from_secs(3600)
            };

            let sleep_duration = rto_timeout.min(sack_timeout);

            tokio::select! {
                _ = close_rx.notified() => {
                    debug!("SctpTransport run_loop exiting (closed)");
                    break;
                },
                _ = self.timer_notify.notified() => {
                    // Woken up by sender, recalculate timeout
                },
                _ = tokio::time::sleep(sleep_duration) => {
                    // Check SACK Timer
                    if let Some(deadline) = sack_deadline {
                        if Instant::now() >= deadline {
                            let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
                            // Only send if we still have pending acks
                            if self.sack_counter.load(Ordering::Relaxed) > 0 {
                                trace!("SACK Timer expired, sending SACK for {}", ack);
                                if let Err(e) = self.send_sack(ack).await {
                                    warn!("Failed to send Delayed SACK: {}", e);
                                }
                                self.sack_counter.store(0, Ordering::Relaxed);
                                self.ack_scheduled.store(false, Ordering::Relaxed);
                            }
                            sack_deadline = None;
                        }
                    }

                    // Check RTO Timer
                    // We check this regardless of whether sleep woke up due to RTO or SACK,
                    // because they might be close.
                    if let Err(e) = self.handle_timeout().await {
                        warn!("SCTP handle timeout error: {}", e);
                    }
                },
                res = incoming_data_rx.recv() => {
                    match res {
                        Some(packet) => {
                            if let Err(e) = self.handle_packet(packet).await {
                                warn!("SCTP handle packet error: {}", e);
                            }
                            // Batch receive: try to drain channel
                            while let Ok(packet) = incoming_data_rx.try_recv() {
                                if let Err(e) = self.handle_packet(packet).await {
                                    warn!("SCTP handle packet error: {}", e);
                                }
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
        info!("SctpTransport run_loop finished");
    }

    async fn handle_timeout(&self) -> Result<()> {
        let mut to_retransmit = Vec::new();

        // 1. Collect all expired chunks and backoff RTO once
        let now = Instant::now();
        let rto = { self.rto_state.lock().unwrap().rto };
        {
            let mut sent_queue = self.sent_queue.lock().unwrap();
            for (tsn, record) in sent_queue.iter_mut() {
                let expiry = record.sent_time + Duration::from_secs_f64(rto);
                if now >= expiry {
                    to_retransmit.push((*tsn, record.payload.clone()));
                    record.transmit_count += 1;
                    record.sent_time = now; // restart timer; don't sample RTT on retransmit
                }
            }
        }

        if !to_retransmit.is_empty() {
            // Backoff RTO once per timer tick
            let mut rto_state = self.rto_state.lock().unwrap();
            rto_state.backoff();
            debug!(
                "T3-RTX Timeout! Retransmitting {} chunks, New RTO: {}",
                to_retransmit.len(),
                rto_state.rto
            );

            // Reduce ssthresh and cwnd (Simplified)
            let flight_size = self.flight_size.load(Ordering::SeqCst);
            let new_ssthresh = (flight_size / 2).max(1200 * 4);
            self.ssthresh.store(new_ssthresh, Ordering::SeqCst);
            self.cwnd.store(1200, Ordering::SeqCst);
        }

        // 2. Retransmit expired chunks
        for (tsn, data) in to_retransmit {
            if let Err(e) = self.dtls_transport.send(data).await {
                warn!("Failed to retransmit TSN {}: {}", tsn, e);
            }
        }

        Ok(())
    }

    fn update_rto(&self, rtt: f64) {
        let mut rto_state = self.rto_state.lock().unwrap();
        rto_state.update(rtt);
        trace!(
            "RTT update: rtt={} srtt={} rttvar={} rto={}",
            rtt, rto_state.srtt, rto_state.rttvar, rto_state.rto
        );
    }

    async fn send_init(&self) -> Result<()> {
        let local_tag = random_u32();
        self.verification_tag.store(local_tag, Ordering::SeqCst);

        let initial_tsn = random_u32();
        self.next_tsn.store(initial_tsn, Ordering::SeqCst);

        let mut init_params = BytesMut::new();
        // Initiate Tag
        init_params.put_u32(local_tag);
        // a_rwnd (1MB)
        init_params.put_u32(1024 * 1024);
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
        let a_rwnd = buf.get_u32();
        let _outbound_streams = buf.get_u16();
        let _inbound_streams = buf.get_u16();
        let initial_tsn = buf.get_u32();

        self.peer_rwnd.store(a_rwnd, Ordering::SeqCst);
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
        let a_rwnd = buf.get_u32();
        let _outbound_streams = buf.get_u16();
        let _inbound_streams = buf.get_u16();
        let initial_tsn = buf.get_u32();

        self.peer_rwnd.store(a_rwnd, Ordering::SeqCst);
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

    async fn handle_sack(&self, chunk: Bytes) -> Result<()> {
        // Parse SACK to see if we are losing packets
        if chunk.len() >= 12 {
            let mut buf = chunk.clone();
            let cumulative_tsn_ack = buf.get_u32();
            let a_rwnd = buf.get_u32();
            let num_gap_ack_blocks = buf.get_u16();
            let _num_duplicate_tsns = buf.get_u16();

            self.peer_rwnd.store(a_rwnd, Ordering::SeqCst);
            let mut gap_blocks = Vec::new();
            for _ in 0..num_gap_ack_blocks {
                if buf.remaining() < 4 {
                    break;
                }
                gap_blocks.push((buf.get_u16(), buf.get_u16()));
            }

            let now = Instant::now();
            let outcome = {
                let mut sent_queue = self.sent_queue.lock().unwrap();
                apply_sack_to_sent_queue(&mut *sent_queue, cumulative_tsn_ack, &gap_blocks, now)
            };

            for rtt in outcome.rtt_samples {
                self.update_rto(rtt);
            }

            if outcome.flight_reduction > 0 {
                self.flight_size
                    .fetch_sub(outcome.flight_reduction, Ordering::SeqCst);

                // Congestion Control: Update cwnd
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let ssthresh = self.ssthresh.load(Ordering::SeqCst);

                if cwnd <= ssthresh {
                    // Slow Start: cwnd += min(bytes_acked, MTU)
                    let increase = outcome.flight_reduction.min(1200);
                    self.cwnd.fetch_add(increase, Ordering::SeqCst);
                } else {
                    // Congestion Avoidance: cwnd += (MTU * bytes_acked) / cwnd
                    let increase = (1200 * outcome.flight_reduction) / cwnd;
                    if increase > 0 {
                        self.cwnd.fetch_add(increase, Ordering::SeqCst);
                    }
                }

                self.flow_control_notify.notify_waiters();
            }

            if outcome.head_moved {
                self.timer_notify.notify_one();
            }

            for (tsn, data) in outcome.retransmit {
                if let Err(e) = self.dtls_transport.send(data).await {
                    warn!("Failed to retransmit TSN {}: {}", tsn, e);
                }
            }
        }
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

    async fn handle_data(&self, flags: u8, chunk: Bytes) -> Result<()> {
        let mut buf = chunk.clone();
        if buf.remaining() < 12 {
            return Ok(());
        }
        let tsn = buf.get_u32();

        // Deduplication and Ordering Check
        let cumulative_ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
        let diff = tsn.wrapping_sub(cumulative_ack);

        if diff == 0 || diff > 0x80000000 {
            // Duplicate or Old: record duplicate and schedule fast SACK
            {
                let mut dups = self.dups_buffer.lock().unwrap();
                if dups.len() < 32 {
                    dups.push(tsn);
                }
            }
            let delay = self.compute_ack_delay_ms(true);
            self.ack_delay_ms.store(delay, Ordering::Relaxed);
            if self
                .ack_scheduled
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.sack_counter.store(1, Ordering::Relaxed);
                self.timer_notify.notify_one();
            }
            return Ok(());
        }

        // Store in received_queue
        {
            let mut received_queue = self.received_queue.lock().unwrap();
            if received_queue.contains_key(&tsn) {
                debug!("Dropping duplicate buffered packet TSN={}", tsn);
            } else {
                received_queue.insert(tsn, (flags, chunk));
            }
        }

        // Process packets in order
        loop {
            let next_tsn = self
                .cumulative_tsn_ack
                .load(Ordering::SeqCst)
                .wrapping_add(1);

            let packet_entry = {
                let mut received_queue = self.received_queue.lock().unwrap();
                received_queue.remove(&next_tsn)
            };

            if let Some((p_flags, p_chunk)) = packet_entry {
                // Process this packet
                self.process_data_payload(p_flags, p_chunk).await?;
                self.cumulative_tsn_ack.store(next_tsn, Ordering::SeqCst);
            } else {
                break;
            }
        }

        let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);

        // Check if we have a gap
        let has_gap = !self.received_queue.lock().unwrap().is_empty();

        if has_gap {
            // Prefer quick delayed ack when gaps exist
            let delay = self.compute_ack_delay_ms(true);
            self.ack_delay_ms.store(delay, Ordering::Relaxed);
            // If the gap pattern changed, send an immediate SACK once
            let sig = self.gap_signature(ack);
            let prev = self.last_gap_sig.swap(sig, Ordering::Relaxed);
            if sig != prev {
                // Throttle immediate SACKs to avoid spamming; use RTT-based minimum interval
                let min_ms = self.compute_ack_delay_ms(true);
                let now = Instant::now();
                let allow_immediate = {
                    let last = self.last_immediate_sack.lock().unwrap();
                    match *last {
                        Some(t) => now.duration_since(t) >= Duration::from_millis(min_ms as u64),
                        None => true,
                    }
                };
                if allow_immediate {
                    debug!("Gap changed. Immediate SACK; cum_ack={}.", ack);
                    self.send_sack(ack).await?;
                    self.ack_scheduled.store(false, Ordering::Relaxed);
                    self.sack_counter.store(0, Ordering::Relaxed);
                    {
                        let mut last = self.last_immediate_sack.lock().unwrap();
                        *last = Some(now);
                    }
                } else if self
                    .ack_scheduled
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    debug!(
                        "Gap detected. Cumulative ACK: {}. Scheduling delayed SACK.",
                        ack
                    );
                    self.sack_counter.store(1, Ordering::Relaxed);
                    self.timer_notify.notify_one();
                }
            } else if self
                .ack_scheduled
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                debug!(
                    "Gap detected. Cumulative ACK: {}. Scheduling delayed SACK.",
                    ack
                );
                self.sack_counter.store(1, Ordering::Relaxed);
                self.timer_notify.notify_one();
            }
        } else {
            // Restore normal delayed ack timing
            self.ack_delay_ms.store(200, Ordering::Relaxed);
            // Delayed Ack logic (RFC 4960): send SACK every 2 packets
            let count = self.sack_counter.fetch_add(1, Ordering::Relaxed);
            if count >= 1 {
                self.sack_counter.store(0, Ordering::Relaxed);
                self.send_sack(ack).await?;
            }
            // If count was 0, it is now 1. The run_loop will pick this up and set the timer.
        }
        Ok(())
    }

    async fn process_data_payload(&self, flags: u8, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        // Skip TSN (4 bytes)
        buf.advance(4);

        let stream_id = buf.get_u16();
        let _stream_seq = buf.get_u16();
        let payload_proto = buf.get_u32();

        let user_data = buf;

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
            // Handle fragmentation
            // B bit: 0x02, E bit: 0x01
            let b_bit = (flags & 0x02) != 0;
            let e_bit = (flags & 0x01) != 0;

            let mut buffer = dc.reassembly_buffer.lock().unwrap();
            if b_bit {
                if !buffer.is_empty() {
                    warn!(
                        "SCTP Reassembly: unexpected B bit, clearing buffer of size {}",
                        buffer.len()
                    );
                }
                buffer.clear();
            }
            buffer.extend_from_slice(&user_data);
            if e_bit {
                let msg = Bytes::from(buffer.clone());
                buffer.clear();
                dc.send_event(DataChannelEvent::Message(msg));
            }
        } else {
            warn!("SCTP: Received data for unknown stream id {}", stream_id);
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
                        max_payload_size: None,
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

    /// Build Gap Ack Blocks from buffered out-of-order packets so the peer knows
    /// exactly which TSNs we have received beyond the cumulative ack. We limit
    /// the number of blocks to keep the SACK compact and stay within 16-bit
    /// offsets.
    fn build_gap_ack_blocks(&self, cumulative_tsn_ack: u32) -> Vec<(u16, u16)> {
        let received = self.received_queue.lock().unwrap();
        build_gap_ack_blocks_from_map(&received, cumulative_tsn_ack)
    }

    fn advertised_rwnd(&self) -> u32 {
        let mut used: usize = 0;
        {
            let received = self.received_queue.lock().unwrap();
            used += received
                .values()
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>();
        }

        {
            let channels = self.data_channels.lock().unwrap();
            for weak_dc in channels.iter() {
                if let Some(dc) = weak_dc.upgrade() {
                    used += dc.reassembly_buffer.lock().unwrap().len();
                }
            }
        }

        LOCAL_RWND_BYTES
            .saturating_sub(used)
            .try_into()
            .unwrap_or(0)
    }

    async fn send_sack(&self, cumulative_tsn_ack: u32) -> Result<()> {
        let mut sack = BytesMut::new();
        sack.put_u32(cumulative_tsn_ack); // Cumulative TSN Ack
        sack.put_u32(self.advertised_rwnd()); // a_rwnd reflects buffered state
        let gap_blocks = self.build_gap_ack_blocks(cumulative_tsn_ack);
        let dups = {
            let mut d = self.dups_buffer.lock().unwrap();
            let mut out = Vec::new();
            while !d.is_empty() && out.len() < 32 {
                out.push(d.remove(0));
            }
            out
        };
        sack.put_u16(gap_blocks.len() as u16); // Number of Gap Ack Blocks
        sack.put_u16(dups.len() as u16); // Number of Duplicate TSNs

        for (start, end) in &gap_blocks {
            sack.put_u16(*start);
            sack.put_u16(*end);
        }
        for tsn in dups {
            sack.put_u32(tsn);
        }

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
        let dc_opt = {
            let channels = self.data_channels.lock().unwrap();
            channels
                .iter()
                .find_map(|weak_dc| weak_dc.upgrade().filter(|dc| dc.id == channel_id))
        };

        let mut max_payload_size = 1200;
        let mut ordered = true;
        let (_guard, ssn) = if let Some(dc) = &dc_opt {
            let guard = dc.send_lock.lock().await;
            ordered = dc.ordered;
            let ssn = if ordered {
                dc.next_ssn.fetch_add(1, Ordering::SeqCst)
            } else {
                0
            };
            max_payload_size = dc.max_payload_size;
            (Some(guard), ssn)
        } else {
            (None, 0)
        };

        // Flow Control Check
        // We loop to send data in chunks that fit within the congestion window.
        // This prevents bursting large messages and flooding the network.
        let total_len = data.len();

        if total_len == 0 {
            // Send empty packet (unfragmented)
            // Wait for window space for at least 1 byte/packet
            loop {
                let flight = self.flight_size.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                if flight >= effective_window {
                    self.flow_control_notify.notified().await;
                } else {
                    break;
                }
            }

            let tsn = self.next_tsn.fetch_add(1, Ordering::SeqCst);
            let mut flags = 0x03;
            if !ordered {
                flags |= 0x04;
            }
            let packet = self.create_packet(channel_id, ppid, data, ssn, flags, tsn);
            {
                let mut queue = self.sent_queue.lock().unwrap();
                let was_empty = queue.is_empty();
                let record = ChunkRecord {
                    payload: packet.clone(),
                    sent_time: Instant::now(),
                    transmit_count: 0,
                    missing_reports: 0,
                };
                queue.insert(tsn, record);
                self.flight_size.fetch_add(packet.len(), Ordering::SeqCst);
                if was_empty {
                    self.timer_notify.notify_one();
                }
            }
            return self.dtls_transport.send(packet).await;
        }

        let mut offset = 0;

        while offset < total_len {
            // 1. Wait for window space
            let allowed_bytes;
            loop {
                let flight = self.flight_size.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                if flight >= effective_window {
                    self.flow_control_notify.notified().await;
                } else {
                    let mut bytes = effective_window - flight;
                    if bytes == 0 {
                        // Should not happen if flight < effective_window, but safety check
                        bytes = max_payload_size;
                    }
                    allowed_bytes = bytes;
                    break;
                }
            }

            // 2. Create a batch of chunks that fits in the window
            let mut chunks = Vec::new();
            let mut batch_len = 0;

            while offset < total_len {
                let remaining = total_len - offset;
                let chunk_size = std::cmp::min(remaining, max_payload_size);

                // Check if we have room (approximate check before expensive create_packet)
                // Header overhead is ~28 bytes.
                if !chunks.is_empty() && batch_len + chunk_size + 28 > allowed_bytes {
                    break;
                }

                let mut flags = if offset == 0 {
                    if remaining <= max_payload_size {
                        0x03 // B=1, E=1 (Unfragmented)
                    } else {
                        0x02 // B=1, E=0 (First)
                    }
                } else if offset + chunk_size >= total_len {
                    0x01 // B=0, E=1 (Last)
                } else {
                    0x00 // B=0, E=0 (Middle)
                };

                if !ordered {
                    flags |= 0x04; // Set U bit
                }

                let tsn = self.next_tsn.fetch_add(1, Ordering::SeqCst);
                let chunk_data = &data[offset..offset + chunk_size];
                let packet = self.create_packet(channel_id, ppid, chunk_data, ssn, flags, tsn);

                let pkt_len = packet.len();
                chunks.push((tsn, packet));
                batch_len += pkt_len;
                offset += chunk_size;

                if batch_len >= allowed_bytes {
                    break;
                }
            }

            // 3. Batch insert into sent_queue
            {
                let mut queue = self.sent_queue.lock().unwrap();
                let now = Instant::now();
                let was_empty = queue.is_empty();

                for (tsn, packet) in &chunks {
                    let record = ChunkRecord {
                        payload: packet.clone(),
                        sent_time: now,
                        transmit_count: 0,
                        missing_reports: 0,
                    };
                    queue.insert(*tsn, record);
                }

                self.flight_size.fetch_add(batch_len, Ordering::SeqCst);

                // Only notify timer if the queue was empty (head changed)
                if was_empty {
                    self.timer_notify.notify_one();
                }
            }

            // 4. Batch send
            for (_, packet) in chunks {
                self.dtls_transport.send(packet).await?;
            }
        }

        Ok(())
    }
    fn create_packet(
        &self,
        channel_id: u16,
        ppid: u32,
        data: &[u8],
        ssn: u16,
        flags: u8,
        tsn: u32,
    ) -> Bytes {
        // Calculate total size
        // Common Header: 12
        // Chunk Header: 4
        // TSN: 4, StreamID: 2, StreamSeq: 2, PPID: 4 = 12
        // Data: N
        // Padding: 0-3

        let data_len = data.len();
        trace!(
            "Sending fragment: len={}, flags={:#x}, ssn={}",
            data_len, flags, ssn
        );
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
        buf.put_u8(flags); // Flags
        buf.put_u16(chunk_len as u16);

        // DATA Chunk Value
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

        buf.freeze()
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
    pub max_payload_size: Option<usize>,
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
            max_payload_size: config.max_payload_size.unwrap_or(1200),
            negotiated: config.negotiated.is_some(),
            state: AtomicUsize::new(DataChannelState::Connecting as usize),
            next_ssn: AtomicU16::new(0),
            tx: Mutex::new(Some(tx)),
            rx: TokioMutex::new(rx),
            reassembly_buffer: Mutex::new(Vec::new()),
            send_lock: TokioMutex::new(()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[test]
    fn test_rto_calculator() {
        let mut calc = RtoCalculator::new();
        assert_eq!(calc.rto, RTO_INITIAL);

        // First measurement: RTT = 1.0
        calc.update(1.0);
        // srtt = 1.0, rttvar = 0.5
        // rto = 1.0 + 4 * 0.5 = 3.0
        assert_eq!(calc.srtt, 1.0);
        assert_eq!(calc.rttvar, 0.5);
        assert_eq!(calc.rto, 3.0);

        // Second measurement: RTT = 1.0 (Stable)
        calc.update(1.0);
        // rttvar = (1 - 0.25) * 0.5 + 0.25 * |1.0 - 1.0| = 0.375
        // srtt = (1 - 0.125) * 1.0 + 0.125 * 1.0 = 1.0
        // rto = 1.0 + 4 * 0.375 = 1.0 + 1.5 = 2.5
        assert_eq!(calc.srtt, 1.0);
        assert_eq!(calc.rttvar, 0.375);
        assert_eq!(calc.rto, 2.5);

        // Backoff
        calc.backoff();
        assert_eq!(calc.rto, 5.0);
    }

    #[tokio::test]
    async fn test_rto_backoff() {
        let mut calc = RtoCalculator::new();
        calc.update(0.1); // RTT 100ms
        assert!(calc.rto >= 1.0); // Min RTO is 1.0s

        calc.backoff();
        assert!(calc.rto >= 2.0);
    }

    #[test]
    fn test_gap_ack_blocks_contiguous_and_gaps() {
        let mut received: BTreeMap<u32, (u8, Bytes)> = BTreeMap::new();
        // cumulative ack is 10; we have 12-13 contiguous and 15 isolated
        received.insert(12, (0, Bytes::new()));
        received.insert(13, (0, Bytes::new()));
        received.insert(15, (0, Bytes::new()));

        let blocks = build_gap_ack_blocks_from_map(&received, 10);
        assert_eq!(blocks, vec![(2, 3), (5, 5)]);
    }

    #[test]
    fn test_gap_ack_blocks_limit_to_16() {
        let mut received: BTreeMap<u32, (u8, Bytes)> = BTreeMap::new();
        // Build more than 16 small gaps; we should cap at 16 blocks
        let cumulative = 1;
        for i in 0..20 {
            // Place isolated TSNs two apart to force separate blocks
            let tsn = cumulative + 2 + i * 2;
            received.insert(tsn, (0, Bytes::new()));
        }

        let blocks = build_gap_ack_blocks_from_map(&received, cumulative);
        assert_eq!(blocks.len(), 16);
        // First block should start at offset 1 (tsn 3) and every block single TSN
        assert_eq!(blocks[0], (2, 2));
    }

    #[test]
    fn test_gap_ack_blocks_ignore_acked_or_wrapped() {
        let mut received: BTreeMap<u32, (u8, Bytes)> = BTreeMap::new();
        // Below or equal cumulative should be ignored
        received.insert(5, (0, Bytes::new()));
        received.insert(6, (0, Bytes::new()));
        // Valid ones after cumulative
        received.insert(8, (0, Bytes::new()));
        received.insert(9, (0, Bytes::new()));

        let blocks = build_gap_ack_blocks_from_map(&received, 6);
        assert_eq!(blocks, vec![(2, 3)]);
    }

    #[test]
    fn test_apply_sack_removes_gaps_and_tracks_rtt() {
        let mut sent: BTreeMap<u32, ChunkRecord> = BTreeMap::new();
        let base = Instant::now() - Duration::from_millis(100);
        sent.insert(
            10,
            ChunkRecord {
                payload: Bytes::from_static(b"a"),
                sent_time: base,
                transmit_count: 0,
                missing_reports: 0,
            },
        );
        sent.insert(
            11,
            ChunkRecord {
                payload: Bytes::from_static(b"b"),
                sent_time: base,
                transmit_count: 0,
                missing_reports: 0,
            },
        );
        sent.insert(
            12,
            ChunkRecord {
                payload: Bytes::from_static(b"c"),
                sent_time: base,
                transmit_count: 0,
                missing_reports: 0,
            },
        );

        // Ack cumulative 10 and gap-ack 12, leaving 11 outstanding.
        let outcome = apply_sack_to_sent_queue(&mut sent, 10, &[(2, 2)], Instant::now());

        assert_eq!(outcome.flight_reduction, 2); // a + c removed
        assert_eq!(outcome.rtt_samples.len(), 2);
        assert!(outcome.retransmit.is_empty());
        assert!(outcome.head_moved); // head advanced from 10 to 11

        assert_eq!(sent.len(), 1);
        assert!(sent.contains_key(&11));
    }

    #[test]
    fn test_fast_retransmit_after_dup_thresh() {
        let mut sent: BTreeMap<u32, ChunkRecord> = BTreeMap::new();
        let base = Instant::now() - Duration::from_millis(50);
        for tsn in 21..=23 {
            sent.insert(
                tsn,
                ChunkRecord {
                    payload: Bytes::from_static(b"p"),
                    sent_time: base,
                    transmit_count: 0,
                    missing_reports: 0,
                },
            );
        }

        // Repeated SACKs report up to TSN 23 but never ack TSN 22.
        let sack_gap = [(2u16, 2u16)];
        let mut outcome;

        outcome = apply_sack_to_sent_queue(&mut sent, 21, &sack_gap, Instant::now());
        assert_eq!(outcome.retransmit.len(), 0);
        assert_eq!(sent.len(), 1); // 21 and 23 acked

        outcome = apply_sack_to_sent_queue(&mut sent, 21, &sack_gap, Instant::now());
        assert_eq!(outcome.retransmit.len(), 0);

        outcome = apply_sack_to_sent_queue(&mut sent, 21, &sack_gap, Instant::now());
        assert_eq!(outcome.retransmit.len(), 1);
        assert_eq!(outcome.retransmit[0].0, 22);
        let rec = sent.get(&22).unwrap();
        assert_eq!(rec.missing_reports, 0);
    }
}
