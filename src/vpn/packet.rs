use std::net::Ipv4Addr;

pub const IPV4_HEADER_MIN_LEN: usize = 20;
pub const TCP_HEADER_MIN_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;
pub const ICMP_HEADER_LEN: usize = 8;

pub const PROTOCOL_ICMP: u8 = 1;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FiveTuple {
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }
    if i < data.len() {
        let word = u16::from_be_bytes([data[i], 0]);
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn calculate_transport_checksum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    transport_segment: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + transport_segment.len());
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(transport_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(transport_segment);
    calculate_checksum(&pseudo)
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub ihl: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < IPV4_HEADER_MIN_LEN {
            return None;
        }
        let ver_ihl = buf[0];
        let version = ver_ihl >> 4;
        if version != 4 {
            return None;
        }
        let ihl = (ver_ihl & 0x0F) * 4;
        if (ihl as usize) < IPV4_HEADER_MIN_LEN || buf.len() < (ihl as usize) {
            return None;
        }

        let total_length = u16::from_be_bytes([buf[2], buf[3]]);
        if buf.len() < (total_length as usize) {
            return None;
        }

        let identification = u16::from_be_bytes([buf[4], buf[5]]);
        let flags_fragment = u16::from_be_bytes([buf[6], buf[7]]);
        let ttl = buf[8];
        let protocol = buf[9];
        let checksum = u16::from_be_bytes([buf[10], buf[11]]);
        let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

        let payload_len = (total_length as usize) - (ihl as usize);
        let payload = &buf[(ihl as usize)..(ihl as usize) + payload_len];

        Some((
            Self {
                ihl,
                total_length,
                identification,
                flags_fragment,
                ttl,
                protocol,
                checksum,
                src_ip,
                dst_ip,
            },
            payload,
        ))
    }

    pub fn serialize_into(&self, buf: &mut [u8]) {
        buf[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        buf[1] = 0x00; // DSCP / ECN
        buf[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags_fragment.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&[0, 0]); // Zero before checksum
        buf[12..16].copy_from_slice(&self.src_ip.octets());
        buf[16..20].copy_from_slice(&self.dst_ip.octets());

        let csum = calculate_checksum(&buf[..20]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());
    }
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < TCP_HEADER_MIN_LEN {
            return None;
        }
        let src_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
        let seq = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ack = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let data_offset = (buf[12] >> 4) * 4;
        if (data_offset as usize) < TCP_HEADER_MIN_LEN || buf.len() < (data_offset as usize) {
            return None;
        }
        let flags = buf[13];
        let window_size = u16::from_be_bytes([buf[14], buf[15]]);
        let checksum = u16::from_be_bytes([buf[16], buf[17]]);
        let urgent_ptr = u16::from_be_bytes([buf[18], buf[19]]);
        let payload = &buf[(data_offset as usize)..];

        Some((
            Self {
                src_port,
                dst_port,
                seq,
                ack,
                data_offset,
                flags,
                window_size,
                checksum,
                urgent_ptr,
            },
            payload,
        ))
    }

    pub fn serialize_into(
        &self,
        buf: &mut [u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) {
        let header_len = self.data_offset as usize;
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack.to_be_bytes());
        buf[12] = ((header_len / 4) as u8) << 4;
        buf[13] = self.flags;
        buf[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        buf[16..18].copy_from_slice(&[0, 0]); // Zero before checksum
        buf[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());

        if !payload.is_empty() {
            buf[header_len..header_len + payload.len()].copy_from_slice(payload);
        }

        let segment_len = header_len + payload.len();
        let csum = calculate_transport_checksum(src_ip, dst_ip, PROTOCOL_TCP, &buf[..segment_len]);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_tcp_syn_ack_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    window_size: u16,
    mss: u16,
) -> Vec<u8> {
    let ip_hdr_len = 20usize;
    let tcp_hdr_len = 24usize; // 20 bytes TCP + 4 bytes MSS option
    let total_len = ip_hdr_len + tcp_hdr_len;

    let mut packet = vec![0u8; total_len];

    let ip_hdr = Ipv4Header {
        ihl: 20,
        total_length: total_len as u16,
        identification: 0x4242,
        flags_fragment: 0x4000, // Don't fragment
        ttl: 64,
        protocol: PROTOCOL_TCP,
        checksum: 0,
        src_ip,
        dst_ip,
    };
    ip_hdr.serialize_into(&mut packet[..20]);

    // TCP Options: MSS Option (Kind=2, Len=4, Value=mss)
    packet[40] = 0x02;
    packet[41] = 0x04;
    packet[42] = (mss >> 8) as u8;
    packet[43] = (mss & 0xFF) as u8;

    let tcp_hdr = TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        data_offset: 24,
        flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
        window_size,
        checksum: 0,
        urgent_ptr: 0,
    };
    tcp_hdr.serialize_into(&mut packet[20..], src_ip, dst_ip, &[]);

    packet
}

#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window_size: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_hdr_len = 20usize;
    let tcp_hdr_len = 20usize;
    let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

    let mut packet = vec![0u8; total_len];

    let ip_hdr = Ipv4Header {
        ihl: 20,
        total_length: total_len as u16,
        identification: 0x4242,
        flags_fragment: 0x4000, // Don't fragment
        ttl: 64,
        protocol: PROTOCOL_TCP,
        checksum: 0,
        src_ip,
        dst_ip,
    };
    ip_hdr.serialize_into(&mut packet[..20]);

    let tcp_hdr = TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        data_offset: 20,
        flags,
        window_size,
        checksum: 0,
        urgent_ptr: 0,
    };
    tcp_hdr.serialize_into(&mut packet[20..], src_ip, dst_ip, payload);

    packet
}

pub fn build_icmp_port_unreachable(router_ip: Ipv4Addr, original_packet: &[u8]) -> Option<Vec<u8>> {
    if original_packet.len() < 28 {
        return None;
    }
    let (orig_ip, _) = Ipv4Header::parse(original_packet)?;
    let client_ip = orig_ip.src_ip;

    let payload_slice_len = original_packet.len().min((orig_ip.ihl as usize) + 8);
    let icmp_payload = &original_packet[..payload_slice_len];

    let icmp_len = 8 + icmp_payload.len();
    let total_len = 20 + icmp_len;

    let mut packet = vec![0u8; total_len];

    let ip_hdr = Ipv4Header {
        ihl: 20,
        total_length: total_len as u16,
        identification: 0x1111,
        flags_fragment: 0,
        ttl: 64,
        protocol: PROTOCOL_ICMP,
        checksum: 0,
        src_ip: router_ip,
        dst_ip: client_ip,
    };
    ip_hdr.serialize_into(&mut packet[..20]);

    let icmp_buf = &mut packet[20..];
    icmp_buf[0] = 3; // Type 3: Destination Unreachable
    icmp_buf[1] = 3; // Code 3: Port Unreachable
    icmp_buf[2..4].copy_from_slice(&[0, 0]); // Zero checksum field prior to RFC 792 calculation
    icmp_buf[4..8].copy_from_slice(&[0, 0, 0, 0]); // Unused (must be zero)
    icmp_buf[8..8 + icmp_payload.len()].copy_from_slice(icmp_payload);

    let csum = calculate_checksum(&icmp_buf[..icmp_len]);
    icmp_buf[2..4].copy_from_slice(&csum.to_be_bytes());

    Some(packet)
}

pub fn build_icmp_echo_reply(original_packet: &[u8]) -> Option<Vec<u8>> {
    let (orig_ip, payload) = Ipv4Header::parse(original_packet)?;
    if orig_ip.protocol != PROTOCOL_ICMP || payload.len() < ICMP_HEADER_LEN {
        return None;
    }
    if payload[0] != 8 {
        // Not an Echo Request
        return None;
    }

    let _total_len = original_packet.len();
    let mut reply = original_packet.to_vec();

    // Swap IP addresses
    let client_ip = orig_ip.src_ip;
    let dest_ip = orig_ip.dst_ip;
    reply[12..16].copy_from_slice(&dest_ip.octets());
    reply[16..20].copy_from_slice(&client_ip.octets());

    // Recompute IP checksum
    reply[10..12].copy_from_slice(&[0, 0]);
    let ip_csum = calculate_checksum(&reply[..orig_ip.ihl as usize]);
    reply[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // Modify ICMP Type to 0 (Echo Reply)
    let icmp_offset = orig_ip.ihl as usize;
    reply[icmp_offset] = 0; // Type 0: Echo Reply
    reply[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&[0, 0]);
    let icmp_csum = calculate_checksum(&reply[icmp_offset..]);
    reply[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    Some(reply)
}
