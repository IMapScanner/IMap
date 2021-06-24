/*************************************************************************
	> File Name: header.p4
	> Author:
	> Mail:
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Header declaration for data plane programs of IMap
 ************************************************************************/

#ifndef _HEADER_
#define _HEADER_

#include "../../iconfig.h"

typedef bit<9>   port_t;
typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12>  vlan_id_t;

typedef bit<IP_RANGE_INDEX_BITS> ipr_idx_t;
typedef bit<IP_RANGE_INDEX_PER_PORT_BITS> ipr_idx_pidx_t;

typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

const ether_type_t ETHERTYPE_IRESULT = ETHER_TYPE_IRESULT;
const ether_type_t ETHERTYPE_IREPORT = ETHER_TYPE_IREPORT;
const ether_type_t ETHERTYPE_IFLUSH  = ETHER_TYPE_IFLUSH;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const bit<16> ARP_OPCODE_REQUEST = 1;
const bit<16> ARP_OPCODE_REPLY   = 2;

// 0: Normal packet
// 1: Template packet
// 2: Probe response packet (the target is active)
// 3: Probe response packet (the target is inactive)
// 4: Probe packets seed in Ingress or probe packet in Egress
// 5: ARP request packet for PROBER_IP
// 6: Flush request packet from the control plane
// 7: Update notirication to the control plane
typedef bit<8> pkt_label_t;
const pkt_label_t PKT_LABEL_NORMAL        = 0;
const pkt_label_t PKT_LABEL_INACTIVE_RESP = 1;
const pkt_label_t PKT_LABEL_ACTIVE_RESP   = 2;
const pkt_label_t PKT_LABEL_TEMPLATE      = 3;
const pkt_label_t PKT_LABEL_SEED          = 4;
const pkt_label_t PKT_LABEL_ARP_REQUEST   = 5;
const pkt_label_t PKT_LABEL_FLUSH_REQUEST = 6;
const pkt_label_t PKT_LABEL_UPDATE_NOTIFY = 7;

header ethernet_h {
    mac_addr_t dst_mac;
    mac_addr_t src_mac;
    bit<16>    ether_type;
}

header vlan_tag_h {
    bit<3>    pcp;
    bit<1>    cfi;
    vlan_id_t vid;
    bit<16>   ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3>  exp;
    bit<1>  bos;
    bit<8>  ttl;
}

header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    ipv4_addr_t src_ip;
    ipv4_addr_t dst_ip;
}

header ipv6_h {
    bit<4>      version;
    bit<8>      traffic_class;
    bit<20>     flow_label;
    bit<16>     payload_len;
    bit<8>      next_hdr;
    bit<8>      hop_limit;
    ipv6_addr_t src_ip;
    ipv6_addr_t dst_ip;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<6>  res;
    // Here we employ 6 byte flags
    // bit<6> flags;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8>  type_;
    bit<8>  code;
    bit<16> hdr_checksum;
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_addr_len;
    bit<8>  proto_addr_len;
    bit<16> opcode;
    // ...
}

header arp_ipv4_h {
    mac_addr_t  src_hw_addr;
    ipv4_addr_t src_proto_addr;
    mac_addr_t  dst_hw_addr;
    ipv4_addr_t dst_proto_addr;
}

// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8>  next_hdr;
    bit<8>  hdr_ext_len;
    bit<8>  routing_type;
    bit<8>  seg_left;
    bit<8>  last_entry;
    bit<8>  flags;
    bit<16> tag;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8>  flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8>  reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    bit<1>  C;
    bit<1>  R;
    bit<1>  K;
    bit<1>  S;
    bit<1>  s;
    bit<3>  recurse;
    bit<5>  flags;
    bit<3>  version;
    bit<16> proto;
}

header result_pack_h {
    bit<32> target_0;
    bit<32> target_1;
    bit<32> target_2;
    bit<32> target_3;
    bit<32> target_4;
    bit<32> target_5;
    bit<32> target_6;
    bit<32> target_7;
    bit<32>  result_0;
    bit<32>  result_1;
    bit<32>  result_2;
    bit<32>  result_3;
    bit<32>  result_4;
    bit<32>  result_5;
    bit<32>  result_6;
    bit<32>  result_7;
}

header result_meta_h {
    bit<8>  resp_pkt_count;
}

struct result_h {
    result_meta_h result_meta;
    result_pack_h result_pack_0;
    result_pack_h result_pack_1;
}

header update_notification_h {
    bit<8>    probe_table;
    ipr_idx_t pipr_idx; // Probe IP Range Index
    bit<7>    _pad;     // For aligning
    port_t    egress_port;
}

#define INTERNAL_MD  \
    pkt_label_t pkt_label

struct internal_metadata_t {
    INTERNAL_MD;
}

header bridged_h {
    // Indicate the imap packet type
    INTERNAL_MD;
    bit<8>  resp_pkt_count;
    bit<16> probe_port_stride;
    bit<32> probe_result;
}

header mirror_h {
    INTERNAL_MD;
    bit<8>    probe_table;
    ipr_idx_t pipr_idx; // Probe IP Range Index
    bit<7>    _pad;     // For aligning
    port_t    egress_port;
    bit<16>   probe_port_stride;
}

struct ingress_metadata_t {
    bridged_h bridged;
    bit<16>   probe_resp_port;
    bit<32>   probe_resp_ack;
    bit<32>   last_probe_timer;
}

struct egress_metadata_t {
    bridged_h   bridged;
    mirror_h    mirror;
    update_notification_h update_notification;
    result_h              result;
    bit<16>     checksum;
    bit<48>     swp_mac;
#if __IP_TYPE__ == 6
    ipv6_addr_t swp_ip;
#else // Default IPv4
    ipv4_addr_t swp_ip;
#endif
    bit<16>     swp_port;
    bit<32>     tmp_seq;
    bit<8>      probe_table;
    ipr_idx_pidx_t pipr_border;
    ipr_idx_t      pipr_idx; // Probe IP Range Index
    bit<32>        pipr_end;
    MirrorId_t  update_notification_mirror_sid;   // Egress mirror session ID
}

struct custom_header_t {
    ethernet_h ethernet;
    arp_h      arp;
    arp_ipv4_h arp_ipv4;
    ipv4_h     ipv4;
    ipv6_h     ipv6;
    icmp_h     icmp;
    tcp_h      tcp;
    udp_h      udp;
}

struct probe_port_t {
    bit<16> pipr_switch_times;
    bit<16> probe_port;
}

#endif /* _HEADER_ */
