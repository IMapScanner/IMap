/*************************************************************************
	> File Name: parser.p4
	> Author: Guanyu Li
	> Mail: dracula.guanyu.li@gmail.com
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Parser declaration for data plane programs of IMap
 ************************************************************************/

#ifndef _PARSER_
#define _PARSER_

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        //pkt.extract(ig_md.resubmit_hdr);
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// Empty egress parser/control blocks
parser EmptyEgressParser<H, M>(
        packet_in pkt,
        out H hdr,
        out M eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

parser StackParser(packet_in pkt, out custom_header_t hdr) {
    state start { // parse Ethernet
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            default : reject;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
            (0x0001, ETHERTYPE_IPV4) : parse_arp_ipv4;
            default : reject;
        }
    }

    state parse_arp_ipv4 {
        pkt.extract(hdr.arp_ipv4);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP  : parse_tcp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default : accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP  : parse_tcp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default : accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

parser ImapEgressParser(packet_in pkt,
                        out custom_header_t hdr,
                        out egress_metadata_t eg_md) {
    Checksum() icmp_csum;
    Checksum() tcp_csum;

    state start {
        internal_metadata_t internal_md = pkt.lookahead<internal_metadata_t>();
        transition select(internal_md.pkt_label) {
            PKT_LABEL_UPDATE_NOTIFY: parse_mirror;
            default: parse_bridged;
        }
    }

    state parse_mirror {
        pkt.extract(eg_md.mirror);
        transition parse_ethernet;
    }

    state parse_bridged {
        pkt.extract(eg_md.bridged);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        eg_md.swp_mac = hdr.ethernet.src_mac;
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_ITEMPLATE : parse_ipv4;
            default : reject;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
            (0x0001, ETHERTYPE_IPV4) : parse_arp_ipv4;
            default : reject;
        }
    }

    state parse_arp_ipv4 {
        pkt.extract(hdr.arp_ipv4);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
#if __IP_TYPE__ != 6 // Default IPv4
        eg_md.swp_ip = hdr.ipv4.src_ip;
#endif
        tcp_csum.subtract({ hdr.ipv4.src_ip, hdr.ipv4.dst_ip });
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP  : parse_tcp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default : accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
#if __IP_TYPE__ == 6
        eg_md.swp_ip = hdr.ipv6.src_ip;
#endif
        tcp_csum.subtract({ hdr.ipv6.src_ip, hdr.ipv6.dst_ip });
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP  : parse_tcp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default : accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        icmp_csum.subtract({ hdr.icmp.checksum });
        icmp_csum.subtract({ hdr.icmp.id, hdr.icmp.seq_no });
        eg_md.icmp_csum = icmp_csum.get();
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        eg_md.swp_port = hdr.tcp.src_port;
        eg_md.tmp_seq = hdr.tcp.seq_no;
        tcp_csum.subtract({ hdr.tcp.checksum });
        tcp_csum.subtract({
            hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no, hdr.tcp.ack_no,
            hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.urg,
            hdr.tcp.ack, hdr.tcp.psh, hdr.tcp.rst, hdr.tcp.syn, hdr.tcp.fin
        });
        eg_md.tcp_csum = tcp_csum.get();
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

#endif /* _PARSER_ */
