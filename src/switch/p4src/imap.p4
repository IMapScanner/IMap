/*************************************************************************
	> File Name: imap.p4
	> Author:
	> Mail:
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Main data plane program (P4-16) of IMap
 ************************************************************************/

#include <core.p4>
#include <tna.p4>

#include "header.p4"
#include "parser.p4"
#include "../../iconfig.h"

// -----------------------------------------------------------------------------
// Ingress parser
// -----------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out custom_header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    StackParser() stack_parser;

    state start {
        ig_md.bridged.setValid();
        ig_md.bridged.pkt_label = PKT_LABEL_NORMAL;
        tofino_parser.apply(pkt, ig_intr_md);
        stack_parser.apply(pkt, hdr);
        transition accept;
    }
}


// -----------------------------------------------------------------------------
// Ingress control flow
// -----------------------------------------------------------------------------
control SwitchIngress(
        inout custom_header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    // ------------------------------ Stage 0 ------------------------------- //

    // ---------- ti_probe_port_stride_fetcher ---------- //

    // Here we use a register to store the probe port update stride configured
    // by control plane. It is used to judge when the probe port is increased.
    Register<bit<16>, _>(1) ri_probe_port_stride;
    RegisterAction<_, _, bit<16>>(ri_probe_port_stride)
                                 rai_probe_port_stride = {
        void apply(inout bit<16> value, out bit<16> output) {
            output = value;
        }
    };

    action ai_probe_port_stride_fetcher() {
        ig_md.bridged.probe_port_stride = rai_probe_port_stride.execute(0);
    }

    @stage(0)
    table ti_probe_port_stride_fetcher {
        actions = { ai_probe_port_stride_fetcher; }
        size = 1;
        const default_action = ai_probe_port_stride_fetcher();
    }

    // ---------- ti_probe_timer_setter ---------- //

    // Here we use a register to store the probe period configured by
    // control plane
    Register<bit<32>, _>(1) ri_probe_period;
    // The output of this RegisterAction is the needed latest timestamp of last
    // probe seed packet
    RegisterAction<_, _, bit<32>>(ri_probe_period) rai_timer_setter = {
        void apply(inout bit<32> value, out bit<32> output) {
            if (ig_intr_md.ingress_mac_tstamp[31:0] >= value) {
                output = ig_intr_md.ingress_mac_tstamp[31:0] - value;
            }
            else {
                // Here we use 0 to ensure this condition would not also cause
                // the predicate "value <= ig_md.last_probe_timer" to be true
                output = 0;
            }
        }
    };

    action ai_probe_timer_setter() {
        // Maybe more processing here
        ig_md.last_probe_timer = rai_timer_setter.execute(0);
    }

    @stage(0)
    table ti_probe_timer_setter {
        actions = { ai_probe_timer_setter; }
        size = 1;
        const default_action = ai_probe_timer_setter();
    }

    // ---------- ti_probe_resp_judger_p0 ---------- //

    Hash<bit<16>>(HashAlgorithm_t.CRC16) hi_dst_port;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hi_ack_no;

    // Part 1 of probe response judger
    action ai_probe_resp_judger_p0() {
#if __IP_TYPE__ == 6
        ig_md.probe_resp_port = hi_dst_port.get({ hdr.ipv6.next_hdr,
                                                  hdr.ipv6.dst_ip,
                                                  hdr.ipv6.src_ip });
#else // Default IPv4
        ig_md.probe_resp_port = hi_dst_port.get({ hdr.ipv4.protocol,
                                                  hdr.ipv4.dst_ip,
                                                  hdr.ipv4.src_ip });
#endif
    }

    @stage(0)
    table ti_probe_resp_judger_p0 {
        actions = { ai_probe_resp_judger_p0; }
        size = 1;
        const default_action = ai_probe_resp_judger_p0();
    }

    // ---------- ti_probe_resp_judger_p1 ---------- //

    // Part 2 of probe response judger
    action ai_probe_resp_judger_p1() {
#if __IP_TYPE__ == 6
        ig_md.probe_resp_ack = hi_ack_no.get({ hdr.ipv6.next_hdr,
                                               hdr.ipv6.dst_ip,
                                               hdr.ipv6.src_ip,
#else // Default IPv4
        ig_md.probe_resp_ack = hi_ack_no.get({ hdr.ipv4.protocol,
                                               hdr.ipv4.dst_ip,
                                               hdr.ipv4.src_ip,
#endif
                                               hdr.tcp.dst_port,
                                               hdr.tcp.src_port });
    }

    @stage(0)
    table ti_probe_resp_judger_p1 {
        actions = { ai_probe_resp_judger_p1; }
        size = 1;
        const default_action = ai_probe_resp_judger_p1();
    }

    // ------------------------------ Stage 1 ------------------------------- //

    // ---------- ti_flush_request_tagger ---------- //

    action ai_flush_request_tagger() {
        ig_md.bridged.pkt_label = PKT_LABEL_FLUSH_REQUEST;
    }

    @stage(1)
    table ti_flush_request_tagger {
        actions = { ai_flush_request_tagger; }
        size = 1;
        const default_action = ai_flush_request_tagger();
    }

    // ---------- ti_probe_generator ---------- //

    Register<bit<32>, _>(1) ri_last_probe_tstamp;
    RegisterAction<_, _, bit<8>>(ri_last_probe_tstamp) rai_probe_timer = {
        void apply(inout bit<32> value, out bit<8> output) {
            if ((value <= ig_md.last_probe_timer) ||
                (value > ig_intr_md.ingress_mac_tstamp[31:0])) {
                value = ig_intr_md.ingress_mac_tstamp[31:0];
                // Probe packets seed
                output = PKT_LABEL_SEED;
            }
            else {
                // Template packet
                output = PKT_LABEL_TEMPLATE;
            }
        }
    };

    action ai_probe_generator() {
        // Maybe more processing here
        ig_md.bridged.pkt_label = rai_probe_timer.execute(0);
    }

    @stage(1)
    table ti_probe_generator {
        actions = { ai_probe_generator; }
        size = 1;
        const default_action = ai_probe_generator();
    }

    // ---------- ti_probe_resp_judger_p2 ---------- //

    // Part 3 of probe response judger
    action ai_probe_resp_judger_p2() {
        ig_md.probe_resp_ack = ig_md.probe_resp_ack + 1;
    }

    @stage(1)
    table ti_probe_resp_judger_p2 {
        actions = { ai_probe_resp_judger_p2; }
        size = 1;
        const default_action = ai_probe_resp_judger_p2();
    }

    // ---------- ti_arp_request_tagger ---------- //

    action ai_arp_request_tagger() {
        ig_md.bridged.pkt_label = PKT_LABEL_ARP_REQUEST;
    }

    @stage(1)
    table ti_arp_request_tagger {
        actions = { ai_arp_request_tagger; }
        size = 1;
        const default_action = ai_arp_request_tagger();
    }

    // ------------------------------ Stage 2 ------------------------------- //

    // ---------- ti_probe_resp_inactive_tagger ---------- //

    action ai_probe_resp_inactive_tagger() {
        ig_md.bridged.pkt_label = PKT_LABEL_INACTIVE_RESP;
    }

    @stage(2)
    table ti_probe_resp_inactive_tagger {
        actions = { ai_probe_resp_inactive_tagger; }
        size = 1;
        const default_action = ai_probe_resp_inactive_tagger();
    }

    action ai_probe_resp_active_tagger() {
        ig_md.bridged.pkt_label = PKT_LABEL_ACTIVE_RESP;
    }

    // ---------- ti_probe_resp_active_tagger ---------- //

    @stage(2)
    table ti_probe_resp_active_tagger {
        actions = { ai_probe_resp_active_tagger; }
        size = 1;
        const default_action = ai_probe_resp_active_tagger();
    }

    // ---------- ti_resp_pkt_count_resetter & ti_resp_pkt_counter ---------- //

    Register<bit<8>, _>(1) ri_resp_pkt_count;

    // Read the current value and reset the response packet counter
    RegisterAction<_, _, bit<8>>(ri_resp_pkt_count)
                                rai_resp_pkt_count_resetter = {
        void apply(inout bit<8> value, out bit<8> output) {
            bit<8> in_value;
            in_value = value;
            output = in_value;
            value = 0;
        }
    };

    RegisterAction<_, _, bit<8>>(ri_resp_pkt_count) rai_resp_pkt_counter = {
        void apply(inout bit<8> value, out bit<8> output) {
            if (value == RESULT_DATABASE_SIZE_M1) {
                // Increase counter to  RESULT_DATABASE_SIZE, then overflow to 0
                bit<8> in_value;
                in_value = value;
                output = in_value;
                value = 0;
            }
            else {
                // Increase counter
                bit<8> in_value;
                in_value = value;
                output = in_value;
                value = in_value + 1;
            }
        }
    };

    action ai_resp_pkt_count_resetter() {
        ig_md.bridged.resp_pkt_count = rai_resp_pkt_count_resetter.execute(0);
    }

    action ai_resp_pkt_counter() {
        ig_md.bridged.resp_pkt_count = rai_resp_pkt_counter.execute(0);
    }

    @stage(2)
    table ti_resp_pkt_count_resetter {
        actions = { ai_resp_pkt_count_resetter; }
        size = 1;
        const default_action = ai_resp_pkt_count_resetter();
    }

    @stage(2)
    table ti_resp_pkt_counter {
        actions = { ai_resp_pkt_counter; }
        size = 1;
        const default_action = ai_resp_pkt_counter();
    }

    // ------------------------------ Stage 3 ------------------------------- //

    // ---------- ti_forward ---------- //

    action ai_nop() {
    }

    action ai_drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }

    action ai_unicast(port_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    action ai_broadcast() {
        ig_intr_tm_md.mcast_grp_a = BROADCAST_MC_GID;
    }

    @stage(3)
    table ti_forward {
        key = {
            hdr.ethernet.dst_mac : lpm;
        }
        actions = {
            ai_unicast;
            ai_broadcast;
            ai_drop;
        }
        size = 64;
        default_action = ai_drop;
    }

    // ---------- ti_probe_resp_inactive_handler ---------- //

    action ai_generate_probe_result() {
        ig_md.bridged.probe_result[31: 16] = hdr.tcp.src_port;
        ig_md.bridged.probe_result[7: 0] = ig_md.bridged.pkt_label;
    }

    action ai_send_back() {
        // Active ports require a RST to close the probed ports, and this packet
        // would be modified to the RST packet in egress.
        // Inactive port does need the reply packet any more, and this packet
        // would be dropped in egress.
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        ai_generate_probe_result();
    }

    action ai_report_to_result_server() {
        ig_intr_tm_md.ucast_egress_port = RESULT_SERVER_PORT;
        ai_generate_probe_result();
    }

    @stage(3)
    table ti_probe_resp_inactive_handler {
        key = {
            ig_md.bridged.resp_pkt_count: exact;
        }
        actions = {
            ai_send_back;
            ai_report_to_result_server;
        }
        size = 2;
        const default_action = ai_send_back();
    }

    // ---------- ti_probe_resp_active_handler ---------- //

    action ai_report_to_result_server_with_multicast() {
        ai_send_back();
        // Forward to CPU currently
        ig_intr_tm_md.mcast_grp_a = RESULT_SERVER_MC_GID;
    }

    @stage(3)
    table ti_probe_resp_active_handler {
        key = {
            ig_md.bridged.resp_pkt_count: exact;
        }
        actions = {
            ai_send_back;
            ai_report_to_result_server_with_multicast;
        }
        size = 2;
        const default_action = ai_send_back();
    }

    // ---------- ti_accelerator ---------- //

    action ai_accelerator() {
        // Maybe more processing here
        ig_intr_tm_md.ucast_egress_port = RECIRC_PORT;
    }

    @stage(3)
    table ti_accelerator {
        actions = { ai_accelerator; }
        size = 1;
        const default_action = ai_accelerator();
    }

    // ---------- ti_replicator ---------- //

    action ai_replicator() {
        // Maybe more processing here
        ig_intr_tm_md.ucast_egress_port = RECIRC_PORT;
        ig_intr_tm_md.mcast_grp_a = BROADCAST_MC_GID;
    }

    @stage(3)
    table ti_replicator {
        actions = { ai_replicator; }
        size = 1;
        const default_action = ai_replicator();
    }

    // ---------- ti_arp_request_handler ---------- //

    action ai_arp_request_handler() {
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        // We put the logic of reply into egress
    }

    @stage(3)
    table ti_arp_request_handler {
        actions = { ai_arp_request_handler; }
        size = 1;
        const default_action = ai_arp_request_handler();
    }

    // ---------- ti_flush_request_handler ---------- //

    action ai_flush_request_handler() {
        ig_intr_tm_md.ucast_egress_port = RESULT_SERVER_PORT;
    }

    @stage(3)
    table ti_flush_request_handler {
        actions = { ai_flush_request_handler; }
        size = 1;
        const default_action = ai_flush_request_handler();
    }

    // ---------------------- Ingress Processing Logic ---------------------- //

    apply {
        // ------ Determine the type of the packet ------ //
        if (ig_intr_md.ingress_port == CPU_PORT ||
            ig_intr_md.ingress_port == RECIRC_PORT) {
            if (hdr.ethernet.ether_type == ETHERTYPE_IFLUSH) {
                // Flush request packet from CPU
                ti_flush_request_tagger.apply();
                ti_resp_pkt_count_resetter.apply();
            }
            else {
                // Template packet
                ti_probe_port_stride_fetcher.apply();
                // Probe generator will generate probe packets seed from the
                // template packet and set the pkt_label
                ti_probe_timer_setter.apply();
                ti_probe_generator.apply();
            }
        }
        else if ((hdr.ipv4.dst_ip == PROBER_IP) &&
                 ((hdr.tcp.rst == 1 && hdr.tcp.ack == 1) ||
                  (hdr.tcp.syn == 1 && hdr.tcp.ack == 1))) {
            // Probe response packet judger: prepare the right hash result
            // Considering the dependency and resource constraints of Tofino,
            // we split the probe response packet judger into 3 parts.
            ti_probe_resp_judger_p0.apply();
            ti_probe_resp_judger_p1.apply();
            // Probe response packet checker
            if (hdr.tcp.dst_port == ig_md.probe_resp_port) {
                ti_probe_resp_judger_p2.apply();
                if (hdr.tcp.ack_no == ig_md.probe_resp_ack) {
                    // The is probe response packet!
                    if (hdr.tcp.rst == 1) {
                        ti_probe_resp_inactive_tagger.apply();
                    }
                    else if (hdr.tcp.syn == 1) {
                        ti_probe_resp_active_tagger.apply();
                    }
                    // Set count of response packet
                    ti_resp_pkt_counter.apply();
                }
            }
        }
        else if (hdr.arp_ipv4.isValid() &&
                 hdr.arp_ipv4.dst_proto_addr == PROBER_IP) {
            // ARP Request for PROBER_IP
            ti_arp_request_tagger.apply();
        }

        // ------ Process the packet according the packet type ------ //
        if (ig_md.bridged.pkt_label == PKT_LABEL_NORMAL) {
            // Normal packet
            ti_forward.apply();
        }
        else if (ig_md.bridged.pkt_label == PKT_LABEL_INACTIVE_RESP) {
            // Probe response packet (the target is inactive)
            ti_probe_resp_inactive_handler.apply();
        }
        else if (ig_md.bridged.pkt_label == PKT_LABEL_ACTIVE_RESP) {
            // Probe response packet (the target is active)
            ti_probe_resp_active_handler.apply();
        }
        else if (ig_md.bridged.pkt_label == PKT_LABEL_TEMPLATE) {
            // Template packet
            ti_accelerator.apply();
        }
        else if (ig_md.bridged.pkt_label == PKT_LABEL_SEED) {
            // Probe packets seed
            ti_replicator.apply();
        }
        else if (ig_md.bridged.pkt_label == PKT_LABEL_ARP_REQUEST) {
            // ARP request packet for the PROBER_IP
            ti_arp_request_handler.apply();
        }
        else if (ig_md.bridged.pkt_label == PKT_LABEL_FLUSH_REQUEST) {
            // Flush request packet from control plane
            ti_flush_request_handler.apply();
        }
    }
}


// -----------------------------------------------------------------------------
// Ingress deparser
// -----------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout custom_header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply {
        pkt.emit(ig_md.bridged); // Only Ingress
        pkt.emit(hdr);
    }
}


// -----------------------------------------------------------------------------
// Egress parser
// -----------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out custom_header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;
    ImapEgressParser() imap_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        imap_parser.apply(pkt, hdr, eg_md);
        transition accept;
    }
}


// -----------------------------------------------------------------------------
// Egress control flow
// -----------------------------------------------------------------------------
control SwitchEgress(
        inout custom_header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    // ------------------------------ Stage 0 ------------------------------- //

    // ---------- te_update_notifier ---------- //

    action ae_update_notifier() {
        hdr.ethernet.ether_type = ETHERTYPE_IREPORT;
        // Remove IP and TCP header from the packet
        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
        // Add update notification layer into the packet
        eg_md.update_notification.setValid();
        eg_md.update_notification.probe_table = eg_md.mirror.probe_table;
        eg_md.update_notification.pipr_idx = eg_md.mirror.pipr_idx;
        eg_md.update_notification.egress_port = eg_md.mirror.egress_port;
    }

    @stage(0)
    table te_update_notifier {
        actions = { ae_update_notifier; }
        size = 1;
        const default_action = ae_update_notifier();
    }

    // ----------  te_probe_table_switcher & te_editor_p0 ---------- //

    Register<bit<8>, _>(1) re_probe_table;

    RegisterAction<_, _, bit<8>>(re_probe_table) rae_probe_table_switcher = {
        void apply(inout bit<8> value, out bit<8> output) {
            value = 1 - value;
            output = value;
        }
    };

    RegisterAction<_, _, bit<8>>(re_probe_table) rae_probe_table_fetcher = {
        void apply(inout bit<8> value, out bit<8> output) {
            output = value;
        }
    };

    action ae_probe_table_switcher() {
        rae_probe_table_switcher.execute(0);
    }

    @stage(0)
    table te_probe_table_switcher {
        actions = { ae_probe_table_switcher; }
        size = 1;
        const default_action = ae_probe_table_switcher();
    }

    action ae_editor_p0() {
        // Get the probe table
        eg_md.probe_table = rae_probe_table_fetcher.execute(0);
    }

    @stage(0)
    table te_editor_p0 {
        actions = { ae_editor_p0; }
        size = 1;
        const default_action = ae_editor_p0();
    }

    // ---------- te_probe_port_updater & te_editor_p1 ---------- //

    // Here we use a register to store the probe port configured by
    // control plane
    Register<probe_port_t, _>(1) re_probe_port;

    RegisterAction<_, _, bit<16>>(re_probe_port) rae_probe_port_updater = {
        void apply(inout probe_port_t value, out bit<16> output) {
            if (value.pipr_switch_times == eg_md.mirror.probe_port_stride - 1) {
                // This is the probe_port_stride times of pipr switching
                value.pipr_switch_times = 0; // Reset to 0 for another round
                value.probe_port = value.probe_port + 1;
            }
            else {
                value.pipr_switch_times = value.pipr_switch_times + 1;
            }
        }
    };

    RegisterAction<_, _, bit<16>>(re_probe_port) rae_probe_port_fetcher = {
        void apply(inout probe_port_t value, out bit<16> output) {
            output = value.probe_port;
        }
    };

    action ae_probe_port_updater() {
        rae_probe_port_updater.execute(0);
    }

    @stage(0)
    table te_probe_port_updater {
        actions = { ae_probe_port_updater; }
        size = 1;
        const default_action = ae_probe_port_updater();
    }

    action ae_editor_p1(mac_addr_t dst_mac, ipr_idx_t pipr_sidx) {
        // Modify the dst address
        hdr.ethernet.dst_mac = dst_mac;
        // Set the target port to the probe port
        hdr.tcp.dst_port = rae_probe_port_fetcher.execute(0);
        // Set the probe ip range index to start index
        eg_md.pipr_idx = pipr_sidx;
    }

    action ae_drop() {
        eg_intr_dprsr_md.drop_ctl = 1;
    }

    @stage(0)
    table te_editor_p1 {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            ae_editor_p1;
            ae_drop;
        }
        size = 64;
        const default_action = ae_drop();
    }

    // ---------- te_arp_resp_responder ---------- //

    action ae_arp_resp_responder() {
        // Ether
        hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
        hdr.ethernet.src_mac = PROBER_MAC;
        // ARP
        hdr.arp.opcode = ARP_OPCODE_REPLY;
        hdr.arp_ipv4.dst_hw_addr = hdr.arp_ipv4.src_hw_addr;
        hdr.arp_ipv4.src_hw_addr = PROBER_MAC;
        hdr.arp_ipv4.dst_proto_addr = hdr.arp_ipv4.src_proto_addr;
        hdr.arp_ipv4.src_proto_addr = PROBER_IP;
    }

    @stage(0)
    table te_arp_resp_responder {
        actions = { ae_arp_resp_responder; }
        size = 1;
        const default_action = ae_arp_resp_responder();
    }

    // ---------- te_flushed_result_packer_p0 ---------- //

    action ae_result_packer() {
        hdr.ethernet.ether_type = ETHERTYPE_IRESULT;
        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
        eg_md.result.result_meta.setValid();
        eg_md.result.result_pack_0.setValid();
        eg_md.result.result_pack_1.setValid();
        eg_md.result.result_meta.resp_pkt_count = eg_md.bridged.resp_pkt_count;
    }

    action ae_flushed_result_packer() {
        ae_result_packer();
        // Use RESULT_DATABASE_SIZE as resp_pkt_count to avoid writing resultdb
        eg_md.bridged.resp_pkt_count = RESULT_DATABASE_SIZE;
    }

    @stage(0)
    table te_flushed_result_packer {
        actions = { ae_flushed_result_packer; }
        size = 1;
        const default_action = ae_flushed_result_packer();
    }

    // ---------- te_evicted_result_packer_p0 ---------- //

    action ae_evicted_result_packer_p0() {
        ae_result_packer();
    }

    @stage(0)
    table te_evicted_result_packer_p0 {
        actions = { ae_evicted_result_packer_p0; }
        size = 1;
        const default_action = ae_evicted_result_packer_p0();
    }

    // ------------------------------ Stage 1 ------------------------------- //

    // ---------- te_editor_p2_t0 ---------- //

    Register<ipr_idx_pidx_t, _>(IP_RANGE_TABLE_SIZE) re_pipr_t0_pidx;

    RegisterAction<_, _, ipr_idx_pidx_t>(re_pipr_t0_pidx) rae_pipr_t0_pidx = {
        void apply(inout ipr_idx_pidx_t value, out ipr_idx_pidx_t output) {
            if (value == (IP_RANGE_TABLE_SIZE - 1)) {
                // Increase counter to  max, then overflow to 0
                ipr_idx_pidx_t in_value;
                in_value = value;
                output = in_value;
                value = 0;
            }
            else {
                // Increase counter
                ipr_idx_pidx_t in_value;
                in_value = value;
                output = in_value;
                value = in_value + 1;
            }
        }
    };

    action ae_acquire_pipr_t0_pidx() {
        // Compute the real probe ip range index
#if IP_RANGE_INDEX_PORT_BITS == 0 // IP_RANGE_INDEX_PER_PORT_BITS = 16
        eg_md.pipr_idx[IP_RANGE_INDEX_PER_PORT_BITS - 1: 0] = \
            rae_pipr_t0_pidx.execute(0);
#else
        eg_md.pipr_idx[IP_RANGE_INDEX_PER_PORT_BITS - 1: 0] = \
            rae_pipr_t0_pidx.execute(eg_md.pipr_idx[IP_RANGE_INDEX_BITS - 1: \
                                                 IP_RANGE_INDEX_PER_PORT_BITS]);
#endif
    }

    @stage(1)
    table te_editor_p2_t0 {
        actions = { ae_acquire_pipr_t0_pidx; }
        size = 1;
        const default_action = ae_acquire_pipr_t0_pidx();
    }

    // ---------- te_editor_p2_t1 ---------- //

    Register<ipr_idx_pidx_t, _>(IP_RANGE_TABLE_SIZE) re_pipr_t1_pidx;

    RegisterAction<_, _, ipr_idx_pidx_t>(re_pipr_t1_pidx) rae_pipr_t1_pidx = {
        void apply(inout ipr_idx_pidx_t value, out ipr_idx_pidx_t output) {
            if (value == (IP_RANGE_TABLE_SIZE - 1)) {
                // Increase counter to  max, then overflow to 0
                ipr_idx_pidx_t in_value;
                in_value = value;
                output = in_value;
                value = 0;
            }
            else {
                // Increase counter
                ipr_idx_pidx_t in_value;
                in_value = value;
                output = in_value;
                value = in_value + 1;
            }
        }
    };

    action ae_acquire_pipr_t1_pidx() {
        // Compute the real probe ip range index
#if IP_RANGE_INDEX_PORT_BITS == 0 // IP_RANGE_INDEX_PER_PORT_BITS = 16
        eg_md.pipr_idx[IP_RANGE_INDEX_PER_PORT_BITS - 1: 0] = \
            rae_pipr_t1_pidx.execute(0);
#else
        eg_md.pipr_idx[IP_RANGE_INDEX_PER_PORT_BITS - 1: 0] = \
            rae_pipr_t1_pidx.execute(eg_md.pipr_idx[IP_RANGE_INDEX_BITS - 1: \
                                                 IP_RANGE_INDEX_PER_PORT_BITS]);
#endif
    }

    @stage(1)
    table te_editor_p2_t1 {
        actions = { ae_acquire_pipr_t1_pidx; }
        size = 1;
        const default_action = ae_acquire_pipr_t1_pidx();
    }

    action ae_evicted_result_packer_p1() {
        eg_md.result.result_meta.resp_pkt_count = \
                                    eg_md.result.result_meta.resp_pkt_count + 1;
    }

    @stage(1)
    table te_evicted_result_packer_p1 {
        actions = { ae_evicted_result_packer_p1; }
        size = 1;
        const default_action = ae_evicted_result_packer_p1();
    }

    // ------------------------------ Stage 2 ------------------------------- //

    // ---------- te_editor_p3_t0 ---------- //

    // Probe IP Range (pipr) end part
    Register<bit<32>, _>(IP_RANGE_TABLE_SIZE) re_pipr_t0_end;

    RegisterAction<_, _, bit<32>>(re_pipr_t0_end) rae_pipr_t0_end = {
        void apply(inout bit<32> value, out bit<32> output) {
            output = value;
        }
    };

    action ae_acquire_pipr_t0_end() {
        // Get the end ip in the corresponding probe ip range
        eg_md.pipr_end = rae_pipr_t0_end.execute(eg_md.pipr_idx);
    }

    @stage(2)
    table te_editor_p3_t0 {
        actions = { ae_acquire_pipr_t0_end; }
        size = 1;
        const default_action = ae_acquire_pipr_t0_end();
    }

    // ---------- te_editor_p3_t1 ---------- //

    // Probe IP Range (pipr) end part
    Register<bit<32>, _>(IP_RANGE_TABLE_SIZE) re_pipr_t1_end;

    RegisterAction<_, _, bit<32>>(re_pipr_t1_end) rae_pipr_t1_end = {
        void apply(inout bit<32> value, out bit<32> output) {
            output = value;
        }
    };

    action ae_acquire_pipr_t1_end() {
        // Get the end ip in the corresponding probe ip range
        eg_md.pipr_end = rae_pipr_t1_end.execute(eg_md.pipr_idx);
    }

    @stage(2)
    table te_editor_p3_t1 {
        actions = { ae_acquire_pipr_t1_end; }
        size = 1;
        const default_action = ae_acquire_pipr_t1_end();
    }

    // Next table are not allocated the correct stage now

#if __IP_TYPE__ == 6
    // ---------- te_editor_p3_e1 ---------- //

    Register<bit<32>, _>(IP_RANGE_TABLE_SIZE) re_pip_prefix_1;

    RegisterAction<_, _, bit<32>>(re_pip_prefix_1) rae_pip_prefix_1 = {
        void apply(inout bit<32> value, out bit<32> output) {
            output = value;
        }
    };

    action ae_editor_p3_e1() {
        hdr.ipv6.dst_ip[127:96] = rae_pip_prefix_1.execute(eg_md.pipr_idx);
    }

    table te_editor_p3_e1 {
        actions = { ae_editor_p3_e1; }
        size = 1;
        const default_action = ae_editor_p3_e1();
    }

    // ---------- te_editor_p3_e2 ---------- //

    Register<bit<32>, _>(IP_RANGE_TABLE_SIZE) re_pip_prefix_3;

    RegisterAction<_, _, bit<32>>(re_pip_prefix_2) rae_pip_prefix_2 = {
        void apply(inout bit<32> value, out bit<32> output) {
            output = value;
        }
    };

    action ae_editor_p3_e2() {
        hdr.ipv6.dst_ip[95:64] = rae_pip_prefix_2.execute(eg_md.pipr_idx);
    }

    table te_editor_p3_e2 {
        actions = { ae_editor_p3_e2; }
        size = 1;
        const default_action = ae_editor_p3_e2();
    }

    // ---------- te_editor_p3_e3 ---------- //

    Register<bit<32>, _>(IP_RANGE_TABLE_SIZE) re_pip_prefix_2;

    RegisterAction<_, _, bit<32>>(re_pip_prefix_3) rae_pip_prefix_3 = {
        void apply(inout bit<32> value, out bit<32> output) {
            output = value;
        }
    };

    action ae_editor_p3_e3() {
        hdr.ipv6.dst_ip[63:32] = rae_pip_prefix_3.execute(eg_md.pipr_idx);
    }

    table te_editor_p3_e3 {
        actions = { ae_editor_p3_e3; }
        size = 1;
        const default_action = ae_editor_p3_e3();
    }
#endif

    // ------------------------------ Stage 3 ------------------------------- //

    // ---------- te_editor_p4_t0 ---------- //

    // Probe IP Range (pipr) start part
    Register<bit<32>, _>(IP_RANGE_TABLE_SIZE) re_pipr_t0_start;

    RegisterAction<_, _, bit<32>>(re_pipr_t0_start) rae_pipr_t0_start = {
        void apply(inout bit<32> value, out bit<32> output) {
            // Notice here, it determine the probe IP range is [start, end].
            // With this setting, 255.255.255.255 will nerver be probed.
            if (value <= eg_md.pipr_end) {
                bit<32> in_value;
                in_value = value;
                output = in_value;
                value = value + 1;
            }
            else {
                output = 0;
            }
        }
    };

    action ae_acquire_pipr_t0_start() {
        // Get the next probe ip in the corresponding probe ip range
#if __IP_TYPE__ == 6
        hdr.ipv6.dst_ip[31:0] = rae_pipr_t0_start.execute(eg_md.pipr_idx);
#else // Default IPv4
        hdr.ipv4.dst_ip = rae_pipr_t0_start.execute(eg_md.pipr_idx);
#endif
    }

    @stage(3)
    table te_editor_p4_t0 {
        actions = { ae_acquire_pipr_t0_start; }
        size = 1;
        const default_action = ae_acquire_pipr_t0_start();
    }

    // ---------- te_editor_p4_t1 ---------- //

    Register<bit<32>, _>(IP_RANGE_TABLE_SIZE) re_pipr_t1_start;

    RegisterAction<_, _, bit<32>>(re_pipr_t1_start) rae_pipr_t1_start = {
        void apply(inout bit<32> value, out bit<32> output) {
            // Notice here, it determine the probe IP range is [start, end].
            // With this setting, 255.255.255.255 will nerver be probed.
            if (value <= eg_md.pipr_end) {
                bit<32> in_value;
                in_value = value;
                output = in_value;
                value = value + 1;
            }
            else {
                output = 0;
            }
        }
    };

    action ae_acquire_pipr_t1_start() {
        // Get the next probe ip in the corresponding probe ip range
#if __IP_TYPE__ == 6
        hdr.ipv6.dst_ip[31:0] = rae_pipr_t1_start.execute(eg_md.pipr_idx);
#else // Default IPv4
        hdr.ipv4.dst_ip = rae_pipr_t1_start.execute(eg_md.pipr_idx);
#endif
    }

    @stage(3)
    table te_editor_p4_t1 {
        actions = { ae_acquire_pipr_t1_start; }
        size = 1;
        const default_action = ae_acquire_pipr_t1_start();
    }

    // ------------------------------ Stage 4 ------------------------------- //

    // ---------- te_editor_p5 ---------- //

    Hash<bit<16>>(HashAlgorithm_t.CRC16) he_src_port;

    action ae_editor_p5() {
        // Set the 1st "secret"
#if __IP_TYPE__ == 6
        hdr.tcp.src_port = he_src_port.get({ hdr.ipv6.next_hdr,
                                             hdr.ipv6.src_ip,
                                             hdr.ipv6.dst_ip });
#else // Default IPv4
        hdr.tcp.src_port = he_src_port.get({ hdr.ipv4.protocol,
                                             hdr.ipv4.src_ip,
                                             hdr.ipv4.dst_ip });
#endif
    }

    @stage(4)
    table te_editor_p5 {
        actions = { ae_editor_p5; }
        size = 1;
        const default_action = ae_editor_p5();
    }

    // ------------------------------ Stage 5 ------------------------------- //

    // ---------- te_editor_p6 ---------- //

    Hash<bit<32>>(HashAlgorithm_t.CRC32) he_seq_no;

    action ae_editor_p6() {
        // Set the 2nd "secret"
#if __IP_TYPE__ == 6
        hdr.tcp.seq_no = he_seq_no.get({ hdr.ipv6.next_hdr,
                                         hdr.ipv6.src_ip,
                                         hdr.ipv6.dst_ip,
#else // Default IPv4
        hdr.tcp.seq_no = he_seq_no.get({ hdr.ipv4.protocol,
                                         hdr.ipv4.src_ip,
                                         hdr.ipv4.dst_ip,
#endif
                                         hdr.tcp.src_port,
                                         hdr.tcp.dst_port });
    }

    @stage(5)
    table te_editor_p6 {
        actions = { ae_editor_p6; }
        size = 1;
        const default_action = ae_editor_p6();
    }

    // ------------------------------ Stage 6 ------------------------------- //

    // ---------- te_cpu_mirrorer ---------- //

    action ae_cpu_mirrorer() {
        // Set mirror metadata
        eg_md.update_notification_mirror_sid = UPDATE_NOTIFY_MIRROR_SID;
        eg_md.mirror.pkt_label = PKT_LABEL_UPDATE_NOTIFY;
        eg_md.mirror.probe_table = eg_md.probe_table;
        eg_md.mirror.pipr_idx = eg_md.pipr_idx;
        eg_md.mirror._pad = 0;
        eg_md.mirror.egress_port = eg_intr_md.egress_port;
        eg_md.mirror.probe_port_stride = eg_md.bridged.probe_port_stride;
        // Set mirroring and drop the original packet
        eg_intr_dprsr_md.mirror_type = MIRROR_TYPE_E2E;
        // eg_intr_dprsr_md.drop_ctl = 1;
    }

    @stage(6) // Actually, te_cpu_mirror can be put into stage 4
    table te_cpu_mirrorer {
        actions = { ae_cpu_mirrorer; }
        size = 1;
        const default_action = ae_cpu_mirrorer();
    }

    // ------------------------------ Stage 10 ------------------------------ //

    // ---------- te_rst_responder ---------- //

    action ae_rst_responder() {
        // Swap the mac address
        hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
        hdr.ethernet.dst_mac = eg_md.swp_mac;
        // Swap the ip address
#if __IP_TYPE__ == 6
        hdr.ipv6.src_ip = hdr.ipv6.dst_ip;
        hdr.ipv6.dst_ip = eg_md.swp_ip;
#else // Default IPv4
        hdr.ipv4.src_ip = hdr.ipv4.dst_ip;
        hdr.ipv4.dst_ip = eg_md.swp_ip;
#endif
        // Swap the tcp port
        hdr.tcp.src_port = hdr.tcp.dst_port;
        hdr.tcp.dst_port = eg_md.swp_port;
        // Set seq_no and ack_no
        hdr.tcp.seq_no = hdr.tcp.ack_no;
        hdr.tcp.ack_no = eg_md.tmp_seq + 1;
        // Set TCP flags
        hdr.tcp.syn = 0;
        hdr.tcp.rst = 1;
    }

    @stage(10)
    table te_rst_responder {
        actions = { ae_rst_responder; }
        size = 1;
        const default_action = ae_rst_responder();
    }

    // ---------- te_drop ---------- //

    @stage(10)
    table te_drop {
        actions = { ae_drop; }
        size = 1;
        const default_action = ae_drop();
    }

    // ------------------------ Cross Stages (1-10) ------------------------- //

#define RESULT_DATABASE(db_idx, pack_idx, entry_idx, t_stage, r_stage)         \
    Register<bit<32>,_>(1) re_resultdb_##db_idx##_target;                      \
                                                                               \
    RegisterAction<_, _, bit<32>>(re_resultdb_##db_idx##_target)               \
                                 rae_load_resultdb_##db_idx##_target = {       \
        void apply(inout bit<32> value, out bit<32> output) {                  \
            output = value;                                                    \
        }                                                                      \
    };                                                                         \
                                                                               \
    RegisterAction<_, _, bit<32>>(re_resultdb_##db_idx##_target)               \
                                 rae_update_resultdb_##db_idx##_target = {     \
        void apply(inout bit<32> value, out bit<32> output) {                  \
            value = hdr.ipv4.src_ip;                                           \
            output = value;                                                    \
        }                                                                      \
    };                                                                         \
                                                                               \
    action ae_load_resultdb_##db_idx##_target() {                              \
        eg_md.result.result_pack_##pack_idx##.target_##entry_idx## =           \
                            rae_load_resultdb_##db_idx##_target.execute(0);    \
    }                                                                          \
                                                                               \
    action ae_update_resultdb_##db_idx##_target() {                            \
        eg_md.result.result_pack_##pack_idx##.target_##entry_idx## =           \
                            rae_update_resultdb_##db_idx##_target.execute(0);  \
    }                                                                          \
                                                                               \
    @stage(##t_stage##)                                                        \
    table te_resultdb_##db_idx##_target_accessor {                             \
        key = {                                                                \
            eg_md.bridged.resp_pkt_count : exact;                              \
        }                                                                      \
        actions = {                                                            \
            ae_load_resultdb_##db_idx##_target;                                \
            ae_update_resultdb_##db_idx##_target;                              \
        }                                                                      \
        size = 2;                                                              \
        const default_action = ae_load_resultdb_##db_idx##_target();           \
    }                                                                          \
                                                                               \
    Register<bit<32>,_>(1) re_resultdb_##db_idx##_result;                      \
                                                                               \
    RegisterAction<_, _, bit<32>>(re_resultdb_##db_idx##_result)               \
                                 rae_load_resultdb_##db_idx##_result  = {      \
        void apply(inout bit<32> value, out bit<32> output) {                  \
            output = value;                                                    \
        }                                                                      \
    };                                                                         \
                                                                               \
    RegisterAction<_, _, bit<32>>(re_resultdb_##db_idx##_result)               \
                                 rae_update_resultdb_##db_idx##_result  = {    \
        void apply(inout bit<32> value, out bit<32> output) {                  \
            value = eg_md.bridged.probe_result;                                \
            output = value;                                                    \
        }                                                                      \
    };                                                                         \
                                                                               \
    action ae_load_resultdb_##db_idx##_result() {                              \
        eg_md.result.result_pack_##pack_idx##.result_##entry_idx## =           \
                            rae_load_resultdb_##db_idx##_result.execute(0);    \
    }                                                                          \
                                                                               \
    action ae_update_resultdb_##db_idx##_result() {                            \
        eg_md.result.result_pack_##pack_idx##.result_##entry_idx## =           \
                            rae_update_resultdb_##db_idx##_result.execute(0);  \
    }                                                                          \
                                                                               \
    @stage(##r_stage##)                                                        \
    table te_resultdb_##db_idx##_result_accessor {                             \
        key = {                                                                \
            eg_md.bridged.resp_pkt_count : exact;                              \
        }                                                                      \
        actions = {                                                            \
            ae_load_resultdb_##db_idx##_result;                                \
            ae_update_resultdb_##db_idx##_result;                              \
        }                                                                      \
        size = 2;                                                              \
        const default_action = ae_load_resultdb_##db_idx##_result();           \
    }                                                                          \

    RESULT_DATABASE(0, 0, 0, 1, 2)
    RESULT_DATABASE(1, 0, 1, 3, 3)
    RESULT_DATABASE(2, 0, 2, 4, 4)
    RESULT_DATABASE(3, 0, 3, 4, 4)
    RESULT_DATABASE(4, 0, 4, 5, 5)
    RESULT_DATABASE(5, 0, 5, 5, 5)
    RESULT_DATABASE(6, 0, 6, 6, 6)
    RESULT_DATABASE(7, 0, 7, 6, 6)
    RESULT_DATABASE(8, 1, 0, 7, 7)
    RESULT_DATABASE(9, 1, 1, 7, 7)
    RESULT_DATABASE(10, 1, 2, 8, 8)
    RESULT_DATABASE(11, 1, 3, 8, 8)
    RESULT_DATABASE(12, 1, 4, 9, 9)
    RESULT_DATABASE(13, 1, 5, 9, 9)
    RESULT_DATABASE(14, 1, 6, 10, 10)
    RESULT_DATABASE(15, 1, 7, 10, 10)

    // ---------------------- Egress Processing Logic ----------------------- //

    apply {
        // Note: Here we do not use pkt_label directly to distinguish egress
        // packets. Because probe packets seed in the ingress would output not
        // only the template packet but also probe packets, and all of them
        // are labeled with 2. Similarly, active probe response packet also
        // output two packets to egress.
        if (eg_intr_md.egress_port == RECIRC_PORT) {
            // Template packet (To RECIRC_PORT)
            // (all packets with label 1 and partial packets with label 2)
        }
        else if (eg_md.mirror.isValid()) {
            // Mirrored packet to be sent to CPU
            te_update_notifier.apply();
            te_probe_table_switcher.apply();
            te_probe_port_updater.apply();
        }
        else if (eg_md.bridged.pkt_label == PKT_LABEL_SEED) {
            // Probe packet
            // Note: Here we separate the editor to avoid compiling error
            // caused by two hashes in the same action or two register actions
            // in the same action.
            te_editor_p0.apply();
            te_editor_p1.apply();
            if (eg_md.probe_table == 0) {
                te_editor_p2_t0.apply();
                te_editor_p3_t0.apply();
                te_editor_p4_t0.apply();
            }
            else {
                te_editor_p2_t1.apply();
                te_editor_p3_t1.apply();
                te_editor_p4_t1.apply();
            }
#if __IP_TYPE__ == 6
            te_editor_p3_e1.apply();
            te_editor_p3_e2.apply();
            te_editor_p3_e3.apply();
#endif
            te_editor_p5.apply();
            te_editor_p6.apply();
#if __IP_TYPE__ == 6
            if (hdr.ipv6.dst_ip[31:0] == eg_md.pipr_end) {
#else // Default IPv4
            if (hdr.ipv4.dst_ip == eg_md.pipr_end)  {
#endif
                // The probe IP range has been all probed
                if (eg_md.pipr_idx == (IP_RANGE_TABLE_SIZE - 1)) {
                    te_cpu_mirrorer.apply();
                }
            }
            // There may be multiple conditions where ipv4.dst_ip == 0:
            // 1. This probe ip range has been probed
            // 2. This probe ip range is not installed (0.0.0.0 to 0.0.0.0)
            if (hdr.ipv4.dst_ip == 0) {
                te_drop.apply();
            }
        }
        else if (eg_md.bridged.pkt_label == PKT_LABEL_ARP_REQUEST) {
            te_arp_resp_responder.apply();
        }
        else if (eg_md.bridged.pkt_label == PKT_LABEL_INACTIVE_RESP ||
                 eg_md.bridged.pkt_label == PKT_LABEL_ACTIVE_RESP ||
                 eg_md.bridged.pkt_label == PKT_LABEL_FLUSH_REQUEST) {
            // Process the packet
            if (eg_intr_md.egress_port == RESULT_SERVER_PORT) {
                // Report packet (To RESULT_SERVER_PORT)
                if (eg_md.bridged.pkt_label == PKT_LABEL_FLUSH_REQUEST) {
                    te_flushed_result_packer.apply();
                }
                else { // pkt_label == PKT_LABEL_(IN)ACTIVE_RESP 
                    // Make resp_pkt_count to be "count" instead of "index"
                    te_evicted_result_packer_p0.apply();
                    te_evicted_result_packer_p1.apply();
                }
            }
            // Load or update the result database
            te_resultdb_0_target_accessor.apply();
            te_resultdb_0_result_accessor.apply();
            te_resultdb_1_target_accessor.apply();
            te_resultdb_1_result_accessor.apply();
            te_resultdb_2_target_accessor.apply();
            te_resultdb_2_result_accessor.apply();
            te_resultdb_3_target_accessor.apply();
            te_resultdb_3_result_accessor.apply();
            te_resultdb_4_target_accessor.apply();
            te_resultdb_4_result_accessor.apply();
            te_resultdb_5_target_accessor.apply();
            te_resultdb_5_result_accessor.apply();
            te_resultdb_6_target_accessor.apply();
            te_resultdb_6_result_accessor.apply();
            te_resultdb_7_target_accessor.apply();
            te_resultdb_7_result_accessor.apply();
            te_resultdb_8_target_accessor.apply();
            te_resultdb_8_result_accessor.apply();
            te_resultdb_9_target_accessor.apply();
            te_resultdb_9_result_accessor.apply();
            te_resultdb_10_target_accessor.apply();
            te_resultdb_10_result_accessor.apply();
            te_resultdb_11_target_accessor.apply();
            te_resultdb_11_result_accessor.apply();
            te_resultdb_12_target_accessor.apply();
            te_resultdb_12_result_accessor.apply();
            te_resultdb_13_target_accessor.apply();
            te_resultdb_13_result_accessor.apply();
            te_resultdb_14_target_accessor.apply();
            te_resultdb_14_result_accessor.apply();
            te_resultdb_15_target_accessor.apply();
            te_resultdb_15_result_accessor.apply();

            if (eg_intr_md.egress_port != RESULT_SERVER_PORT) {
                if (eg_md.bridged.pkt_label == PKT_LABEL_ACTIVE_RESP) {
                    // Probe response packet (active)
                    te_rst_responder.apply();
                }
                else {
                    // Probe response packet (inactive)
                    // Drop the packet when the packet enters egress MAC
                    te_drop.apply();
                }
            }
        }
    }
}


// -----------------------------------------------------------------------------
// Egress deparser
// -----------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout custom_header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {

    Checksum() ipv4_csum;
    // IPv6 does not have checksum field
    Checksum() tcp_csum;
    Mirror() mirror;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_csum.update({
            hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
            hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags,
            hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol,
            // Skip hdr.ipv4.hdr_checksum,
            hdr.ipv4.src_ip, hdr.ipv4.dst_ip
        });
        hdr.tcp.checksum = tcp_csum.update({
#if __IP_TYPE__ == 6
            hdr.ipv6.src_ip, hdr.ipv6.dst_ip,
#endif
            hdr.ipv4.src_ip, hdr.ipv4.dst_ip,
            hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no, hdr.tcp.ack_no,
            hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.urg, hdr.tcp.ack,
            hdr.tcp.psh, hdr.tcp.rst, hdr.tcp.syn, hdr.tcp.fin,
            eg_md.checksum
        });
        if (eg_intr_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_h>(
                eg_md.update_notification_mirror_sid, eg_md.mirror
            );
        }
        pkt.emit(hdr);
        pkt.emit(eg_md.result);
        pkt.emit(eg_md.update_notification);
    }
}


// -----------------------------------------------------------------------------
// Assemble pipeline and switch
// -----------------------------------------------------------------------------
Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;
