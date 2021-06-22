/*************************************************************************
	> File Name: imap.h
	> Author: Guanyu Li
	> Mail: dracula.guanyu.li@gmail.com
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Config and macro definition file for IMap
 ************************************************************************/

#ifndef _ICONFIG_H
#define _ICONFIG_H

#define __IP_TYPE__ 4
#define __TOFINO_MODE__ 0 // 0: ASIC 1: Model

#define ETHER_TYPE_IRESULT 0x6666
#define ETHER_TYPE_IREPORT 0x6668
#define ETHER_TYPE_IFLUSH  0x6688

#define PROBE_RESULT_NO_RESP       0b00
#define PROBE_RESULT_INACTIVE_RESP 0b01
#define PROBE_RESULT_ACTIVE_RESP   0b10

#define RESULT_PACKS_PER_PACKET 2
#define RESULTS_PER_RESULT_PACK 8

#define RESULT_ENTRY_BUF_SIZE (1 << 20)

// Probe IP Range Index: Port Index + Per Port Index
#define IP_RANGE_INDEX_BITS 16
// Set IP_RANGE_INDEX_PORT_BITS = 0 is just for single-switch-port scanning
#define IP_RANGE_INDEX_PORT_BITS 0
#define IP_RANGE_INDEX_PER_PORT_BITS \
        (IP_RANGE_INDEX_BITS - IP_RANGE_INDEX_PORT_BITS)

#define IP_RANGE_MAX_SIZE 256

#define IP_RANGE_TABLE_SIZE (1 << IP_RANGE_INDEX_BITS)

#define IP_PLACEHOLDER 0

// Only for data plane
#if __TOFINO_MODE__ == 0
#define CPU_PORT 192
#define RESULT_SERVER_PORT 144
#else
#define CPU_PORT 64
#define RESULT_SERVER_PORT 3
#endif

#define RECIRC_PORT 196
#define BROADCAST_MC_GID 255
#define RESULT_SERVER_MC_GID 192
#define UPDATE_NOTIFY_MIRROR_SID 66
#define PKTBUF_SIZE 2048

// #define RESULT_DATABASE_SIZE    (RESULT_PACKS_PER_PACKET * RESULTS_PER_RESULT_PACK)
// #define RESULT_DATABASE_SIZE_M1 (RESULT_DATABASE_SIZE - 1)
#define RESULT_DATABASE_SIZE    16
#define RESULT_DATABASE_SIZE_M1 15

#if __IP_TYPE__ == 6
#define PROBER_IPV6_P1 0xfe800000
#define PROBER_IPV6_P2 0xfe800000
#define PROBER_IPV6_P3 0x6a91d0ff
#define PROBER_IPV6_P4 0xfe123456
#else
// #define PROBER_IP 0xc0a82801
#define PROBER_IP 0xc0a82888
#endif

// #define PROBER_MAC 0x123456789abc
#define PROBER_MAC 0x6891d0611258

// Only for control plane
#define PRIME_ROOT 3
#define RANDOM_PICKER_SIZE (1 << 16)
#define SLEEP_TIME_FOR_IDLE_CHANNEL 5

// Only for result server
#define MAX_PKT_BURST 10
#define CHANNEL_MAX_LATENCY 500000000 //ns

#endif
