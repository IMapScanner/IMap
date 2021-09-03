/*************************************************************************
	> File Name: ichannel.c
	> Author: Guanyu Li
	> Mail: dracula.guanyu.li@gmail.com
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Program about probe modules of IMap
 ************************************************************************/

#ifndef _ICHANNEL_H
#define _ICHANNEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <time.h>

#define MAC_ARRAY(d, i) ((d >> ((5 - i) * 8)) & 0xff)
#define IPV6_ARRAY(d, i) ((d >> ((3 - i)* 8)) & 0xff)

typedef uint32_t ipaddr_n_t; // IPv4 address network order
typedef uint32_t ipaddr_h_t; // IPv4 address host order
typedef uint16_t port_n_t;   // TCP/UDP port network order
typedef uint16_t port_h_t;   // TCP/UDP port host order

// Pseudo header needed for checksum calculation
struct psdhdr {
	ipaddr_h_t saddr;
	ipaddr_h_t daddr;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
	struct tcphdr tcp;
};

struct psdv6hdr {
	struct in6_addr saddr;
	struct in6_addr daddr;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
	struct tcphdr tcp;
};

typedef struct update_notifying_channel_s {
	int sockfd;
	char recvbuf[PKTBUF_SIZE];
    uint8_t  probe_table;
    uint16_t pipr_idx;
    uint16_t egress_port;
} update_notifying_channel_t;

#if __TOFINO_MODE__ == 0
// static const char CPUIF_NAME[] = "bf_pci0";
static const char CPUIF_NAME[] = "enp4s0";
#else
static const char CPUIF_NAME[] = "veth251";
#endif

static unsigned short csum(unsigned short *ptr,int nbytes);
int send_ipv6_syn_temp_to_switch();
int recv_ipv6_probe_report_from_switch();
int send_syn_temp_to_switch();
int send_icmp_temp_to_switch();
int recv_probe_report_from_switch();
int creat_update_notifying_channel(update_notifying_channel_t *channel);
int recv_update_notification(update_notifying_channel_t *channel);
int recv_update_notification_from_switch(uint32_t timer, uint8_t *pipr_filter);
int send_flush_request_to_switch();

#endif
