/*************************************************************************
	> File Name: ichannel.c
	> Author:
	> Mail:
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Program about probe modules of IMap
 ************************************************************************/

#include "../iconfig.h"
#include "ichannel.h"

#if __IP_TYPE__ == 6
int send_ipv6_syn_temp_to_switch() {
	int sockfd;
	struct ifreq cpuif_req;
	int tx_len = 0;
	char sendbuf[PKTBUF_SIZE];
	struct ethhdr *eth_h = (struct ethhdr *)sendbuf;
    struct ipv6hdr *ipv6_h = (struct ipv6hdr *)
                             ((char *)eth_h + sizeof(struct ethhdr));
    struct tcphdr *tcp_h = (struct tcphdr *)
                           ((char *)ipv6_h + sizeof(struct ipv6hdr));
    struct psdv6hdr psd_h;
    struct sockaddr_ll sock_addr;
	char cpuif_name[IFNAMSIZ];
	
	/* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    /* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
        return -1;
	}

	/* Get the index of the interface to send on */
	memset(&cpuif_req, 0, sizeof(struct ifreq));
	strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &cpuif_req) < 0) {
	    perror("SIOCGIFINDEX");
		close(sockfd);
        return -1;
    }

	/* Construct the Ethernet header */
	memset(sendbuf, 0, PKTBUF_SIZE);
	/* Ethernet header */
    for (unsigned int idx = 0; idx < 6; idx++) {
        eth_h->h_source[idx] = MAC_ARRAY(PROBER_MAC, idx);
    }
    eth_h->h_proto = htons(ETH_P_IPV6);
	tx_len += sizeof(struct ethhdr);

	/* IP header */
    ipv6_h->version = 6;
    ipv6_h->priority = 0;
    ipv6_h->flow_lbl[0] = 0;
    ipv6_h->flow_lbl[1] = 0;
    ipv6_h->flow_lbl[2] = 0;
    ipv6_h->payload_len = htons(sizeof(struct tcphdr));
    ipv6_h->nexthdr = IPPROTO_TCP;
    ipv6_h->hop_limit = 128;
    for (unsigned int idx = 0; idx < 4; idx++) {
        ipv6_h->saddr.__in6_u.__u6_addr8[idx + 0] = \
                                            IPV6_ARRAY(PROBER_IPV6_P1, idx);
    }
    for (unsigned int idx = 0; idx < 4; idx++) {
        ipv6_h->saddr.__in6_u.__u6_addr8[idx + 4] = \
                                            IPV6_ARRAY(PROBER_IPV6_P2, idx);
    }
    for (unsigned int idx = 0; idx < 4; idx++) {
        ipv6_h->saddr.__in6_u.__u6_addr8[idx + 8] = \
                                            IPV6_ARRAY(PROBER_IPV6_P3, idx);
    }
    for (unsigned int idx = 0; idx < 4; idx++) {
        ipv6_h->saddr.__in6_u.__u6_addr8[idx + 12] = \
                                            IPV6_ARRAY(PROBER_IPV6_P4, idx);
    }

	tx_len += sizeof(struct ipv6hdr);

	/* TCP header */
    tcp_h->seq = htonl(123456789);
    tcp_h->ack_seq = htonl(0);
    tcp_h->doff = sizeof(struct tcphdr) / 4;
    tcp_h->fin=0;
    tcp_h->syn=1;
    tcp_h->rst=0;
    tcp_h->psh=0;
    tcp_h->ack=0;
    tcp_h->urg=0;
    tcp_h->window = htons(1024);
    tcp_h->check = 0;
    tcp_h->urg_ptr = 0;
	tx_len += sizeof(struct tcphdr);

    // TCP Checksum
    psd_h.saddr = ipv6_h->saddr;
    psd_h.daddr = ipv6_h->daddr;
    psd_h.placeholder = 0;
    psd_h.protocol = ipv6_h->nexthdr;
    psd_h.tcp_length =
        htons(tx_len - sizeof(struct ethhdr) - sizeof(struct ipv6hdr));
    memcpy(&psd_h.tcp , tcp_h , sizeof (struct tcphdr));
    tcp_h->check = csum((uint16_t *)&psd_h, sizeof(struct psdv6hdr));

	/* Packet data */
	// sendbuf[tx_len++] = 0xde;
	// sendbuf[tx_len++] = 0xad;
	// sendbuf[tx_len++] = 0xbe;
	// sendbuf[tx_len++] = 0xef;

	/* Index of the network device */
	sock_addr.sll_ifindex = cpuif_req.ifr_ifindex;
	/* Address length*/
	sock_addr.sll_halen = ETH_ALEN;
	/* Destination MAC */
	// sock_addr.sll_addr[0] = 0;
	// sock_addr.sll_addr[1] = 0;
	// sock_addr.sll_addr[2] = 0;
	// sock_addr.sll_addr[3] = 0;
	// sock_addr.sll_addr[4] = 0;
	// sock_addr.sll_addr[5] = 0;

	/* Send packet */
    if (sendto(sockfd, sendbuf, tx_len, 0,
               (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_ll)) < 0) {
        printf("Send failed\n");
    }

	return 0;
}

int recv_ipv6_probe_report_from_switch() {
	int sockfd;
	struct ifreq cpuif_req;
	int rx_len = 0;
	char recvbuf[PKTBUF_SIZE];
	struct sockaddr_ll sock_addr;
    int sock_addrlen = sizeof(sock_addr);
	char cpuif_name[IFNAMSIZ];
	
	/* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    /* Header structures */
	struct ethhdr *eth_h = (struct ethhdr *)recvbuf;
    struct ipv6hdr *ipv6_h = (struct ipv6hdr *)
                             ((char *)eth_h + sizeof(struct ethhdr));
    struct tcphdr *tcp_h = (struct tcphdr *)
                           ((char *)ipv6_h + sizeof(struct ipv6hdr));

    /* Open RAW socket to send on */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6))) == -1) {
	    perror("socket");
        return -1;
	}

    memset(&cpuif_req, 0, sizeof(struct ifreq));
    strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
    ioctl(sockfd, SIOCGIFFLAGS, &cpuif_req);
    cpuif_req.ifr_flags |= IFF_PROMISC;
    ioctl(sockfd, SIOCSIFFLAGS, &cpuif_req);

	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                   cpuif_name, IFNAMSIZ - 1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
        return -1;
	}

	/* Construct the Ethernet header */
	memset(recvbuf, 0, PKTBUF_SIZE);

	/* Receive packet */
    while (1) {
        rx_len = recvfrom(sockfd, recvbuf, PKTBUF_SIZE, 0, NULL, NULL);
        if (rx_len < 0) {
            printf("Recv failed\n");
        }
        else {
            // BUG: Here we can receive packets from other NICs!
            // So we need filter the packets from the switch
            if ((eth_h->h_dest[0] == MAC_ARRAY(PROBER_MAC, 0)) &&
                (eth_h->h_dest[1] == MAC_ARRAY(PROBER_MAC, 1)) &&
                (eth_h->h_dest[2] == MAC_ARRAY(PROBER_MAC, 2)) &&
                (eth_h->h_dest[3] == MAC_ARRAY(PROBER_MAC, 3)) &&
                (eth_h->h_dest[4] == MAC_ARRAY(PROBER_MAC, 4)) &&
                (eth_h->h_dest[5] == MAC_ARRAY(PROBER_MAC, 5))) {

                char probe_ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ipv6_h->saddr, probe_ip, sizeof(probe_ip));

                if (tcp_h->syn == 1) {
                    printf("Port %u of %s is active!\n",
                           ntohs(tcp_h->source), probe_ip);
                }
                else if (tcp_h->rst == 1) {
                    printf("Port %u of %s is inactive!\n",
                           ntohs(tcp_h->source), probe_ip);
                }
            }
        }
    }

    return 0;
}

#else
int sendpkt_to_switch() {
	int sockfd;
	struct ifreq cpuif_req;
	int tx_len = 0;
	char sendbuf[PKTBUF_SIZE];
	struct sockaddr_ll sock_addr;
	char cpuif_name[IFNAMSIZ];
	
	/* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    /* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
		close(sockfd);
        return -1;
	}

	/* Get the index of the interface to send on */
	memset(&cpuif_req, 0, sizeof(struct ifreq));
	strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &cpuif_req) < 0) {
	    perror("SIOCGIFINDEX");
		close(sockfd);
        return -1;
    }

	/* Construct the Ethernet header */
	memset(sendbuf, 0, PKTBUF_SIZE);
	tx_len += sizeof(struct ethhdr);

	/* Index of the network device */
	sock_addr.sll_ifindex = cpuif_req.ifr_ifindex;

	/* Send packet */
    if (sendto(sockfd, sendbuf, tx_len, 0,
               (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_ll)) < 0) {
        printf("Send failed\n");
        return -1;
    }

    return 0;
}

/*
 Checksums - IP and TCP
 */
static unsigned short csum(unsigned short *ptr,int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte)= *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;
	
	return answer;
}

int send_syn_temp_to_switch() {
	int sockfd;
	struct ifreq cpuif_req;
	int tx_len = 0;
	char sendbuf[PKTBUF_SIZE];
	struct ethhdr *eth_h = (struct ethhdr *)sendbuf;
    struct iphdr *ip_h = (struct iphdr *)
                         ((char *)eth_h + sizeof(struct ethhdr));
    struct tcphdr *tcp_h = (struct tcphdr *)
                           ((char *)ip_h + sizeof(struct iphdr));
    struct psdhdr psd_h;
    struct sockaddr_ll sock_addr;
	char cpuif_name[IFNAMSIZ];
	
	/* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    /* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
        return -1;
	}

	/* Get the index of the interface to send on */
	memset(&cpuif_req, 0, sizeof(struct ifreq));
	strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &cpuif_req) < 0) {
	    perror("SIOCGIFINDEX");
		close(sockfd);
        return -1;
    }

	/* Construct the Ethernet header */
	memset(sendbuf, 0, PKTBUF_SIZE);
	/* Ethernet header */
    for (unsigned int idx = 0; idx < 6; idx++) {
        eth_h->h_source[idx] = MAC_ARRAY(PROBER_MAC, idx);
    }
    eth_h->h_proto = htons(ETH_P_IP);
	tx_len += sizeof(struct ethhdr);

	/* IP header */
    ip_h->ihl = 5;
    ip_h->version = 4;
    ip_h->tos = 0;
    ip_h->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_h->id = htons(12345);
    ip_h->ttl = 128;
    ip_h->protocol = IPPROTO_TCP;
    ip_h->check = 0;
    ip_h->saddr = htonl(PROBER_IP);
    // ip_h->daddr = inet_addr("192.168.40.134");
    // IP Checksum
    ip_h->check = csum ((uint16_t *)ip_h, sizeof(struct iphdr));
	tx_len += sizeof(struct iphdr);

	/* TCP header */
    tcp_h->seq = htonl(123456789);
    tcp_h->ack_seq = htonl(0);
    tcp_h->doff = sizeof(struct tcphdr) / 4;
    tcp_h->fin=0;
    tcp_h->syn=1;
    tcp_h->rst=0;
    tcp_h->psh=0;
    tcp_h->ack=0;
    tcp_h->urg=0;
    tcp_h->window = htons(1024);
    tcp_h->check = 0;
    tcp_h->urg_ptr = 0;
	tx_len += sizeof(struct tcphdr);

    // TCP Checksum
    psd_h.saddr = ip_h->saddr;
    psd_h.daddr = ip_h->daddr;
    psd_h.placeholder = 0;
    psd_h.protocol = ip_h->protocol;
    psd_h.tcp_length =
        htons(tx_len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    memcpy(&psd_h.tcp , tcp_h , sizeof (struct tcphdr));
    tcp_h->check = csum((uint16_t *)&psd_h, sizeof(struct psdhdr));

	/* Packet data */
	// sendbuf[tx_len++] = 0xde;
	// sendbuf[tx_len++] = 0xad;
	// sendbuf[tx_len++] = 0xbe;
	// sendbuf[tx_len++] = 0xef;

	/* Index of the network device */
	sock_addr.sll_ifindex = cpuif_req.ifr_ifindex;
	/* Address length*/
	sock_addr.sll_halen = ETH_ALEN;
	/* Destination MAC */
	// sock_addr.sll_addr[0] = 0;
	// sock_addr.sll_addr[1] = 0;
	// sock_addr.sll_addr[2] = 0;
	// sock_addr.sll_addr[3] = 0;
	// sock_addr.sll_addr[4] = 0;
	// sock_addr.sll_addr[5] = 0;

	/* Send packet */
    for (uint32_t idx = 0; idx < 50000; idx++) {
        if (sendto(sockfd, sendbuf, tx_len, 0,
                (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_ll)) < 0) {
            printf("Send failed\n");
        }
    }

	return 0;
}

// abandon now
int recv_probe_report_from_switch() {
	int sockfd;
	struct ifreq cpuif_req;
	int rx_len = 0;
	char recvbuf[PKTBUF_SIZE];
	struct sockaddr_ll sock_addr;
    int sock_addrlen = sizeof(sock_addr);
	char cpuif_name[IFNAMSIZ];
	
	/* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    /* Header structures */
	struct ethhdr *eth_h = (struct ethhdr *)recvbuf;
    struct iphdr *ip_h = (struct iphdr *)
                         ((char *)eth_h + sizeof(struct ethhdr));
    struct tcphdr *tcp_h = (struct tcphdr *)
                           ((char *)ip_h + sizeof(struct iphdr));

    /* Open RAW socket to send on */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
	    perror("socket");
        return -1;
	}

    memset(&cpuif_req, 0, sizeof(struct ifreq));
    strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
    ioctl(sockfd, SIOCGIFFLAGS, &cpuif_req);
    cpuif_req.ifr_flags |= IFF_PROMISC;
    ioctl(sockfd, SIOCSIFFLAGS, &cpuif_req);

	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                   cpuif_name, IFNAMSIZ - 1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
        return -1;
	}

	/* Construct the Ethernet header */
	memset(recvbuf, 0, PKTBUF_SIZE);

	/* Receive packet */
    while (1) {
        rx_len = recvfrom(sockfd, recvbuf, PKTBUF_SIZE, 0, NULL, NULL);
        if (rx_len < 0) {
            printf("Recv failed\n");
        }
        else {
            // printf("ethertype: %x\n",ntohs(eth_h->h_proto));
            // BUG: Here we can receive packets from other NICs!
            // So we need filter the packets from the switch
            if ((eth_h->h_dest[0] == MAC_ARRAY(PROBER_MAC, 0)) &&
                (eth_h->h_dest[1] == MAC_ARRAY(PROBER_MAC, 1)) &&
                (eth_h->h_dest[2] == MAC_ARRAY(PROBER_MAC, 2)) &&
                (eth_h->h_dest[3] == MAC_ARRAY(PROBER_MAC, 3)) &&
                (eth_h->h_dest[4] == MAC_ARRAY(PROBER_MAC, 4)) &&
                (eth_h->h_dest[5] == MAC_ARRAY(PROBER_MAC, 5))) {

                char probe_ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip_h->saddr, probe_ip, sizeof(probe_ip));

                if (tcp_h->syn == 1) {
                    printf("Port %u of %s is active!\n",
                           ntohs(tcp_h->source), probe_ip);
                }
                else if (tcp_h->rst == 1) {
                    printf("Port %u of %s is inactive!\n",
                           ntohs(tcp_h->source), probe_ip);
                }
            }
        }
    }

    return 0;
}
#endif

int creat_update_notifying_channel(update_notifying_channel_t *channel) {
	struct ifreq cpuif_req;
	struct sockaddr_ll sock_addr;
    int sock_addrlen = sizeof(sock_addr);
	char cpuif_name[IFNAMSIZ];

    /* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    channel->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_IREPORT));
    /* Open RAW socket to send on */
	if (channel->sockfd == -1) {
	    perror("socket");
        return -1;
	}

    memset(&cpuif_req, 0, sizeof(struct ifreq));
    strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
    ioctl(channel->sockfd, SIOCGIFFLAGS, &cpuif_req);
    cpuif_req.ifr_flags |= IFF_PROMISC;
    ioctl(channel->sockfd, SIOCSIFFLAGS, &cpuif_req);

	if (setsockopt(channel->sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                   cpuif_name, IFNAMSIZ - 1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(channel->sockfd);
        return -1;
	}

	/* Construct the Ethernet header */
	memset(channel->recvbuf, 0, PKTBUF_SIZE);

    return 0;
}

int recv_update_notification(update_notifying_channel_t *channel) {
	int rx_len = 0;

    /* Header structures */
	struct ethhdr *eth_h = (struct ethhdr *)channel->recvbuf;
    uint8_t *probe_table = (uint8_t *)((char *)eth_h + sizeof(struct ethhdr));
    uint16_t *pipr_idx = (uint16_t *)((char *)probe_table + sizeof(uint8_t));
    uint16_t *egress_port = (uint16_t *)((char *)pipr_idx + sizeof(uint16_t));

    rx_len = recvfrom(channel->sockfd, channel->recvbuf,
                      PKTBUF_SIZE, 0, NULL, NULL);
    if (rx_len < 0) {
        printf("Recv failed\n");
        return -1;
    }
    else {
        channel->probe_table = *probe_table;
        channel->pipr_idx = htons(*pipr_idx);
        channel->egress_port = htons(*egress_port);
        return 0;
    }
}

//abandon now
int recv_update_notification_from_switch(uint32_t timer, uint8_t *pipr_filter) {
	int sockfd;
	struct ifreq cpuif_req;
	int rx_len = 0;
	char recvbuf[PKTBUF_SIZE];
	struct sockaddr_ll sock_addr;
    int sock_addrlen = sizeof(sock_addr);
	char cpuif_name[IFNAMSIZ];
    time_t start_time, current_time;
    uint32_t not_completed = 0;
	
    /* Header structures */
	struct ethhdr *eth_h = (struct ethhdr *)recvbuf;
    uint16_t *pipr_idx = (uint16_t *)((char *)eth_h + sizeof(struct ethhdr));
    uint16_t *egress_port = (uint16_t *)((char *)pipr_idx + sizeof(uint16_t));

	/* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_IREPORT));
    /* Open RAW socket to send on */
	if (sockfd == -1) {
	    perror("socket");
        return -1;
	}

    memset(&cpuif_req, 0, sizeof(struct ifreq));
    strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
    ioctl(sockfd, SIOCGIFFLAGS, &cpuif_req);
    cpuif_req.ifr_flags |= IFF_PROMISC;
    ioctl(sockfd, SIOCSIFFLAGS, &cpuif_req);

	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                   cpuif_name, IFNAMSIZ - 1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
        return -1;
	}

	/* Construct the Ethernet header */
	memset(recvbuf, 0, PKTBUF_SIZE);

    start_time = time(NULL);

	/* Receive packet */
    while (1) {
        current_time = time(NULL);
        if (difftime(current_time, start_time) > timer) {
            break;
        }
        rx_len = recvfrom(sockfd, recvbuf, PKTBUF_SIZE, 0, NULL, NULL);
        if (rx_len < 0) {
            printf("Recv failed\n");
        }
        else {
            // // BUG: Here we can receive packets from other NICs!
            // // So we need filter the packets from the switch
            // if ((eth_h->h_source[0] == MAC_ARRAY(PROBER_MAC, 0)) &&
            //     (eth_h->h_source[1] == MAC_ARRAY(PROBER_MAC, 1)) &&
            //     (eth_h->h_source[2] == MAC_ARRAY(PROBER_MAC, 2)) &&
            //     (eth_h->h_source[3] == MAC_ARRAY(PROBER_MAC, 3)) &&
            //     (eth_h->h_source[4] == MAC_ARRAY(PROBER_MAC, 4)) &&
            //     (eth_h->h_source[5] == MAC_ARRAY(PROBER_MAC, 5))) {

            //     printf("The probe ip range (idx: %u, port: %u) is probed "
            //            "completely\n", htons(*pipr_idx), htons(*egress_port));
            // }
            if (pipr_filter[htons(*pipr_idx)] == 1) {
                pipr_filter[htons(*pipr_idx)] = 2;
            }
        }
    }

    for (uint32_t idx = 0; idx < IP_RANGE_TABLE_SIZE; idx++) {
        if (pipr_filter[idx] == 1) {
            printf("The probe ip range (%u) is not probed completely\n", idx);
            not_completed += 1;
        }
    }

    printf("The probe task is completed with %u probe ip "
           "range not probed completely\n", not_completed);

    return 0;
}

int send_flush_request_to_switch() {
	int sockfd;
	struct ifreq cpuif_req;
	int tx_len = 0;
	char sendbuf[PKTBUF_SIZE];
	struct ethhdr *eth_h = (struct ethhdr *)sendbuf;
    struct psdhdr psd_h;
    struct sockaddr_ll sock_addr;
	char cpuif_name[IFNAMSIZ];
	
	/* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    /* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
        return -1;
	}

	/* Get the index of the interface to send on */
	memset(&cpuif_req, 0, sizeof(struct ifreq));
	strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &cpuif_req) < 0) {
	    perror("SIOCGIFINDEX");
		close(sockfd);
        return -1;
    }

	/* Construct the Ethernet header */
	memset(sendbuf, 0, PKTBUF_SIZE);
	/* Ethernet header */
    for (unsigned int idx = 0; idx < 6; idx++) {
        eth_h->h_source[idx] = MAC_ARRAY(PROBER_MAC, idx);
    }
    eth_h->h_proto = htons(ETHER_TYPE_IFLUSH);
	tx_len += sizeof(struct ethhdr);

	/* Packet data */
	// sendbuf[tx_len++] = 0xde;
	// sendbuf[tx_len++] = 0xad;
	// sendbuf[tx_len++] = 0xbe;
	// sendbuf[tx_len++] = 0xef;

	/* Index of the network device */
	sock_addr.sll_ifindex = cpuif_req.ifr_ifindex;
	/* Address length*/
	sock_addr.sll_halen = ETH_ALEN;
	/* Destination MAC */
	// sock_addr.sll_addr[0] = 0;
	// sock_addr.sll_addr[1] = 0;
	// sock_addr.sll_addr[2] = 0;
	// sock_addr.sll_addr[3] = 0;
	// sock_addr.sll_addr[4] = 0;
	// sock_addr.sll_addr[5] = 0;

	/* Send packet */
    if (sendto(sockfd, sendbuf, tx_len, 0,
               (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_ll)) < 0) {
        printf("Send failed\n");
    }

	return 0;
}
