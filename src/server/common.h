#ifndef __COMMON_H__
#define __COMMON_H__

#include <rte_byteorder.h>

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
    //TODO: support multiple queues per core?
    unsigned rx_queue_id;
} __rte_cache_aligned;

#define RTE_LOGTYPE_IMAP RTE_LOGTYPE_USER1

struct imap_result_meta {
    uint8_t  resp_pkt_count;
} __rte_packed;

struct imap_probe_result {
    uint16_t probe_port;
    uint8_t  _pad;
    uint8_t  result;
} __rte_packed;

struct imap_result_pack {
    uint32_t target[RESULTS_PER_RESULT_PACK];
    struct imap_probe_result result[RESULTS_PER_RESULT_PACK];
} __rte_packed;

struct imap_result_entry {
    uint32_t probe_addr;
    uint16_t probe_port;
    uint32_t probe_result;
};

#endif