#include "../iconfig.h"
#include "common.h"

#include <stdint.h>
#include <inttypes.h>
#include <netinet/ether.h>
#include <linux/icmp.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_arp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_debug.h>
#include <rte_meter.h>

#define REDIS_MODE 0
#define POSTGRE_MODE 1

// #define DATABASE_MODE REDIS_MODE
#define DATABASE_MODE POSTGRE_MODE

#if DATABASE_MODE == POSTGRE_MODE
#include <postgresql/libpq-fe.h>
static void exit_nicely(PGconn *conn) {
	PQfinish(conn);
	exit(1);
}
#elif DATABASE_MODE == REDIS_MODE
#include <hiredis/hiredis.h>
#endif

extern volatile bool force_quit;
extern struct lcore_queue_conf lcore_queue_conf[];

#ifdef DEBUG
#define NUM_ENTRIES (RESULT_ENTRY_BUF_SIZE / sizeof(struct imap_result_entry))
struct imap_result_entry result_buf[NUM_ENTRIES];
size_t result_buf_cnt = 0;
#endif

void
print_ethaddr(const char *msg, unsigned char * eth_addr) {
    printf("%s: ", msg);
    printf("%2x:%2x:%2x:%2x:%2x:%2x\n", eth_addr[0], eth_addr[1], eth_addr[2],
        eth_addr[3], eth_addr[4], eth_addr[5]);
}

const char*
probe_result_display(uint8_t probe_result) {
    switch (probe_result) {
        case PROBE_RESULT_INACTIVE_RESP:
            return "inactive";
        case PROBE_RESULT_ACTIVE_RESP:
            return "active";
    };
}

const char*
icmp_type_display(uint8_t icmp_type) {
    switch (icmp_type) {
        case ICMP_ECHOREPLY:
            return "Echo Reply";
        case ICMP_DEST_UNREACH:
            return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH:
            return "Source Quench";
        case ICMP_REDIRECT:
            return "Redirect (change route)";
        case ICMP_ECHO:
            return "Echo Request";
        case ICMP_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMP_PARAMETERPROB:
            return "Parameter Problem";
        case ICMP_TIMESTAMP:
            return "Timestamp Request";
        case ICMP_TIMESTAMPREPLY:
            return "Timestamp Reply";
        case ICMP_INFO_REQUEST:
            return "Information Request";
        case ICMP_INFO_REPLY:
            return "Information Reply";
        case ICMP_ADDRESS:
            return "Address Mask Request";
        case ICMP_ADDRESSREPLY:
            return "Address Mask Reply";
    };
    return "Unsupported ICMP Type";
}

const char*
icmp_code_display(uint8_t icmp_type, uint8_t icmp_code) {
    if (icmp_type == ICMP_ECHOREPLY) {
        return "OK";
    }
    else if (icmp_type == ICMP_DEST_UNREACH) {
        switch (icmp_code) {
            case ICMP_NET_UNREACH:
                return "Network Unreachable";
            case ICMP_HOST_UNREACH:
                return "Host Unreachable";
            case ICMP_PROT_UNREACH:
                return "Protocol Unreachable";
            case ICMP_PORT_UNREACH:
                return "Port Unreachable";
            case ICMP_FRAG_NEEDED:
                return "Fragmentation Needed/DF set";
            case ICMP_SR_FAILED:
                return "Source Route failed";
            case ICMP_PKT_FILTERED:
                return "Packet filtered";
            case ICMP_PREC_VIOLATION:
                return "Precedence violation";
            case ICMP_PREC_CUTOFF:
                return "Precedence cut off";
        };
    }
    else if (icmp_type == ICMP_REDIRECT) {
        switch (icmp_code) {
            case ICMP_REDIR_NET:
                return "Redirect Net";
            case ICMP_REDIR_HOST:
                return "Redirect Host";
            case ICMP_REDIR_NETTOS:
                return "Redirect Net for TOS";
            case ICMP_REDIR_HOSTTOS:
                return "Redirect Host for TOS";
        };
    }
    else if (icmp_type == ICMP_TIME_EXCEEDED) {
        switch (icmp_code) {
            case ICMP_EXC_TTL:
                return "TTL count exceeded";
            case ICMP_EXC_FRAGTIME:
                return "Fragment Reass time exceeded";
        };
    }
    return "Unsupported ICMP Code";
}

void
print_imap_result_entry(const char *msg, struct imap_result_entry entry) {
    printf("%s: ", msg);
    uint8_t *ip_addr = (uint8_t *)&entry.probe_addr;
    #if __PROBE_TYPE__ == PROBE_TYPE_SYN_PROBER
    printf("%3u.%3u.%3u.%3u:%5hu\t",
           ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], entry.probe_port);
    printf("%s\n", probe_result_display(entry.probe_result));
    #elif __PROBE_TYPE__ == PROBE_TYPE_ICMP_PROBER
    printf("%3u.%3u.%3u.%3u\t", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
    printf("%s\t", probe_result_display(entry.probe_result));
    printf("%s\t%s\n", 
           icmp_type_display(entry.icmp_type), 
           icmp_code_display(entry.icmp_type, entry.icmp_code));
    #endif
}

void
imap_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	unsigned i, j, m, n, idx, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_tx_buffer *buffer;
    unsigned count;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];
#if DATABASE_MODE == POSTGRE_MODE
    const char *conninfo;
    PGconn     *conn;
    conninfo = "host=127.0.0.1 port=5432 dbname=imap user=postgres";
    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        printf("Connection to database failed: %s\n",
                PQerrorMessage(conn));
        exit_nicely(conn);
    }
    else {
        printf("Database connected.\n");
    }
    PGresult *res;
    char command_buffer[256];
#elif DATABASE_MODE == REDIS_MODE

    redisContext *redis_conn;
    redisReply *redis_reply;
    redis_conn = redisConnect("127.0.0.1", 6379);
    if (redis_conn->err) {
        rte_exit(EXIT_FAILURE,
                 "Redis connection error: %s\n", redis_conn->errstr);
    }
    else {
		RTE_LOG(INFO, IMAP, "Redis database connected\n");
    }
#endif

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, IMAP, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, IMAP, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, IMAP, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}

    count = 0;

	while (!force_quit) {
		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, qconf->rx_queue_id,
						 pkts_burst, MAX_PKT_BURST);

            if (unlikely(nb_rx == 0)) {
                continue;
            }

			for (j = 0; j < nb_rx; j++) {
                /* extract ethernet */
                struct rte_ether_hdr *eth_hdr;
                eth_hdr = rte_pktmbuf_mtod(pkts_burst[j], void *);
                rte_prefetch0(eth_hdr);

                if (eth_hdr->ether_type == \
                        rte_be_to_cpu_16(ETHER_TYPE_IRESULT)) {
                    /* extract result packs */
                    struct imap_result_meta *meta = (struct imap_result_meta *)
                                ((char*)eth_hdr + sizeof(struct rte_ether_hdr));
                    struct imap_result_pack *packs = (struct imap_result_pack *)
                                ((char*)meta + sizeof(struct imap_result_meta));
                    if (meta->resp_pkt_count != \
                            RESULT_PACKS_PER_PACKET * RESULTS_PER_RESULT_PACK) {
                        count += meta->resp_pkt_count;
                        #ifdef DEBUG
                        printf("This is a result packet after flushing "
                               "(resp_pkt_count: %u, sum_count: %u)\n",
                               meta->resp_pkt_count, count);
                        #endif
                        for (idx = 0; idx < meta->resp_pkt_count; idx++) {
                            m = idx / RESULTS_PER_RESULT_PACK;
                            n = idx % RESULTS_PER_RESULT_PACK;
                            #ifdef DEBUG
                            result_buf[result_buf_cnt].probe_addr = \
                                                            packs[m].target[n];
                            #if __PROBE_TYPE__ == PROBE_TYPE_SYN_PROBER
                            result_buf[result_buf_cnt].probe_port = \
                                rte_be_to_cpu_16(packs[m].result[n].probe_port);
                            #elif __PROBE_TYPE__ == PROBE_TYPE_ICMP_PROBER
                            result_buf[result_buf_cnt].icmp_type = \
                                                packs[m].result[n].icmp_type;
                            result_buf[result_buf_cnt].icmp_code = \
                                                packs[m].result[n].icmp_code;
                            #endif
                            result_buf[result_buf_cnt].probe_result = \
                                                    packs[m].result[n].result;
                            print_imap_result_entry("data entry",
                                                    result_buf[result_buf_cnt]);
                            result_buf_cnt += 1;
                            #endif
                            #if DATABASE_MODE == POSTGRE_MODE
                            #if __PROBE_TYPE__ == PROBE_TYPE_SYN_PROBER
                                sprintf(command_buffer, 
                                    "INSERT INTO imap VALUES ('%u.%u.%u.%u:%u', %u) ON CONFLICT DO NOTHING",
                                    ((uint8_t *)&(packs[m].target[n]))[0],
                                    ((uint8_t *)&(packs[m].target[n]))[1],
                                    ((uint8_t *)&(packs[m].target[n]))[2],
                                    ((uint8_t *)&(packs[m].target[n]))[3],
                                    rte_be_to_cpu_16(packs[m].result[n].probe_port),
                                    packs[m].result[n].result);
                            #elif __PROBE_TYPE__ == PROBE_TYPE_ICMP_PROBER
                                sprintf(command_buffer, 
                                    "INSERT INTO imap VALUES ('%u.%u.%u.%u', %u)",
                                    ((uint8_t *)&(packs[m].target[n]))[0],
                                    ((uint8_t *)&(packs[m].target[n]))[1],
                                    ((uint8_t *)&(packs[m].target[n]))[2],
                                    ((uint8_t *)&(packs[m].target[n]))[3],
                                    packs[m].result[n].result);
                            #endif
                                res = PQexec(conn, command_buffer); 
                                if (PQresultStatus(res)!=PGRES_COMMAND_OK) {
                                    printf("insert failed: %s\n", PQerrorMessage(conn));
                                }
                                // PQclear(res);
                            #elif DATABASE_MODE == REDIS_MODE
                            #if __PROBE_TYPE__ == PROBE_TYPE_SYN_PROBER
                            redis_reply = redisCommand(
                                redis_conn, "set %u.%u.%u.%u:%hu %s",
                                ((uint8_t *)&(packs[m].target[n]))[0],
                                ((uint8_t *)&(packs[m].target[n]))[1],
                                ((uint8_t *)&(packs[m].target[n]))[2],
                                ((uint8_t *)&(packs[m].target[n]))[3],
                                rte_be_to_cpu_16(packs[m].result[n].probe_port),
                                probe_result_display(packs[m].result[n].result)
                            );
                            #elif __PROBE_TYPE__ == PROBE_TYPE_ICMP_PROBER
                            redis_reply = redisCommand(
                                redis_conn, "set %u.%u.%u.%u %s",
                                ((uint8_t *)&(packs[m].target[n]))[0],
                                ((uint8_t *)&(packs[m].target[n]))[1],
                                ((uint8_t *)&(packs[m].target[n]))[2],
                                ((uint8_t *)&(packs[m].target[n]))[3],
                                probe_result_display(packs[m].result[n].result)
                            );
                            #endif
                            if (redis_reply->type == REDIS_REPLY_ERROR) {
                                rte_exit(EXIT_FAILURE,
                                        "Redis insertion error: %s\n",
                                        redis_reply->str);
                            }
                            #endif
                        }
                    }
                    else {
                        count += RESULT_PACKS_PER_PACKET * \
                                 RESULTS_PER_RESULT_PACK;
                        #ifdef DEBUG
                        printf("This is a result packet after evicting "
                               "(sum_count: %u)\n", count);
                        #endif
                        for (m = 0; m < RESULT_PACKS_PER_PACKET; m++) {
                            for (n = 0; n < RESULTS_PER_RESULT_PACK; n++) {
                                #ifdef DEBUG
                                result_buf[result_buf_cnt].probe_addr = \
                                                            packs[m].target[n];
                                #if __PROBE_TYPE__ == PROBE_TYPE_SYN_PROBER
                                result_buf[result_buf_cnt].probe_port = \
                                rte_be_to_cpu_16(packs[m].result[n].probe_port);
                                #elif __PROBE_TYPE__ == PROBE_TYPE_ICMP_PROBER
                                result_buf[result_buf_cnt].icmp_type = \
                                                packs[m].result[n].icmp_type;
                                result_buf[result_buf_cnt].icmp_code = \
                                                packs[m].result[n].icmp_code;
                                #endif
                                result_buf[result_buf_cnt].probe_result = \
                                                    packs[m].result[n].result;
                                print_imap_result_entry("data entry",
                                                    result_buf[result_buf_cnt]);
                                result_buf_cnt += 1;
                                #endif
                                #if DATABASE_MODE == POSTGRE_MODE
                                #if __PROBE_TYPE__ == PROBE_TYPE_SYN_PROBER
                                    sprintf(command_buffer, 
                                        "INSERT INTO imap VALUES ('%u.%u.%u.%u:%u', %u) ON CONFLICT DO NOTHING",
                                        ((uint8_t *)&(packs[m].target[n]))[0],
                                        ((uint8_t *)&(packs[m].target[n]))[1],
                                        ((uint8_t *)&(packs[m].target[n]))[2],
                                        ((uint8_t *)&(packs[m].target[n]))[3],
                                        rte_be_to_cpu_16(packs[m].result[n].probe_port),
                                        packs[m].result[n].result);
                                #elif __PROBE_TYPE__ == PROBE_TYPE_ICMP_PROBER
                                    sprintf(command_buffer, 
                                        "INSERT INTO imap VALUES ('%u.%u.%u.%u', %u)",
                                        ((uint8_t *)&(packs[m].target[n]))[0],
                                        ((uint8_t *)&(packs[m].target[n]))[1],
                                        ((uint8_t *)&(packs[m].target[n]))[2],
                                        ((uint8_t *)&(packs[m].target[n]))[3],
                                        packs[m].result[n].result);
                                #endif
                                res = PQexec(conn, command_buffer); 
                                if (PQresultStatus(res)!=PGRES_COMMAND_OK) {
                                    printf("insert failed: %s\n", PQerrorMessage(conn));
                                }
                                // PQclear(res);
                                
                                #elif DATABASE_MODE == REDIS_MODE
                                #if __PROBE_TYPE__ == PROBE_TYPE_SYN_PROBER
                                redis_reply = redisCommand(
                                    redis_conn, "set %u.%u.%u.%u:%hu %s",
                                    ((uint8_t *)&(packs[m].target[n]))[0],
                                    ((uint8_t *)&(packs[m].target[n]))[1],
                                    ((uint8_t *)&(packs[m].target[n]))[2],
                                    ((uint8_t *)&(packs[m].target[n]))[3],
                                    rte_be_to_cpu_16(
                                            packs[m].result[n].probe_port),
                                    probe_result_display(
                                                packs[m].result[n].result)
                                );
                                #elif __PROBE_TYPE__ == PROBE_TYPE_ICMP_PROBER
                                redis_reply = redisCommand(
                                    redis_conn, "set %u.%u.%u.%u %s",
                                    ((uint8_t *)&(packs[m].target[n]))[0],
                                    ((uint8_t *)&(packs[m].target[n]))[1],
                                    ((uint8_t *)&(packs[m].target[n]))[2],
                                    ((uint8_t *)&(packs[m].target[n]))[3],
                                    probe_result_display(
                                                packs[m].result[n].result)
                                );
                                #endif
                                if (redis_reply->type == REDIS_REPLY_ERROR) {
                                    rte_exit(EXIT_FAILURE,
                                            "Redis insertion error: %s\n",
                                            redis_reply->str);
                                }
                                #endif
                            }
                        }
                    }

                    #ifdef DEBUG
                    if (result_buf_cnt >= NUM_ENTRIES) {
                        // TODO: call data buf handler
                    }
                    #endif
                }
                rte_pktmbuf_free(pkts_burst[j]);
			}
		}
	}
}
