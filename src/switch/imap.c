/*************************************************************************
	> File Name: imap.c
	> Author: Guanyu Li
	> Mail: dracula.guanyu.li@gmail.com
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Main program of IMap
 ************************************************************************/

#include "../iconfig.h"
#include "imap.h"
#include "iswitch.h"
#include "ichannel.h"
#include "iparser.h"

typedef struct imap_conf_s {
    int           log_level;
    uint32_t      probe_period;
    uint32_t      waiting_time;
    port_h_t      probe_port;
    probe_entry_t probe_port_range;
    char          config_filename[256];
} imap_conf_t;

const switch_port_t FORWARD_LIST[] = {
    {0x6891d061b4c4, "1/0"},
    // {0x6891d061124b, "4/0"},
};

// PRIME_LIST[i] is the smallest prime greater than 2 ^ i
const uint32_t PRIME_LIST [] = {
//  1, 2, 4,  8, 16, 32, 64, 128, ( 2 ^ i)
    2, 3, 5, 11, 17, 37, 67, 131,
//  256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
    257, 521, 1031, 2053, 4099, 8209, 16411, 32771,
//  65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608,
    65537, 131101, 262147, 524309, 1048583, 2097169, 4194319, 8388617,
//  16777216, 33554432, 67108864, 134217728, 268435456, 536870912
    16777259, 33554467, 67108879, 134217757, 268435459, 536870923
};

probe_entry_t PIPR_ENTRIES[((uint64_t)1 << 32) / IP_RANGE_MAX_SIZE];
uint64_t PIPR_ENTRY_COUNT;

static void parse_options(imap_conf_t *iconf, int argc, char **argv) {
    int option_index = 0;
    enum opts {
        OPT_LOG_LEVEL = 1,
        OPT_PROBE_PORT,
        OPT_PROBE_PORT_RANGE,
        OPT_RATE,
        OPT_SEED_RATE,
        OPT_WAITING_TIME,
        OPT_CONFIG_FILE,
    };
    static struct option options[] = {
        {"help", no_argument, 0, 'h'},
        {"log-level", optional_argument, 0, OPT_LOG_LEVEL},
        {"probe-port", required_argument, 0, OPT_PROBE_PORT},
        {"probe-port-range", required_argument, 0, OPT_PROBE_PORT_RANGE},
        {"rate", required_argument, 0, OPT_RATE},
        {"seed-rate", required_argument, 0, OPT_SEED_RATE},
        {"waiting-time", required_argument, 0, OPT_WAITING_TIME},
        {"ip-list", required_argument, 0, OPT_CONFIG_FILE},
    };

    memset(iconf, 0, sizeof(imap_conf_t));
    iconf->probe_period = 1000000000; // Default set to 1s (10^9 ns)
    iconf->waiting_time = 0xffffffff;

    while (1) {
        int c = getopt_long(argc, argv, "h", options, &option_index);

        if (c == -1) {
            break;
        }
        switch (c) {
            case OPT_LOG_LEVEL:
                iconf->log_level = atoi(optarg);
                printf("Log Level: %d\n", iconf->log_level);
                break;
            case OPT_PROBE_PORT:
                iconf->probe_port = atoi(optarg);
                printf("Probe Port : %hu\n", iconf->probe_port);
                break;
            case OPT_PROBE_PORT_RANGE:
                if (sscanf(optarg, "%hu:%hu", \
                           &(iconf->probe_port_range.start), \
                           &(iconf->probe_port_range.end)) != 2) {
                    printf("Invalid format for --probe-port-range\n");
                    exit(0);
                }
                else {
                    printf("Probe Port Range: %hu:%hu\n",
                           iconf->probe_port_range.start,
                           iconf->probe_port_range.end);
                }
                break;
            case OPT_RATE:
                iconf->probe_period /= atoi(optarg);
                iconf->probe_period *= ARRLEN(FORWARD_LIST);
                printf("Rate: %u (Probe period: %u)\n",
                       atoi(optarg), iconf->probe_period);
                break;
            case OPT_SEED_RATE:
                iconf->probe_period /= atoi(optarg);
                printf("Probe seed rate: %d (Probe period: %d)\n",
                       atoi(optarg), iconf->probe_period);
                break;
            case OPT_WAITING_TIME:
                iconf->waiting_time = atoi(optarg);
                printf("Waiting time: %u\n", atoi(optarg));
                break;
            case OPT_CONFIG_FILE:
                strcpy(iconf->config_filename, optarg);
                printf("IP list config file: %s\n", optarg);
                break;
            case 'h':
            case '?':
                printf("imap \n");
                printf("Usage : imap --rate/seed-rate <rate>/<seed-rate> "
                       "--waiting-time <waiting-time> "
                       "--probe-port <port-number> / "
                       "--probe-port-range <start-port:end-port>\n");
                exit(c == 'h' ? 0 : 1);
                break;
            default:
                printf("Invalid option\n");
                exit(0);
                break;
        }
    }

    if  (iconf->probe_port_range.end == 0) {
        if (iconf->probe_port == 0) {
            printf("ERROR: Probe port or probe port range "
                   "must be specified correctly\n");
            exit(0);
        }
        else {
            iconf->probe_port_range.start = iconf->probe_port;
            iconf->probe_port_range.end = iconf->probe_port;
        }
    }
    
    if (iconf->probe_period * (uint64_t)IP_RANGE_TABLE_SIZE \
                            * IP_RANGE_MAX_SIZE < CHANNEL_MAX_LATENCY) {
        printf("ERROR: Probe rate is too fast, it must be set to be smaller "
               "than IP_RANGE_TABLE_SIZE * IP_RANGE_MAX_SIZE * 10^9 / "
               "CHANNEL_MAX_LATENCY to avoid race conditions\n");
        exit(0);
    }
}

static void start_scanner(imap_conf_t *iconf,
                          iswitch_t *iswitch,
                          const probe_entry_t *probe_space,
                          const uint32_t probe_entry_count) {
    int imap_status = 0;
    uint16_t port_range_size = 0;
    uint64_t probe_space_size = 0;
    uint32_t entry_size = 0;
    uint8_t  entry_size_base;
    probe_entry_t pipr_entry;
    update_notifying_channel_t update_channel;
    struct timespec start_time, current_time;
    // Next are only used when the probe space is greater
    // than IP_RANGE_TABLE_SIZE
    uint64_t rest_probe_space_size;
    uint32_t *rest_size = NULL;
    uint32_t *prime_base = NULL;
    uint32_t *prime_count = NULL;
    uint32_t *random_picker = NULL;
    uint32_t picker_cursor = 0; // Random picker cursor
    uint32_t picker_coverage = 0; // Random picker coverage
    uint32_t entry_idx = 0;
    uint64_t pipr_entry_idx = 0;
    uint8_t  not_completed = 0;
    uint32_t batch_size = 0;

    port_range_size = iconf->probe_port_range.end - \
                      iconf->probe_port_range.start + 1;

    printf("Probe port range size: %hu\n", port_range_size);

    for (uint32_t idx = 0; idx < probe_entry_count; idx++) {
        probe_space_size += probe_space[idx].end - probe_space[idx].start + 1;
    }

    printf("Probe space size: %lu\n", probe_space_size);

    // Default we employ the pipr_t0 first.
    probe_ip_range_table_reset(iswitch, 0);

    rest_probe_space_size = probe_space_size;
    rest_size = (uint32_t *)malloc(probe_entry_count * sizeof(uint32_t));
    prime_base = (uint32_t *)malloc(probe_entry_count * sizeof(uint32_t));
    prime_count = (uint32_t *)malloc(probe_entry_count * sizeof(uint32_t));
    random_picker = (uint32_t *)malloc
                    (RANDOM_PICKER_SIZE * sizeof(uint32_t));

    entry_size = (uint32_t)ceil(1.0 * probe_space_size / IP_RANGE_TABLE_SIZE);
    memset(random_picker, 0, RANDOM_PICKER_SIZE * sizeof(uint32_t));
    // Resize the entry_size to 2 ^ i
    entry_size = pow(2, (uint32_t)ceil(log2(entry_size)));
    // Control the maxmium entry size
    entry_size = (entry_size <= IP_RANGE_MAX_SIZE) ? entry_size : \
                                                        IP_RANGE_MAX_SIZE;
    printf("Probe IP range table entry size: %u\n", entry_size);
    entry_size_base = (uint8_t)log2(entry_size);
    // Prepare for the data structure to allocate entries for pipr table
    for (uint32_t idx = 0; idx < probe_entry_count; idx++) {
        rest_size[idx] = probe_space[idx].end - probe_space[idx].start + 1;
        // Prepare for the prime base
        prime_base[idx] = (uint32_t)ceil(1.0 * rest_size[idx] / entry_size);
        prime_base[idx] = (uint32_t)ceil(log2(prime_base[idx]));
        prime_count[idx] = 0;
        // Construct the random picker
        // (random picker is used to implement the weighted random number
        // generation, utilizing the storage to gain efficient computing)
        picker_coverage = (uint32_t)(1.0 * rest_size[idx] /
                                        probe_space_size * RANDOM_PICKER_SIZE);
        for (uint32_t offset = 0; offset < picker_coverage; offset++) {
            random_picker[picker_cursor] = idx;
            picker_cursor += 1;
        }
    }
    // Employ "multiplicative group of integers modulo n" to compute entries
    PIPR_ENTRY_COUNT = 0;
    while (rest_probe_space_size != 0) {
        // Select a nonempty probe space entry
        do {
            // Here we use the instead of RANDOM_PICKER_SIZE, because the real
            // size (picker_cursor) may be smaller than RANDOM_PICKER_SIZE
            entry_idx = random_picker[rand() % picker_cursor];
            // printf("Debug - entry_idx: %u\n", entry_idx);
        } while (rest_size[entry_idx] == 0);
        // Generate a valid address range (pipr entry) with the method in ZMap
        do {
            // printf("Debug - prime_count: %u\n", prime_count[entry_idx]);
            pipr_entry.start = probe_space[entry_idx].start;
            // printf("Debug - start base: 0x%x\n", pipr_entry.start);
            pipr_entry.start += ((prime_count[entry_idx] * PRIME_ROOT) % \
                                    PRIME_LIST[prime_base[entry_idx]]
                                ) << entry_size_base;
            // printf("Debug - start: 0x%x\n", pipr_entry.start);
            prime_count[entry_idx] += 1;
        } while (pipr_entry.start > probe_space[entry_idx].end);
        pipr_entry.end = pipr_entry.start + (entry_size - 1);
        if (pipr_entry.end > probe_space[entry_idx].end) {
            pipr_entry.end = probe_space[entry_idx].end;
        }
        // Store the generated pipr entry
        PIPR_ENTRIES[PIPR_ENTRY_COUNT] = pipr_entry;
        PIPR_ENTRY_COUNT += 1;
        // Update the rest probe space
        rest_size[entry_idx] -= pipr_entry.end - pipr_entry.start + 1;
        rest_probe_space_size -= pipr_entry.end - pipr_entry.start + 1;
    }
    printf("Entry count of probe ip range table: %lu\n", PIPR_ENTRY_COUNT);
    
    // NOTICE: sleep is used to avoid race condition for control channel!
    printf("Waiting %u seconds to avoid race condition "
           "in control channel\n", SLEEP_TIME_FOR_IDLE_CHANNEL);
    sleep(SLEEP_TIME_FOR_IDLE_CHANNEL);

    // Install probe ip range entry to t0
    clock_gettime(CLOCK_REALTIME, &start_time);
    if (PIPR_ENTRY_COUNT - pipr_entry_idx < IP_RANGE_TABLE_SIZE) {
        // The pipr table can not be loaded fully this time
        batch_size = PIPR_ENTRY_COUNT - pipr_entry_idx;
        // We add an extra entry in the last slot to ensure the correctness
        pipr_entry.start = IP_PLACEHOLDER;
        pipr_entry.end = pipr_entry.start + (entry_size - 1);
        probe_ip_range_table_install(iswitch, 0,
                                     IP_RANGE_TABLE_SIZE - 1, &pipr_entry);
    }
    else {
        batch_size = IP_RANGE_TABLE_SIZE;
    }
    // printf("Debug: batch_size %u\n", batch_size);
    // Default we employ the pipr_t0 first.
    probe_ip_range_table_install_batch(iswitch, 0, 0, batch_size,
                                       &PIPR_ENTRIES[pipr_entry_idx]);
    pipr_entry_idx += batch_size;
    not_completed += 1;
    printf("Debug: %lu probe ip range entries are left for port %hu\n",
           PIPR_ENTRY_COUNT - pipr_entry_idx,
           iconf->probe_port_range.end - port_range_size + 1);
    if (pipr_entry_idx == PIPR_ENTRY_COUNT) {
        // The pipr entries are all loaded
        if (port_range_size != 0) {
            // The current port is probed, considering the next probe port in
            // the range
            port_range_size -= 1;
        }
        if (port_range_size != 0) {
            // The whole port range is probed
            pipr_entry_idx = 0;
        }
    }
    clock_gettime(CLOCK_REALTIME, &current_time);
    printf("Debug: Install probe ip range entries into t0 within %f seconds\n",
           ((current_time.tv_sec - start_time.tv_sec) * 1000000000.0 + \
            current_time.tv_nsec - start_time.tv_nsec) / 1000000000.0);

    if (!(pipr_entry_idx == PIPR_ENTRY_COUNT && port_range_size == 0)) {
        // Install probe ip range entry to t1
        clock_gettime(CLOCK_REALTIME, &start_time);
        if (PIPR_ENTRY_COUNT - pipr_entry_idx < IP_RANGE_TABLE_SIZE) {
            // The pipr table can not be loaded fully this time
            batch_size = PIPR_ENTRY_COUNT - pipr_entry_idx;
            // We add an extra entry in the last slot to ensure the correctness
            pipr_entry.start = IP_PLACEHOLDER;
            pipr_entry.end = pipr_entry.start + (entry_size - 1);
            probe_ip_range_table_install(iswitch, 1,
                                         IP_RANGE_TABLE_SIZE - 1, &pipr_entry);
        }
        else {
            batch_size = IP_RANGE_TABLE_SIZE;
        }
        probe_ip_range_table_install_batch(iswitch, 1, 0, batch_size,
                                        &PIPR_ENTRIES[pipr_entry_idx]);
        pipr_entry_idx += batch_size;
        not_completed += 1;
        printf("Debug: %lu probe ip range entries are left for port %hu\n",
               PIPR_ENTRY_COUNT - pipr_entry_idx,
               iconf->probe_port_range.end - port_range_size + 1);
        if (pipr_entry_idx == PIPR_ENTRY_COUNT) {
            // The pipr entries are all loaded
            if (port_range_size != 0) {
                // The current port is probed, considering the next probe port
                // in the range
                port_range_size -= 1;
            }
            if (port_range_size != 0) {
                // The whole port range is probed
                pipr_entry_idx = 0;
            }
        }
        clock_gettime(CLOCK_REALTIME, &current_time);
        printf("Debug: Install probe ip range "
               "entries into t1 within %f seconds\n",
               ((current_time.tv_sec - start_time.tv_sec) * 1000000000.0 + \
               current_time.tv_nsec - start_time.tv_nsec) / 1000000000.0);
    }

    // Configure the probe port
    probe_port_stride_config(iswitch,
        (uint16_t)ceil(PIPR_ENTRY_COUNT * 1.0 / IP_RANGE_TABLE_SIZE));
    probe_port_config(iswitch, iconf->probe_port_range.start);

    imap_status = creat_update_notifying_channel(&update_channel);
    if (imap_status == 0) {
        printf("ichannel: The update notifying channel "
               "is created successfully!\n");
    }
    else {
        printf("ichannel: The update notifying channel "
               "is not created successfully!\n");
    }

    clock_gettime(CLOCK_REALTIME, &start_time);
#if __PROBE_TYPE__ == PROBE_TYPE_SYN_PROBER
    imap_status = send_syn_temp_to_switch();
#elif __PROBE_TYPE__ == PROBE_TYPE_ICMP_PROBER
    imap_status = send_icmp_temp_to_switch();
#endif
    if (imap_status == 0) {
        printf("ichannel: The template packets are "
               "sent to the data plane of IMap\n");
    }
    else {
        printf("ichannel: The template packets can not "
               "be sent to the data plane of IMap\n");
    }
    clock_gettime(CLOCK_REALTIME, &current_time);
    printf("Send template packets into the data plane within %f seconds\n",
           ((current_time.tv_sec - start_time.tv_sec) * 1000000000.0 + \
            current_time.tv_nsec - start_time.tv_nsec) / 1000000000.0);

    clock_gettime(CLOCK_REALTIME, &start_time);

	/* Receive packet */
    while (not_completed != 0) {
        imap_status = recv_update_notification(&update_channel);
        if (imap_status == 0) {
            // printf("Debug: pipr idx %u\n", update_channel.pipr_idx);
            // clock_gettime(CLOCK_REALTIME, &current_time);
            // printf("The probe packets are all sent within %f seconds\n",
            //        ((current_time.tv_sec - start_time.tv_sec) * 1000000000.0 + \
            //         current_time.tv_nsec - start_time.tv_nsec) / 1000000000.0);
            printf("Debug: probe table %hhu has been probed\n",
                   update_channel.probe_table);
            not_completed -= 1;
            if (pipr_entry_idx == PIPR_ENTRY_COUNT && port_range_size == 0) {
                // The probe space has been depoyed into the data plane
                // totally, and enter the next notification receiving loop.
                continue;
            }
            probe_ip_range_table_reset(iswitch, update_channel.probe_table);
            // Employ "multiplicative group of integers modulo n" again
            if (PIPR_ENTRY_COUNT - pipr_entry_idx < IP_RANGE_TABLE_SIZE) {
                // The pipr table can not be loaded fully this time
                batch_size = PIPR_ENTRY_COUNT - pipr_entry_idx;
                // We add an extra entry in the last slot to ensure the correctness
                pipr_entry.start = IP_PLACEHOLDER;
                pipr_entry.end = pipr_entry.start + (entry_size - 1);
                probe_ip_range_table_install(iswitch,
                                             update_channel.probe_table,
                                             IP_RANGE_TABLE_SIZE - 1, 
                                             &pipr_entry);
            }
            else {
                batch_size = IP_RANGE_TABLE_SIZE;
            }
            probe_ip_range_table_install_batch(iswitch,
                                               update_channel.probe_table, 0,
                                               batch_size,
                                               &PIPR_ENTRIES[pipr_entry_idx]);
            pipr_entry_idx += batch_size;
            not_completed += 1;
            printf("Debug: %lu probe ip range entries are left for port %hu\n",
                   PIPR_ENTRY_COUNT - pipr_entry_idx,
                   iconf->probe_port_range.end - port_range_size + 1);
            if (pipr_entry_idx == PIPR_ENTRY_COUNT) {
                // The pipr entries are all loaded
                if (port_range_size != 0) {
                    // The current port is probed, considering the next probe
                    // port in the range
                    port_range_size -= 1;
                }
                if (port_range_size != 0) {
                    // The whole port range is probed
                    pipr_entry_idx = 0;
                }
            }
        }
        else {
            printf("ichannel: The update notification is not received\n");
        }
    }

    clock_gettime(CLOCK_REALTIME, &current_time);
    printf("The probe packets are all sent within %f seconds\n",
           ((current_time.tv_sec - start_time.tv_sec) * 1000000000.0 + \
            current_time.tv_nsec - start_time.tv_nsec) / 1000000000.0);

    printf("Waiting %u seconds for receiving "
           "probe responsing packets\n", iconf->waiting_time);

    sleep(iconf->waiting_time);

    imap_status = send_flush_request_to_switch();
    if (imap_status == 0) {
        printf("ichannel: The flush request packet is "
               "sent to the data plane of IMap\n");
    }
    else {
        printf("ichannel: The flush request packet can not "
               "be sent to the data plane of IMap\n");
    }

    printf("The scan task is completed!\n");
}

int main(int argc, char *argv[]) {
    int imap_status = 0;
    imap_conf_t iconf;
    iswitch_t iswitch;
    probe_entry_t *probe_space_entries;
    uint32_t probe_space_entries_count;
    // Parse cmd options
    parse_options(&iconf, argc, argv);

    config_file_parse(iconf.config_filename, 
                      &probe_space_entries, 
                      &probe_space_entries_count);

    // The configuration iconf.probe_period can further be configured
    //based on the network utilization
    imap_status = launch_iswitch(&iswitch, FORWARD_LIST, ARRLEN(FORWARD_LIST));
    if (imap_status == 0) {
        printf("iswitch: The data plane of IMap is launched correctly!\n");
    }
    else {
        printf("iswitch: The data plane of IMap "
               "is not launched correctly!\n");
    }

    // Configure the probe period
    probe_period_config(&iswitch, iconf.probe_period);

    start_scanner(&iconf, &iswitch, probe_space_entries, 
                  probe_space_entries_count);

    // while (1);

    return 0;
}
