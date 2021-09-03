/*************************************************************************
	> File Name: iswitch.h
	> Author: Guanyu Li
	> Mail: dracula.guanyu.li@gmail.com
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Barefoot switch control interfaces for IMap
 ************************************************************************/

#ifndef _ISWITCH_H
#define _ISWITCH_H

#include <bf_switchd/bf_switchd.h>
#include <bf_rt/bf_rt_init.h>
#include <bf_rt/bf_rt_session.h>
// #include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.h>
#include <bf_rt/bf_rt_table_data.h>
#include <bf_rt/bf_rt_table.h>
#include <bf_pm/bf_pm_intf.h>
#include <mc_mgr/mc_mgr_intf.h>
#include <tofino/pdfixed/pd_conn_mgr.h>
#include <tofino/pdfixed/pd_mirror.h>

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_DATA(d) *((uint8_t *)&d + 5), *((uint8_t *)&d + 4), \
                    *((uint8_t *)&d + 3), *((uint8_t *)&d + 2), \
                    *((uint8_t *)&d + 1), *((uint8_t *)&d + 0)

typedef struct forward_table_info_s {
    // Key field ids
    bf_rt_id_t kid_dst_mac;
    // Action Ids
    bf_rt_id_t aid_unicast;
    bf_rt_id_t aid_broadcast;
    bf_rt_id_t aid_drop;
    // Data field Ids for ai_unicast
    bf_rt_id_t did_port;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    // Multicast info
    bf_mc_session_hdl_t mc_session;
    bf_mc_mgrp_hdl_t mc_mgrp;
    bf_mc_node_hdl_t mc_node;
    bf_mc_port_map_t mc_port_map;
    bf_mc_lag_map_t mc_lag_map;
} forward_table_info_t;

typedef struct forward_table_entry_s {
    // Key value
    uint64_t dst_mac;
    // Match length (for LPM)
    uint16_t match_length;
    // Action
    char action[16];
    // Data value
    bf_dev_port_t egress_port;
} forward_table_entry_t;

typedef struct probe_resp_handler_table_info_s {
    // Key field ids
    bf_rt_id_t kid_resp_pkt_count;
    // Action Ids
    bf_rt_id_t aid_report_to_result_server;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
} probe_resp_handler_table_info_t;

typedef struct probe_resp_handler_table_entry_s {
    // Key value
    uint64_t resp_pkt_count;
} probe_resp_handler_table_entry_t;

typedef struct editor_table_info_s {
    // Key field ids
    bf_rt_id_t kid_egress_port;
    // Action Ids
    bf_rt_id_t aid_editor;
    // Data field Ids for ai_unicast
    bf_rt_id_t did_dst_mac;
    bf_rt_id_t did_pipr_sidx; // Probe IP Range Start Index
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
} editor_table_info_t;

typedef struct editor_table_entry_s {
    // Key value
    bf_dev_port_t egress_port;
    // Data value
    uint64_t dst_mac;
    uint32_t pipr_sidx;
} editor_table_entry_t;

typedef struct resultdb_table_info_s {
    // Key field ids
    bf_rt_id_t kid_resp_pkt_count;

    // Action Ids
    bf_rt_id_t aid_update_resultdb;

    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
} resultdb_table_info_t;

typedef struct resultdb_table_entry_s {
    // Key value
    uint64_t resp_pkt_count;
} resultdb_table_entry_t;

typedef struct register_info_s {
    // Key field ids
    bf_rt_id_t kid_register_index;
    // Data field Ids for register table
    bf_rt_id_t did_value;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
} register_info_t;

typedef struct register_entry_s {
    // Key value
    uint32_t register_index;
    // Data value
    uint32_t value;
    uint32_t value_array_size;
    uint64_t *value_array;
} register_entry_t;

typedef struct probe_period_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} probe_period_t;

typedef struct probe_port_stride_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} probe_port_stride_t;

typedef struct probe_port_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} probe_port_t;

typedef struct probe_ip_range_table_s {
    const bf_rt_table_hdl *pipr_start_reg;
    const bf_rt_table_hdl *pipr_end_reg;
    const bf_rt_table_hdl *pipr_pidx_reg;
#if __IP_TYPE__ == 6
    const bf_rt_table_hdl *pip_prefix_1_reg;
    const bf_rt_table_hdl *pip_prefix_2_reg;
    const bf_rt_table_hdl *pip_prefix_3_reg;
#endif
    register_info_t pipr_start_reg_info;
    register_info_t pipr_end_reg_info;
    register_info_t pipr_pidx_reg_info;
#if __IP_TYPE__ == 6
    register_info_t pip_prefix_1_reg_info;
    register_info_t pip_prefix_2_reg_info;
    register_info_t pip_prefix_3_reg_info;
#endif
} probe_ip_range_table_t;

// typedef struct iswitch_info_s {
//     bf_status_t status;
//     bf_rt_target_t dev_tgt;
//     bf_switchd_context_t *switchd_ctx;
//     const bf_rt_info_hdl *bfrt_info;
//     const bf_rt_table_hdl *forward_table;
//     const bf_rt_table_hdl *editor_table;
//     bf_rt_session_hdl *session;
//     forward_table_info_t forward_table_info;
//     editor_table_info_t editor_table_info;
// } iswitch_info_t;

typedef struct switch_port_s {
    uint64_t dst_mac;
    char fp_port[5];
} switch_port_t;

typedef struct probe_entry_s {
    uint32_t start;
    uint32_t end;
} probe_entry_t;

typedef struct iswitch_s {
    bf_rt_target_t dev_tgt;
    bf_rt_session_hdl *session;
    probe_period_t period_reg;
    probe_port_stride_t stride_reg;
    probe_port_t port_reg;
    probe_ip_range_table_t pipr_table_t0;
    probe_ip_range_table_t pipr_table_t1;
} iswitch_t;

static void switchd_setup(bf_switchd_context_t *switchd_ctx);
static void bfrt_setup(const bf_rt_target_t *dev_tgt,
                       const bf_rt_info_hdl **bfrt_info,
                       bf_rt_session_hdl **session);
static void port_setup(const bf_rt_target_t *dev_tgt,
                       const switch_port_t *port_list,
                       const uint8_t rule_count);
static void result_server_port_setup(const bf_rt_target_t *dev_tgt,
                                     const bf_dev_port_t result_server_port);
static void result_server_multicast_setup(const bf_rt_target_t *dev_tgt,
                                          const bf_rt_info_hdl *bfrt_info);
static void update_notifying_mirror_setup(const bf_rt_target_t *dev_tgt);
static void forward_table_setup(const bf_rt_target_t *dev_tgt,
                                const bf_rt_info_hdl *bfrt_info,
                                const bf_rt_table_hdl **fwd_table,
                                forward_table_info_t *fwd_table_info,
                                const switch_port_t *forward_list,
                                const uint8_t rule_count);
static void forward_table_entry_add(const bf_rt_target_t *dev_tgt,
                                    const bf_rt_session_hdl *session,
                                    const bf_rt_table_hdl *fwd_table,
                                    forward_table_info_t *fwd_table_info,
                                    forward_table_entry_t *fwd_entry);
static void forward_table_deploy(const bf_rt_target_t *dev_tgt,
                                 const bf_rt_info_hdl *bfrt_info,
                                 const bf_rt_session_hdl *session,
                                 const switch_port_t *forward_list,
                                 const uint8_t rule_count);
static void probe_resp_active_handler_table_setup(
                        const bf_rt_info_hdl *bfrt_info,
                        const bf_rt_table_hdl **handler_table,
                        probe_resp_handler_table_info_t *handler_table_info);
static void probe_resp_inactive_handler_table_setup(
                        const bf_rt_info_hdl *bfrt_info,
                        const bf_rt_table_hdl **handler_table,
                        probe_resp_handler_table_info_t *handler_table_info);
static void probe_resp_handler_table_entry_add(
                            const bf_rt_target_t *dev_tgt,
                            const bf_rt_session_hdl *session,
                            const bf_rt_table_hdl *handler_table,
                            probe_resp_handler_table_info_t *handler_table_info,
                            probe_resp_handler_table_entry_t *handler_entry);
static void probe_resp_handler_table_deploy(const bf_rt_target_t *dev_tgt,
                                            const bf_rt_info_hdl *bfrt_info,
                                            const bf_rt_session_hdl *session);
static void editor_table_setup(const bf_rt_info_hdl *bfrt_info,
                               const bf_rt_table_hdl **edtr_table,
                               editor_table_info_t *edtr_table_info);
static void editor_table_entry_add(const bf_rt_target_t *dev_tgt,
                                   const bf_rt_session_hdl *session,
                                   const bf_rt_table_hdl *edtr_table,
                                   editor_table_info_t *edtr_table_info,
                                   editor_table_entry_t *edtr_entry);
static void editor_table_deploy(const bf_rt_target_t *dev_tgt,
                                const bf_rt_info_hdl *bfrt_info,
                                const bf_rt_session_hdl *session,
                                const switch_port_t *forward_list,
                                const uint8_t rule_count);
static void resultdb_table_setup(const bf_rt_info_hdl *bfrt_info,
                                 uint32_t resultdb_idx,
                                 const bf_rt_table_hdl **target_table,
                                 const bf_rt_table_hdl **result_table,
                                 resultdb_table_info_t *target_table_info,
                                 resultdb_table_info_t *result_table_info);
static void resultdb_table_entry_add(const bf_rt_target_t *dev_tgt,
                                     const bf_rt_session_hdl *session,
                                     uint32_t resultdb_idx,
                                     const bf_rt_table_hdl *resultdb_table,
                                     resultdb_table_info_t *resultdb_table_info,
                                     resultdb_table_entry_t *resultdb_entry);
static void resultdb_table_deploy(const bf_rt_target_t *dev_tgt,
                                 const bf_rt_info_hdl *bfrt_info,
                                 const bf_rt_session_hdl *session);
static void register_setup(const bf_rt_info_hdl *bfrt_info,
                           const char *reg_name,
                           const char *value_field_name,
                           const bf_rt_table_hdl **reg,
                           register_info_t *reg_info);
static void register_write(const bf_rt_target_t *dev_tgt,
                           const bf_rt_session_hdl *session,
                           const bf_rt_table_hdl *reg,
                           register_info_t *reg_info,
                           register_entry_t *reg_entry);
static void register_write_no_wait(const bf_rt_target_t *dev_tgt,
                                   const bf_rt_session_hdl *session,
                                   const bf_rt_table_hdl *reg,
                                   register_info_t *reg_info,
                                   register_entry_t *reg_entry);
static void register_read(const bf_rt_target_t *dev_tgt,
                          const bf_rt_session_hdl *session,
                          const bf_rt_table_hdl *reg,
                          register_info_t *reg_info,
                          register_entry_t *reg_entry);
static void probe_period_setup(const bf_rt_info_hdl *bfrt_info,
                               probe_period_t *period_reg);
void probe_period_config(iswitch_t *iswitch, uint32_t probe_period);
static void probe_port_stride_setup(const bf_rt_info_hdl *bfrt_info,
                                    probe_port_stride_t *stride_reg);
void probe_port_stride_config(iswitch_t *iswitch, uint16_t probe_port_stride);
static void probe_port_setup(const bf_rt_info_hdl *bfrt_info,
                             probe_port_t *port_reg);
void probe_port_config(iswitch_t *iswitch, uint16_t probe_port);
static void probe_ip_range_table_setup(const bf_rt_info_hdl *bfrt_info,
                                       probe_ip_range_table_t *pipr_table_t0,
                                       probe_ip_range_table_t *pipr_table_t1);
void probe_ip_range_table_reset(iswitch_t *iswitch, const uint8_t probe_table);
void probe_ip_range_table_install(iswitch_t *iswitch,
                                  const uint8_t probe_table,
                                  const uint32_t pipr_idx,
                                  const probe_entry_t *probe_entry);
void probe_ip_range_table_install_batch(iswitch_t *iswitch,
                                        const uint8_t probe_table,
                                        const uint32_t pipr_idx_start,
                                        const uint32_t batch_size,
                                        const probe_entry_t *probe_entries);
// void probe_ip_range_table_fetch(iswitch_t *iswitch,
//                                 const uint8_t probe_table,
//                                 const uint32_t pipr_idx);
int launch_iswitch(iswitch_t *iswitch,
                   const switch_port_t *forward_list,
                   const uint8_t rule_count);

#endif
