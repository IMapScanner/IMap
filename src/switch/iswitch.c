/*************************************************************************
	> File Name: iswitch.c
	> Author: Guanyu Li
	> Mail: dracula.guanyu.li@gmail.com
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Data plane (Tofino) control interfaces for IMap
 ************************************************************************/

#include "../iconfig.h"
#include "iswitch.h"
#include <unistd.h>

static void switchd_setup(bf_switchd_context_t *switchd_ctx) {
    char conf_file[256];
    char bf_sysfs_fname[128] = "/sys/class/bf/bf0/device";
    FILE *fd;

    switchd_ctx->install_dir = getenv("SDE_INSTALL");
    sprintf(conf_file, "%s%s",
            getenv("SDE_INSTALL"), "/share/p4/targets/tofino/imap.conf");
    switchd_ctx->conf_file = conf_file;
    switchd_ctx->running_in_background = true;
    switchd_ctx->dev_sts_thread = true;
    switchd_ctx->dev_sts_port = 7777;

    /* Determine if kernel mode packet driver is loaded */
    strncat(bf_sysfs_fname, "/dev_add",
            sizeof(bf_sysfs_fname) - 1 - strlen(bf_sysfs_fname));
    printf("bf_sysfs_fname %s\n", bf_sysfs_fname);
    fd = fopen(bf_sysfs_fname, "r");
    if (fd != NULL) {
        /* override previous parsing if bf_kpkt KLM was loaded */
        printf("kernel mode packet driver present, forcing kpkt option!\n");
        switchd_ctx->kernel_pkt = true;
        fclose(fd);
    }

    assert(bf_switchd_lib_init(switchd_ctx) == BF_SUCCESS);
    printf("\nbf_switchd is initialized correctly!\n");
}

static void bfrt_setup(const bf_rt_target_t *dev_tgt,
                       const bf_rt_info_hdl **bfrt_info,
                       bf_rt_session_hdl **session) {
    bf_status_t bf_status;

    // Get bfrtInfo object from dev_id and p4 program name
    bf_status = bf_rt_info_get(dev_tgt->dev_id, "imap", bfrt_info);
    assert(bf_status == BF_SUCCESS);
    // Create a session object
    bf_status = bf_rt_session_create(session);
    assert(bf_status == BF_SUCCESS);
    printf("bfrt_info is got and session is created correctly!\n");
}

static void port_setup(const bf_rt_target_t *dev_tgt,
                       const switch_port_t *port_list,
                       const uint8_t port_count) {
    bf_status_t bf_status;

    // Add and enable ports
    for (unsigned int idx = 0; idx < port_count; idx++) {
        bf_pal_front_port_handle_t port_hdl;
        bf_status = bf_pm_port_str_to_hdl_get(dev_tgt->dev_id,
                                              port_list[idx].fp_port,
                                              &port_hdl);
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_pm_port_add(dev_tgt->dev_id, &port_hdl,
                                   BF_SPEED_40G, BF_FEC_TYP_NONE);
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_pm_port_enable(dev_tgt->dev_id, &port_hdl);
        assert(bf_status == BF_SUCCESS);
        printf("Port %s is enabled successfully!\n", port_list[idx].fp_port);
    }
}

static void result_server_port_setup(const bf_rt_target_t *dev_tgt,
                                     const bf_dev_port_t result_server_port) {
    bf_status_t bf_status;

    // Add and enable ports
    bf_pal_front_port_handle_t port_hdl;
    bf_status = bf_pm_port_dev_port_to_front_panel_port_get(dev_tgt->dev_id,
                                                            result_server_port,
                                                            &port_hdl);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_pm_port_add(dev_tgt->dev_id, &port_hdl,
                               BF_SPEED_40G, BF_FEC_TYP_NONE);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_pm_port_enable(dev_tgt->dev_id, &port_hdl);
    assert(bf_status == BF_SUCCESS);
    printf("Result server port (%u) is enabled "
           "successfully!\n", result_server_port);
}

static void result_server_multicast_setup(const bf_rt_target_t *dev_tgt,
                                          const bf_rt_info_hdl *bfrt_info) {
    bf_status_t bf_status;
    bf_mc_session_hdl_t mc_session;
    bf_mc_mgrp_hdl_t mc_mgrp;
    bf_mc_node_hdl_t mc_node;
    bf_mc_port_map_t mc_port_map;
    bf_mc_lag_map_t mc_lag_map;

    bf_status = bf_mc_create_session(&mc_session);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_mgrp_create(mc_session, dev_tgt->dev_id,
                                  RESULT_SERVER_MC_GID, &mc_mgrp);
    assert(bf_status == BF_SUCCESS);

    BF_MC_PORT_MAP_INIT(mc_port_map);
    BF_MC_LAG_MAP_INIT(mc_lag_map);

    BF_MC_PORT_MAP_SET(mc_port_map, RESULT_SERVER_PORT);

    // Rid set to 0
    bf_status = bf_mc_node_create(mc_session, dev_tgt->dev_id, 0,
                                  mc_port_map, mc_lag_map, &mc_node);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_associate_node(mc_session, dev_tgt->dev_id,
                                     mc_mgrp, mc_node, false,  0);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_complete_operations(mc_session);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_destroy_session(mc_session);
    assert(bf_status == BF_SUCCESS);
    printf("Muticast for cloning to CPU is set up correctly!\n");
}

static void update_notifying_mirror_setup(const bf_rt_target_t *dev_tgt) {
    p4_pd_status_t pd_status;
    p4_pd_sess_hdl_t mirror_session;
    p4_pd_dev_target_t pd_dev_tgt = { dev_tgt->dev_id, dev_tgt->pipe_id };
    p4_pd_mirror_session_info_t mirror_session_info = {
        .type        = PD_MIRROR_TYPE_NORM, // Not sure
        .dir         = PD_DIR_EGRESS,
        .id          = UPDATE_NOTIFY_MIRROR_SID,
        .egr_port    = CPU_PORT,
        .egr_port_v  = true,
        .max_pkt_len = 16384 // Refer to example in Barefoot Academy
    };

    pd_status = p4_pd_client_init(&mirror_session);
    assert(pd_status == BF_SUCCESS);

    // p4_pd_mirror_session_create() will enable the session by default
    pd_status = p4_pd_mirror_session_create(mirror_session, pd_dev_tgt,
                                            &mirror_session_info);
    assert(pd_status == BF_SUCCESS);
}

static void forward_table_setup(const bf_rt_target_t *dev_tgt,
                                const bf_rt_info_hdl *bfrt_info,
                                const bf_rt_table_hdl **forward_table,
                                forward_table_info_t *forward_table_info,
                                const switch_port_t *forward_list,
                                const uint8_t forward_count) {
    bf_status_t bf_status;

    // Get table object from name
    bf_status = bf_rt_table_from_name_get(bfrt_info,
                                          "SwitchIngress.ti_forward",
                                          forward_table);
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*forward_table,
                                         &forward_table_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*forward_table,
                                          &forward_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(*forward_table, "hdr.ethernet.dst_mac",
                                       &forward_table_info->kid_dst_mac);
    assert(bf_status == BF_SUCCESS);

    // Get action Ids for action a_unicast
    bf_status = bf_rt_action_name_to_id(*forward_table,
                                        "SwitchIngress.ai_unicast",
                                        &forward_table_info->aid_unicast);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_action_name_to_id(*forward_table,
                                        "SwitchIngress.ai_broadcast",
                                        &forward_table_info->aid_broadcast);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_action_name_to_id(*forward_table,
                                        "SwitchIngress.ai_drop",
                                        &forward_table_info->aid_drop);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for data field
    bf_status = bf_rt_data_field_id_with_action_get(
        *forward_table, "port",
        forward_table_info->aid_unicast, &forward_table_info->did_port
    );
    assert(bf_status == BF_SUCCESS);

    //                                       //
    // Set up the multicast for ai_broadcast //
    //                                       //

    bf_status = bf_mc_create_session(&forward_table_info->mc_session);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_mgrp_create(forward_table_info->mc_session,
                                  dev_tgt->dev_id,
                                  BROADCAST_MC_GID,
                                  &forward_table_info->mc_mgrp);
    assert(bf_status == BF_SUCCESS);

    BF_MC_PORT_MAP_INIT(forward_table_info->mc_port_map);
    BF_MC_LAG_MAP_INIT(forward_table_info->mc_lag_map);

    for (unsigned idx = 0; idx < forward_count; idx++) {
        bf_dev_port_t dev_port;
        bf_status = bf_pm_port_str_to_dev_port_get(
            dev_tgt->dev_id, (char *)forward_list[idx].fp_port, &dev_port
        );
        assert(bf_status == BF_SUCCESS);
        BF_MC_PORT_MAP_SET(forward_table_info->mc_port_map, dev_port);
    }

    // Rid set to 0
    bf_status = bf_mc_node_create(forward_table_info->mc_session,
                                  dev_tgt->dev_id, 0,
                                  forward_table_info->mc_port_map,
                                  forward_table_info->mc_lag_map,
                                  &forward_table_info->mc_node);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_associate_node(forward_table_info->mc_session,
                                     dev_tgt->dev_id,
                                     forward_table_info->mc_mgrp,
                                     forward_table_info->mc_node,
                                     false,  0);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_complete_operations(forward_table_info->mc_session);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_destroy_session(forward_table_info->mc_session);
    assert(bf_status == BF_SUCCESS);
}

static void forward_table_entry_add(const bf_rt_target_t *dev_tgt,
                                    const bf_rt_session_hdl *session,
                                    const bf_rt_table_hdl *forward_table,
                                    forward_table_info_t *forward_table_info,
                                    forward_table_entry_t *forward_entry) {
    bf_status_t bf_status;

    // Reset key before use
    bf_rt_table_key_reset(forward_table, &forward_table_info->key);

    // Fill in the Key object
    bf_status = bf_rt_key_field_set_value_lpm(forward_table_info->key,
                                              forward_table_info->kid_dst_mac,
                                              forward_entry->dst_mac,
                                              forward_entry->match_length);
    assert(bf_status == BF_SUCCESS);

    if (strcmp(forward_entry->action, "ai_unicast") == 0) {
        // Reset data before use
        bf_rt_table_action_data_reset(forward_table,
                                      forward_table_info->aid_unicast,
                                      &forward_table_info->data);
        // Fill in the Data object
        bf_status = bf_rt_data_field_set_value(forward_table_info->data,
                                               forward_table_info->did_port,
                                               forward_entry->egress_port);
        assert(bf_status == BF_SUCCESS);
    }
    else if (strcmp(forward_entry->action, "ai_broadcast") == 0) {
        bf_rt_table_action_data_reset(forward_table,
                                      forward_table_info->aid_broadcast,
                                      &forward_table_info->data);
    }

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(forward_table, session, dev_tgt,
                                      forward_table_info->key,
                                      forward_table_info->data);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);
}

static void forward_table_deploy(const bf_rt_target_t *dev_tgt,
                                 const bf_rt_info_hdl *bfrt_info,
                                 const bf_rt_session_hdl *session,
                                 const switch_port_t *forward_list,
                                 const uint8_t forward_count) {
    bf_status_t bf_status;
    const bf_rt_table_hdl *forward_table = NULL;
    forward_table_info_t forward_table_info;

    // Set up the forward table
    forward_table_setup(dev_tgt, bfrt_info, &forward_table,
                        &forward_table_info, forward_list, forward_count);
    printf("Table forward is set up correctly!\n");

    // Add forward entries
    for (unsigned int idx = 0; idx < forward_count; idx++) {
        forward_table_entry_t forward_entry = {
            .match_length = 48, .action = "ai_unicast"
        };
        forward_entry.dst_mac = forward_list[idx].dst_mac;
        bf_status = bf_pm_port_str_to_dev_port_get(
            dev_tgt->dev_id,
            (char *)forward_list[idx].fp_port, &forward_entry.egress_port
        );
        assert(bf_status == BF_SUCCESS);
        forward_table_entry_add(dev_tgt, session, forward_table,
                                &forward_table_info, &forward_entry);
        printf("Add entry to forward packets with dmac "MAC_FMT" to port %s\n",
               MAC_DATA(forward_list[idx].dst_mac), forward_list[idx].fp_port);
    }

    forward_table_entry_t forward_entry = {
        .dst_mac = 0xffffffffffff, .match_length = 48,
        .action = "ai_broadcast", .egress_port = 0
    };
    forward_table_entry_add(dev_tgt, session, forward_table,
                            &forward_table_info, &forward_entry);
    printf("Add entry for broadcast packets\n");

    forward_entry.dst_mac = 0x333300000000;
    forward_entry.match_length = 16;
    forward_table_entry_add(dev_tgt, session, forward_table,
                            &forward_table_info, &forward_entry);
    printf("Add entry for IPv6 broadcast packets\n");
}

static void probe_resp_inactive_handler_table_setup(
                        const bf_rt_info_hdl *bfrt_info,
                        const bf_rt_table_hdl **handler_table,
                        probe_resp_handler_table_info_t *handler_table_info) {
    bf_status_t bf_status;

    // Get table object from name
    bf_status = bf_rt_table_from_name_get(
        bfrt_info, "SwitchIngress.ti_probe_resp_inactive_handler", handler_table
    );
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*handler_table,
                                         &handler_table_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*handler_table,
                                          &handler_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(*handler_table,
                                       "ig_md.bridged.resp_pkt_count",
                                       &handler_table_info->kid_resp_pkt_count);
    assert(bf_status == BF_SUCCESS);

    // Get action Ids
    bf_status = bf_rt_action_name_to_id(
        *handler_table, "SwitchIngress.ai_report_to_result_server",
        &handler_table_info->aid_report_to_result_server
    );
    assert(bf_status == BF_SUCCESS);
}

static void probe_resp_active_handler_table_setup(
                        const bf_rt_info_hdl *bfrt_info,
                        const bf_rt_table_hdl **handler_table,
                        probe_resp_handler_table_info_t *handler_table_info) {
    bf_status_t bf_status;

    // Get table object from name
    bf_status = bf_rt_table_from_name_get(
        bfrt_info, "SwitchIngress.ti_probe_resp_active_handler", handler_table
    );
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*handler_table,
                                         &handler_table_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*handler_table,
                                          &handler_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(*handler_table,
                                       "ig_md.bridged.resp_pkt_count",
                                       &handler_table_info->kid_resp_pkt_count);
    assert(bf_status == BF_SUCCESS);

    // Get action Ids
    bf_status = bf_rt_action_name_to_id(
        *handler_table,
        "SwitchIngress.ai_report_to_result_server_with_multicast",
        &handler_table_info->aid_report_to_result_server
    );
    assert(bf_status == BF_SUCCESS);
}

static void probe_resp_handler_table_entry_add(
                            const bf_rt_target_t *dev_tgt,
                            const bf_rt_session_hdl *session,
                            const bf_rt_table_hdl *handler_table,
                            probe_resp_handler_table_info_t *handler_table_info,
                            probe_resp_handler_table_entry_t *handler_entry) {
    bf_status_t bf_status;

    // Reset key before use
    bf_rt_table_key_reset(handler_table, &handler_table_info->key);

    // Fill in the Key object
    bf_status = bf_rt_key_field_set_value(
        handler_table_info->key,
        handler_table_info->kid_resp_pkt_count, handler_entry->resp_pkt_count
    );
    assert(bf_status == BF_SUCCESS);

    // Reset data before use
    bf_rt_table_action_data_reset(
        handler_table,
        handler_table_info->aid_report_to_result_server,
        &handler_table_info->data
    );

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(handler_table, session, dev_tgt,
                                      handler_table_info->key,
                                      handler_table_info->data);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);
}

static void probe_resp_handler_table_deploy(const bf_rt_target_t *dev_tgt,
                                            const bf_rt_info_hdl *bfrt_info,
                                            const bf_rt_session_hdl *session) {
    bf_status_t bf_status;
    const bf_rt_table_hdl *active_handler_table = NULL;
    const bf_rt_table_hdl *inactive_handler_table = NULL;
    probe_resp_handler_table_info_t active_handler_table_info;
    probe_resp_handler_table_info_t inactive_handler_table_info;

    // Set up the probe response active/inactive handler table
    probe_resp_inactive_handler_table_setup(bfrt_info, &inactive_handler_table,
                                            &inactive_handler_table_info);
    probe_resp_active_handler_table_setup(bfrt_info, &active_handler_table,
                                          &active_handler_table_info);
    printf("Table of probe response active/"
           "inactive handler is set up correctly!\n");

    // Add entries for reporting to result server (with multicast)
    probe_resp_handler_table_entry_t report_entry = {
        .resp_pkt_count = RESULT_DATABASE_SIZE_M1
    };
    probe_resp_handler_table_entry_add(dev_tgt, session,
                                       active_handler_table,
                                       &active_handler_table_info,
                                       &report_entry);
    probe_resp_handler_table_entry_add(dev_tgt, session,
                                       inactive_handler_table,
                                       &inactive_handler_table_info,
                                       &report_entry);
    printf("Add entry for reporting to result server (with multicast)\n");
}

static void editor_table_setup(const bf_rt_info_hdl *bfrt_info,
                               const bf_rt_table_hdl **editor_table,
                               editor_table_info_t *editor_table_info) {
    bf_status_t bf_status;

    // Get table object from name
    bf_status = bf_rt_table_from_name_get(bfrt_info,
                                          "SwitchEgress.te_editor_p1",
                                          editor_table);
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*editor_table,
                                         &editor_table_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*editor_table,
                                          &editor_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(*editor_table, "eg_intr_md.egress_port",
                                       &editor_table_info->kid_egress_port);
    assert(bf_status == BF_SUCCESS);

    // Get action Ids for action a_unicast
    bf_status = bf_rt_action_name_to_id(*editor_table,
                                        "SwitchEgress.ae_editor_p1",
                                        &editor_table_info->aid_editor);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for data field
    bf_status = bf_rt_data_field_id_with_action_get(
        *editor_table, "dst_mac",
        editor_table_info->aid_editor, &editor_table_info->did_dst_mac
    );
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_id_with_action_get(
        *editor_table, "pipr_sidx",
        editor_table_info->aid_editor, &editor_table_info->did_pipr_sidx
    );
    assert(bf_status == BF_SUCCESS);
}

static void editor_table_entry_add(const bf_rt_target_t *dev_tgt,
                                   const bf_rt_session_hdl *session,
                                   const bf_rt_table_hdl *editor_table,
                                   editor_table_info_t *editor_table_info,
                                   editor_table_entry_t *editor_entry) {
    bf_status_t bf_status;

    // Reset key before use
    bf_rt_table_key_reset(editor_table, &editor_table_info->key);

    // Fill in the Key object
    bf_status = bf_rt_key_field_set_value(editor_table_info->key,
                                          editor_table_info->kid_egress_port,
                                          editor_entry->egress_port);
    assert(bf_status == BF_SUCCESS);

    // Reset data before use
    bf_rt_table_action_data_reset(editor_table,
                                  editor_table_info->aid_editor,
                                  &editor_table_info->data);

    // Fill in the Data object
    bf_status = bf_rt_data_field_set_value(editor_table_info->data,
                                           editor_table_info->did_dst_mac,
                                           editor_entry->dst_mac);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_set_value(editor_table_info->data,
                                           editor_table_info->did_pipr_sidx,
                                           editor_entry->pipr_sidx);
    assert(bf_status == BF_SUCCESS);

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(editor_table, session, dev_tgt,
                                      editor_table_info->key,
                                      editor_table_info->data);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);
}

static void editor_table_deploy(const bf_rt_target_t *dev_tgt,
                                const bf_rt_info_hdl *bfrt_info,
                                const bf_rt_session_hdl *session,
                                const switch_port_t *forward_list,
                                const uint8_t forward_count) {
    bf_status_t bf_status;
    const bf_rt_table_hdl *editor_table = NULL;
    editor_table_info_t editor_table_info;

    // Set up the editor table
    editor_table_setup(bfrt_info, &editor_table, &editor_table_info);
    printf("Table of editor is set up correctly!\n");

    // Add editor entries
    for (unsigned int idx = 0; idx < forward_count; idx++) {
        editor_table_entry_t editor_entry;
        bf_status = bf_pm_port_str_to_dev_port_get(
            dev_tgt->dev_id,
            (char *)forward_list[idx].fp_port, &editor_entry.egress_port
        );
        assert(bf_status == BF_SUCCESS);
        editor_entry.dst_mac = forward_list[idx].dst_mac;
        editor_entry.pipr_sidx = idx << IP_RANGE_INDEX_PER_PORT_BITS;
        editor_table_entry_add(dev_tgt, session, editor_table,
                               &editor_table_info, &editor_entry);
        printf("Add entry for probe packets to port %s "
               "with dmac "MAC_FMT" and pipr_sidx 0x%x\n",
               forward_list[idx].fp_port,
               MAC_DATA(forward_list[idx].dst_mac), editor_entry.pipr_sidx);
    }
}

static void resultdb_table_setup(const bf_rt_info_hdl *bfrt_info,
                                 uint32_t resultdb_idx,
                                 const bf_rt_table_hdl **target_table,
                                 const bf_rt_table_hdl **result_table,
                                 resultdb_table_info_t *target_table_info,
                                 resultdb_table_info_t *result_table_info) {
    bf_status_t bf_status;

    char table_name[256];
    char action_name[256];

    // Set up target table
    sprintf(table_name,
            "SwitchEgress.te_resultdb_%u_target_accessor", resultdb_idx);
    sprintf(action_name,
            "SwitchEgress.ae_update_resultdb_%u_target", resultdb_idx);

    // Get table object from name
    bf_status = bf_rt_table_from_name_get(bfrt_info, table_name, target_table);
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*target_table,
                                         &target_table_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*target_table,
                                          &target_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(*target_table,
                                       "eg_md.bridged.resp_pkt_count",
                                       &target_table_info->kid_resp_pkt_count);
    assert(bf_status == BF_SUCCESS);

    // Get action Ids
    bf_status = bf_rt_action_name_to_id(
        *target_table, action_name, &target_table_info->aid_update_resultdb
    );
    assert(bf_status == BF_SUCCESS);

    // Set up result table
    sprintf(table_name,
            "SwitchEgress.te_resultdb_%u_result_accessor", resultdb_idx);
    sprintf(action_name,
            "SwitchEgress.ae_update_resultdb_%u_result", resultdb_idx);
    // Get table object from name
    bf_status = bf_rt_table_from_name_get(bfrt_info, table_name, result_table);
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*result_table,
                                         &result_table_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*result_table,
                                          &result_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(*result_table,
                                       "eg_md.bridged.resp_pkt_count",
                                       &result_table_info->kid_resp_pkt_count);
    assert(bf_status == BF_SUCCESS);


    // Get action Ids
    bf_status = bf_rt_action_name_to_id(
        *result_table, action_name, &result_table_info->aid_update_resultdb
    );
    assert(bf_status == BF_SUCCESS);
}

static void resultdb_table_entry_add(const bf_rt_target_t *dev_tgt,
                                     const bf_rt_session_hdl *session,
                                     uint32_t resultdb_idx,
                                     const bf_rt_table_hdl *resultdb_table,
                                     resultdb_table_info_t *resultdb_table_info,
                                     resultdb_table_entry_t *resultdb_entry) {
    bf_status_t bf_status;

    // Reset key before use
    bf_rt_table_key_reset(resultdb_table, &resultdb_table_info->key);

    // Fill in the Key object
    bf_status = bf_rt_key_field_set_value(
        resultdb_table_info->key,
        resultdb_table_info->kid_resp_pkt_count, resultdb_entry->resp_pkt_count
    );
    assert(bf_status == BF_SUCCESS);

    bf_rt_table_action_data_reset(resultdb_table,
                                  resultdb_table_info->aid_update_resultdb,
                                  &resultdb_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(resultdb_table, session, dev_tgt,
                                      resultdb_table_info->key,
                                      resultdb_table_info->data);
    assert(bf_status == BF_SUCCESS);
    bf_rt_session_complete_operations(session);
}

static void resultdb_table_deploy(const bf_rt_target_t *dev_tgt,
                                  const bf_rt_info_hdl *bfrt_info,
                                  const bf_rt_session_hdl *session) {
    bf_status_t bf_status;
    const bf_rt_table_hdl *resultdb_target_tables[RESULT_DATABASE_SIZE];
    const bf_rt_table_hdl *resultdb_result_tables[RESULT_DATABASE_SIZE];
    resultdb_table_info_t resultdb_target_tables_info[RESULT_DATABASE_SIZE];
    resultdb_table_info_t resultdb_result_tables_info[RESULT_DATABASE_SIZE];

    for (int db_idx = 0; db_idx < RESULT_DATABASE_SIZE; db_idx++){
        // Set up resultdb tables
        resultdb_table_setup(bfrt_info, db_idx,
                             &resultdb_target_tables[db_idx],
                             &resultdb_result_tables[db_idx],
                             &resultdb_target_tables_info[db_idx],
                             &resultdb_result_tables_info[db_idx]);
        printf("Tables of result database %u is set up correctly!\n", db_idx);

        resultdb_table_entry_t resultdb_table_entry = {
            .resp_pkt_count = db_idx
        };
        resultdb_table_entry_add(dev_tgt, session, db_idx,
                                 resultdb_target_tables[db_idx],
                                 &resultdb_target_tables_info[db_idx],
                                 &resultdb_table_entry);
        printf("Add entry to update result database %u's target!\n", db_idx);
        resultdb_table_entry_add(dev_tgt, session, db_idx,
                                 resultdb_result_tables[db_idx],
                                 &resultdb_result_tables_info[db_idx],
                                 &resultdb_table_entry);
        printf("Add entry to update result database %u's result!\n", db_idx);
    }
}

static void register_setup(const bf_rt_info_hdl *bfrt_info,
                           const char *reg_name,
                           const char *value_field_name,
                           const bf_rt_table_hdl **reg,
                           register_info_t *reg_info) {
    bf_status_t bf_status;
    char reg_value_field_name[64];

    // Get table object from name
    bf_status = bf_rt_table_from_name_get(bfrt_info, reg_name, reg);
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*reg, &reg_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*reg, &reg_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(*reg, "$REGISTER_INDEX",
                                       &reg_info->kid_register_index);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for data field
    strcpy(reg_value_field_name, reg_name);
    if (value_field_name == NULL) {
        strcat(reg_value_field_name, ".f1");
    }
    else {
        strcat(reg_value_field_name, ".");
        strcat(reg_value_field_name, value_field_name);
    }
    bf_status = bf_rt_data_field_id_get(*reg, reg_value_field_name,
                                        &reg_info->did_value);
    assert(bf_status == BF_SUCCESS);
}

static void register_write(const bf_rt_target_t *dev_tgt,
                           const bf_rt_session_hdl *session,
                           const bf_rt_table_hdl *reg,
                           register_info_t *reg_info,
                           register_entry_t *reg_entry) {
    bf_status_t bf_status;

    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // Fill in the Key and Data object
    bf_status = bf_rt_key_field_set_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          reg_entry->register_index);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_set_value(reg_info->data,
                                           reg_info->did_value,
                                           reg_entry->value);
    assert(bf_status == BF_SUCCESS);

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(reg, session, dev_tgt,
                                      reg_info->key, reg_info->data);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);
}

static void register_write_no_wait(const bf_rt_target_t *dev_tgt,
                                   const bf_rt_session_hdl *session,
                                   const bf_rt_table_hdl *reg,
                                   register_info_t *reg_info,
                                   register_entry_t *reg_entry) {
    bf_status_t bf_status;

    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // Fill in the Key and Data object
    bf_status = bf_rt_key_field_set_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          reg_entry->register_index);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_set_value(reg_info->data,
                                           reg_info->did_value,
                                           reg_entry->value);
    assert(bf_status == BF_SUCCESS);

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(reg, session, dev_tgt,
                                      reg_info->key, reg_info->data);
    assert(bf_status == BF_SUCCESS);
    // bf_status = bf_rt_session_complete_operations(session);
    // assert(bf_status == BF_SUCCESS);
}

static void register_read(const bf_rt_target_t *dev_tgt,
                          const bf_rt_session_hdl *session,
                          const bf_rt_table_hdl *reg,
                          register_info_t *reg_info,
                          register_entry_t *reg_entry) {
    bf_status_t bf_status;

    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // Fill in the Key object
    bf_status = bf_rt_key_field_set_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          reg_entry->register_index);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_set_value(reg_info->data,
                                           reg_info->did_value,
                                           reg_entry->value);
    assert(bf_status == BF_SUCCESS);

    // Call table entry add API
    bf_status = bf_rt_table_entry_get(reg, session, dev_tgt, reg_info->key,
                                      reg_info->data, ENTRY_READ_FROM_HW);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);

    // Get the real values in the Data object
    // Notice: I don't know whether bf_rt_data_field_get_value_u64_array works
    // fine here, instead bf_rt_data_field_get_value_u64_array.
    bf_status = bf_rt_data_field_get_value_u64_array_size(
        reg_info->data, reg_info->did_value, &reg_entry->value_array_size
    );
    assert(bf_status == BF_SUCCESS);
    if (reg_entry->value_array) {
        free(reg_entry->value_array);
    }
    reg_entry->value_array = (uint64_t *)malloc
                             (reg_entry->value_array_size * sizeof(uint64_t));
    bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                     reg_info->did_value,
                                                     reg_entry->value_array);
    assert(bf_status == BF_SUCCESS);
}

static void probe_period_setup(const bf_rt_info_hdl *bfrt_info,
                               probe_period_t *period_reg) {
    // Set up the probe period register
    register_setup(bfrt_info, "SwitchIngress.ri_probe_period",
                   NULL, &period_reg->reg, &period_reg->reg_info);
    printf("Register of probe period is set up correctly!\n");
}

void probe_period_config(iswitch_t *iswitch, uint32_t probe_period) {
    register_entry_t probe_period_entry;

    probe_period_entry.register_index = 0;
    probe_period_entry.value = probe_period;
    register_write(&iswitch->dev_tgt, iswitch->session, iswitch->period_reg.reg,
                   &iswitch->period_reg.reg_info, &probe_period_entry);
    printf("Register of probe period is set to "
           "%d correctly!\n", probe_period_entry.value);
}

static void probe_port_stride_setup(const bf_rt_info_hdl *bfrt_info,
                                    probe_port_stride_t *stride_reg) {
    // Set up the probe port register
    register_setup(bfrt_info, "SwitchIngress.ri_probe_port_stride",
                   NULL, &stride_reg->reg, &stride_reg->reg_info);
    printf("Register of probe port stride is set up correctly!\n");
}

void probe_port_stride_config(iswitch_t *iswitch, uint16_t probe_port_stride) {
    register_entry_t probe_port_stride_entry;

    probe_port_stride_entry.register_index = 0;
    probe_port_stride_entry.value = probe_port_stride;
    register_write(&iswitch->dev_tgt, iswitch->session, iswitch->stride_reg.reg,
                   &iswitch->stride_reg.reg_info, &probe_port_stride_entry);
    printf("Register of probe port stride is set to "
           "%hu correctly!\n", probe_port_stride_entry.value);
}

static void probe_port_setup(const bf_rt_info_hdl *bfrt_info,
                             probe_port_t *port_reg) {
    // Set up the probe port register
    register_setup(bfrt_info, "SwitchEgress.re_probe_port",
                   "probe_port", &port_reg->reg, &port_reg->reg_info);
    printf("Register of probe port is set up correctly!\n");
}

void probe_port_config(iswitch_t *iswitch, uint16_t probe_port) {
    register_entry_t probe_port_entry;

    probe_port_entry.register_index = 0;
    probe_port_entry.value = probe_port;
    register_write(&iswitch->dev_tgt, iswitch->session, iswitch->port_reg.reg,
                   &iswitch->port_reg.reg_info, &probe_port_entry);
    printf("Register of probe port is set to "
           "%hu correctly!\n", probe_port_entry.value);
}

static void probe_ip_range_table_setup(const bf_rt_info_hdl *bfrt_info,
                                       probe_ip_range_table_t *pipr_table_t0,
                                       probe_ip_range_table_t *pipr_table_t1) {
    // Set up the probe ip range registers
    register_setup(bfrt_info, "SwitchEgress.re_pipr_t0_pidx", NULL,
                   &pipr_table_t0->pipr_pidx_reg,
                   &pipr_table_t0->pipr_pidx_reg_info);
    register_setup(bfrt_info, "SwitchEgress.re_pipr_t1_pidx", NULL,
                   &pipr_table_t1->pipr_pidx_reg,
                   &pipr_table_t1->pipr_pidx_reg_info);
    register_setup(bfrt_info, "SwitchEgress.re_pipr_t0_start", NULL,
                   &pipr_table_t0->pipr_start_reg,
                   &pipr_table_t0->pipr_start_reg_info);
    register_setup(bfrt_info, "SwitchEgress.re_pipr_t1_start", NULL,
                   &pipr_table_t1->pipr_start_reg,
                   &pipr_table_t1->pipr_start_reg_info);
    register_setup(bfrt_info, "SwitchEgress.re_pipr_t0_end", NULL,
                   &pipr_table_t0->pipr_end_reg,
                   &pipr_table_t0->pipr_end_reg_info);
    register_setup(bfrt_info, "SwitchEgress.re_pipr_t1_end", NULL,
                   &pipr_table_t1->pipr_end_reg,
                   &pipr_table_t1->pipr_end_reg_info);
#if __IP_TYPE__ == 6
    register_setup(bfrt_info, "SwitchEgress.re_pip_prefix_1", NULL,
                   &pipr_table->pip_prefix_1_reg,
                   &pipr_table->pip_prefix_1_reg_info);
    register_setup(bfrt_info, "SwitchEgress.re_pip_prefix_2", NULL,
                   &pipr_table->pip_prefix_2_reg,
                   &pipr_table->pip_prefix_2_reg_info);
    register_setup(bfrt_info, "SwitchEgress.re_pip_prefix_3", NULL,
                   &pipr_table->pip_prefix_3_reg,
                   &pipr_table->pip_prefix_3_reg_info);
#endif
    printf("Registers of pipr (probe ip range) are set up correctly!\n");
}

void probe_ip_range_table_reset(iswitch_t *iswitch, const uint8_t probe_table) {
    probe_ip_range_table_t *pipr_table;
    register_entry_t pipr_pidx_entry;

    if (probe_table == 0) {
        pipr_table = &iswitch->pipr_table_t0;
    }
    else {
        pipr_table = &iswitch->pipr_table_t1;
    }

    for (uint16_t idx = 0; idx < (1 << IP_RANGE_INDEX_PORT_BITS); idx++) {
        pipr_pidx_entry.register_index = idx;
        pipr_pidx_entry.value = 0;
        register_write(&iswitch->dev_tgt, iswitch->session,
                       pipr_table->pipr_pidx_reg,
                       &pipr_table->pipr_pidx_reg_info, &pipr_pidx_entry);
    }
}

void probe_ip_range_table_install(iswitch_t *iswitch,
                                  const uint8_t probe_table,
                                  const uint32_t pipr_idx,
                                  const probe_entry_t *probe_entry) {
    probe_ip_range_table_t *pipr_table;
    register_entry_t pipr_entry;

    if (probe_table == 0) {
        pipr_table = &iswitch->pipr_table_t0;
    }
    else {
        pipr_table = &iswitch->pipr_table_t1;
    }

    // Write probe ip range
    pipr_entry.register_index = pipr_idx;
    // Register re_pipr_start
    pipr_entry.value = probe_entry->start;
    register_write(&iswitch->dev_tgt, iswitch->session,
                   pipr_table->pipr_start_reg,
                   &pipr_table->pipr_start_reg_info, &pipr_entry);
    // Register re_pipr_end
    pipr_entry.value = probe_entry->end;
    register_write(&iswitch->dev_tgt, iswitch->session,
                   pipr_table->pipr_end_reg,
                   &pipr_table->pipr_end_reg_info, &pipr_entry);
#if __IP_TYPE__ == 6
    // TODO: Next codes need to be updated
    // Register re_pip_prefix_1
    pipr_entry.value = 0xfe800000;
    register_write(&iswitch->dev_tgt, iswitch->session,
                    pipr_table->pip_prefix_1_reg,
                    &pipr_table->pip_prefix_1_reg_info, &pipr_entry);
    // Register re_pip_prefix_2
    pipr_entry.value = 0x00000000;
    register_write(&iswitch->dev_tgt, iswitch->session,
                    pipr_table->pip_prefix_2_reg,
                    &pipr_table->pip_prefix_2_reg_info, &pipr_entry);
    // Register re_pip_prefix_3
    pipr_entry.value = 0x6a91d0ff;
    register_write(&iswitch->dev_tgt, iswitch->session,
                    pipr_table->pip_prefix_3_reg,
                    &pipr_table->pip_prefix_3_reg_info, &pipr_entry);
#endif
    // printf("Registers of pipr (probe ip range) are set successfully!\n");
}

void probe_ip_range_table_install_batch(iswitch_t *iswitch,
                                        const uint8_t probe_table,
                                        const uint32_t pipr_idx_start,
                                        const uint32_t batch_size,
                                        const probe_entry_t *probe_entries) {
    bf_status_t bf_status;
    probe_ip_range_table_t *pipr_table;
    register_entry_t pipr_entry;

    if (probe_table == 0) {
        pipr_table = &iswitch->pipr_table_t0;
    }
    else {
        pipr_table = &iswitch->pipr_table_t1;
    }

    // Start batch operation
    bf_status = bf_rt_begin_batch(iswitch->session);
    assert(bf_status == BF_SUCCESS);

    // Write probe ip ranges
    for (uint32_t idx = 0; idx < batch_size; idx++) {
        pipr_entry.register_index = pipr_idx_start + idx;
        // Register re_pipr_start
        pipr_entry.value = probe_entries[idx].start;
        register_write_no_wait(&iswitch->dev_tgt, iswitch->session,
                               pipr_table->pipr_start_reg,
                               &pipr_table->pipr_start_reg_info, &pipr_entry);
        // Register re_pipr_end
        pipr_entry.value = probe_entries[idx].end;
        register_write_no_wait(&iswitch->dev_tgt, iswitch->session,
                               pipr_table->pipr_end_reg,
                               &pipr_table->pipr_end_reg_info, &pipr_entry);
    }

    bf_status = bf_rt_end_batch(iswitch->session, true);
    assert(bf_status == BF_SUCCESS);

    //TODO: handle IPv6
}

// void probe_ip_range_table_fetch(iswitch_t *iswitch,
//                                 const uint8_t probe_table,
//                                 const uint32_t pipr_idx) {
//     bf_status_t bf_status;
//     probe_ip_range_table_t *pipr_table;
//     register_entry_t pipr_entry;

//     if (probe_table == 0) {
//         pipr_table = &iswitch->pipr_table_t0;
//     }
//     else {
//         pipr_table = &iswitch->pipr_table_t1;
//     }

//     pipr_entry.register_index = pipr_idx;
//     printf("Debug: pipr_idx %u, ", pipr_idx);
//     register_read(&iswitch->dev_tgt, iswitch->session,
//                   pipr_table->pipr_start_reg,
//                   &pipr_table->pipr_start_reg_info, &pipr_entry);
//     printf("start %lx, ", pipr_entry.value_array[2]);
//     register_read(&iswitch->dev_tgt, iswitch->session,
//                   pipr_table->pipr_end_reg,
//                   &pipr_table->pipr_end_reg_info, &pipr_entry);
//     printf("end %lx\n", pipr_entry.value_array[2]);
// }

int launch_iswitch(iswitch_t *iswitch,
                   const switch_port_t *forward_list,
                   const uint8_t forward_count) {
    bf_switchd_context_t *switchd_ctx;
    bf_rt_target_t *dev_tgt = &iswitch->dev_tgt;
    const bf_rt_info_hdl *bfrt_info = NULL;
    bf_rt_session_hdl **session = &iswitch->session;

    dev_tgt->dev_id = 0;
    dev_tgt->pipe_id = BF_DEV_PIPE_ALL;

    // Initialize and set the bf_switchd
    switchd_ctx = (bf_switchd_context_t *)
                  calloc(1, sizeof(bf_switchd_context_t));
    if (switchd_ctx == NULL) {
        printf("Cannot allocate switchd context\n");
        return -1;
    }
    switchd_setup(switchd_ctx);

    // Get BfRtInfo and create the bf_runtime session
    bfrt_setup(dev_tgt, &bfrt_info, session);

    // Set up the forward ports of the switch
    port_setup(dev_tgt, forward_list, forward_count);

    // Set up the result server port of the switch
    result_server_port_setup(dev_tgt, RESULT_SERVER_PORT);

    // Set up the result server multicat
    result_server_multicast_setup(dev_tgt, bfrt_info);

    // Set up the update notifying mirror
    update_notifying_mirror_setup(dev_tgt);

    // Set up and add entries for the forward table
    forward_table_deploy(dev_tgt, bfrt_info, *session,
                         forward_list, forward_count);

    // Set up and add entries for the active/inactive handler table
    probe_resp_handler_table_deploy(dev_tgt, bfrt_info, *session);

    // Set up and add entries for the editor table
    editor_table_deploy(dev_tgt, bfrt_info, *session,
                        forward_list, forward_count);

    // Set up and add entries for the response vector tables
    resultdb_table_deploy(dev_tgt, bfrt_info, *session);

    // Set up the probe period register
    probe_period_setup(bfrt_info, &iswitch->period_reg);

    // Set up the probe port stride register
    probe_port_stride_setup(bfrt_info, &iswitch->stride_reg);

    // Set up the probe port register
    probe_port_setup(bfrt_info, &iswitch->port_reg);

    // Set up the probe ip range registers
    probe_ip_range_table_setup(bfrt_info,
                               &iswitch->pipr_table_t0,
                               &iswitch->pipr_table_t1);

    return 0;
}