/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "context.h"
#include "event.h"
#include "timer.h"
#include "upf-sm.h"

#include "pfcp-path.h"
#include "n4-handler.h"

#include <inttypes.h>

static void pfcp_restoration(ogs_pfcp_node_t *node);
static void node_timeout(ogs_pfcp_xact_t *xact, void *data);

void upf_pfcp_state_initial(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;

    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    node->t_no_heartbeat = ogs_timer_add(ogs_app()->timer_mgr,
            upf_timer_no_heartbeat, node);
    ogs_assert(node->t_no_heartbeat);

    OGS_FSM_TRAN(s, &upf_pfcp_state_will_associate);
}

void upf_pfcp_state_final(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    ogs_timer_delete(node->t_no_heartbeat);
}

void upf_pfcp_state_will_associate(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_xact_t *xact = NULL;
    ogs_pfcp_message_t *message = NULL;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        if (node->t_association) {
            ogs_timer_start(node->t_association,
                ogs_local_conf()->time.message.pfcp.association_interval);

            ogs_pfcp_up_send_association_setup_request(node, node_timeout);
        }
        break;

    case OGS_FSM_EXIT_SIG:
        if (node->t_association) {
            ogs_timer_stop(node->t_association);
        }
        break;

    case UPF_EVT_N4_TIMER:
        switch(e->timer_id) {
        case UPF_TIMER_ASSOCIATION:
            ogs_warn("Retry association with peer failed %s",
                    ogs_sockaddr_to_string_static(node->addr_list));

            ogs_assert(node->t_association);
            ogs_timer_start(node->t_association,
                ogs_local_conf()->time.message.pfcp.association_interval);

            ogs_pfcp_up_send_association_setup_request(node, node_timeout);
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    upf_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case UPF_EVT_N4_MESSAGE:
        message = e->pfcp_message;
        ogs_assert(message);
        xact = ogs_pfcp_xact_find_by_id(e->pfcp_xact_id);
        ogs_assert(xact);

        switch (message->h.type) {
        case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_request(node, xact,
                    &message->pfcp_heartbeat_request));
            break;
        case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_response(node, xact,
                    &message->pfcp_heartbeat_response));
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            ogs_pfcp_up_handle_association_setup_request(node, xact,
                    &message->pfcp_association_setup_request);
            OGS_FSM_TRAN(s, upf_pfcp_state_associated);
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            ogs_pfcp_up_handle_association_setup_response(node, xact,
                    &message->pfcp_association_setup_response);
            OGS_FSM_TRAN(s, upf_pfcp_state_associated);
            break;
        default:
            ogs_warn("cannot handle PFCP message type[%d]",
                    message->h.type);
            break;
        }
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

void upf_pfcp_state_associated(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_xact_t *xact = NULL;
    ogs_pfcp_message_t *message = NULL;

    upf_sess_t *sess = NULL;

    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        ogs_info("PFCP associated %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        ogs_timer_start(node->t_no_heartbeat,
                ogs_local_conf()->time.message.pfcp.no_heartbeat_duration);
        ogs_assert(OGS_OK ==
            ogs_pfcp_send_heartbeat_request(node, node_timeout));

        if (node->restoration_required == true) {
            pfcp_restoration(node);
            node->restoration_required = false;
            ogs_error("PFCP restoration");
        }

        upf_metrics_inst_global_inc(UPF_METR_GLOB_GAUGE_PFCP_PEERS_ACTIVE);
        break;
    case OGS_FSM_EXIT_SIG:
        ogs_info("PFCP de-associated %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        ogs_timer_stop(node->t_no_heartbeat);

        upf_metrics_inst_global_dec(UPF_METR_GLOB_GAUGE_PFCP_PEERS_ACTIVE);
        break;
    case UPF_EVT_N4_MESSAGE:
        message = e->pfcp_message;
        ogs_assert(message);
        xact = ogs_pfcp_xact_find_by_id(e->pfcp_xact_id);
        ogs_assert(xact);

        if (message->h.seid_presence && message->h.seid != 0)
            sess = upf_sess_find_by_upf_n4_seid(message->h.seid);

        switch (message->h.type) {
        case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_request(node, xact,
                    &message->pfcp_heartbeat_request));
            if (node->restoration_required == true) {
                if (node->t_association) {
        /*
         * node->t_association that the PFCP entity attempts an association.
         *
         * In this case, even if Remote PFCP entity is restarted,
         * PFCP restoration must be performed after PFCP association.
         *
         * Otherwise, Session related PFCP cannot be initiated
         * because the peer PFCP entity is in a de-associated state.
         */
                    OGS_FSM_TRAN(s, upf_pfcp_state_will_associate);
                } else {

        /*
         * If the peer PFCP entity is performing the association,
         * Restoration can be performed immediately.
         */
                    pfcp_restoration(node);
                    node->restoration_required = false;
                    ogs_error("PFCP restoration");
                }
            }
            break;
        case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_response(node, xact,
                    &message->pfcp_heartbeat_response));
            if (node->restoration_required == true) {
        /*
         * node->t_association that the PFCP entity attempts an association.
         *
         * In this case, even if Remote PFCP entity is restarted,
         * PFCP restoration must be performed after PFCP association.
         *
         * Otherwise, Session related PFCP cannot be initiated
         * because the peer PFCP entity is in a de-associated state.
         */
                if (node->t_association) {
                    OGS_FSM_TRAN(s, upf_pfcp_state_will_associate);
                } else {
        /*
         * If the peer PFCP entity is performing the association,
         * Restoration can be performed immediately.
         */
                    pfcp_restoration(node);
                    node->restoration_required = false;
                    ogs_error("PFCP restoration");
                }
            }
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            ogs_warn("PFCP[REQ] has already been associated %s",
                    ogs_sockaddr_to_string_static(node->addr_list));
            ogs_pfcp_up_handle_association_setup_request(node, xact,
                    &message->pfcp_association_setup_request);
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            ogs_warn("PFCP[RSP] has already been associated %s",
                    ogs_sockaddr_to_string_static(node->addr_list));
            ogs_pfcp_up_handle_association_setup_response(node, xact,
                    &message->pfcp_association_setup_response);
            break;
        case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
            sess = upf_sess_add_by_message(message);
            if (sess)
                OGS_SETUP_PFCP_NODE(sess, node);

            upf_n4_handle_session_establishment_request(
                sess, xact, &message->pfcp_session_establishment_request);

            /* 
            E2E Demo enhancement (PFCP Establishment) PDU PFCP establishment-NON-GBR AMBR QoS Bandwidth
            */

            // Step1: Iterate the create_qer IE array, extract QER MBR information and print it
            uint64_t create_qer_mbr_ul = 0;
            uint8_t create_qer_cause_value = 0;
            uint8_t create_qer_offending_ie_value = 0;

            for (int i = 0; i < OGS_MAX_NUM_OF_QER; i++){
                if (message->pfcp_session_establishment_request.create_qer[i].presence){
                    ogs_pfcp_qer_t *qer = ogs_pfcp_handle_create_qer(
                        &sess->pfcp,
                        &message->pfcp_session_establishment_request.create_qer[i],
                        &create_qer_cause_value,
                        &create_qer_offending_ie_value);
                    if (qer != NULL){
                        create_qer_mbr_ul = qer->mbr.uplink;
                        break;
                    }
                }
            }
            if (create_qer_mbr_ul > 0){
                ogs_info("✅ QER MBR extracted: UL = %" PRIu64 " bps", create_qer_mbr_ul);
                // Note: for example, if PCF applies 2Mbps, then create_qer_mbr_ul should be 2000000 bps
                uint32_t rate_mbit = (uint32_t)(create_qer_mbr_ul / 1000000);
                char rate_str[32] = {0};
                snprintf(rate_str, sizeof(rate_str), "%umbit", rate_mbit);
                // downlink interface
                const char *interface = "ogstun";
                char tc_cmd[512];
                // uplink interface
                const char *interface1 = "zthnhfhjec";
                char tc_cmd1[512];


                // Clean up the TC rules when a new session is established
                // downlink
                snprintf(tc_cmd, sizeof(tc_cmd), "sudo tc qdisc del dev %s root 2>/dev/null", interface);
                system(tc_cmd);
                // uplink
                snprintf(tc_cmd1, sizeof(tc_cmd1), "sudo tc qdisc del dev %s root 2>/dev/null", interface1);
                system(tc_cmd1);

                // Configure downlink rate limiting rule (matches all DESTINATION IPs, global rule)
                snprintf(tc_cmd, sizeof(tc_cmd),
                         "sudo tc qdisc add dev %s root handle 1: htb default 20", interface);
                system(tc_cmd);
                snprintf(tc_cmd, sizeof(tc_cmd),
                         "sudo tc class add dev %s parent 1: classid 1:1 htb rate 100mbit burst 15k", interface);
                system(tc_cmd);
                snprintf(tc_cmd, sizeof(tc_cmd),
                         "sudo tc class add dev %s parent 1:1 classid 1:20 htb rate %s burst 15k", interface, rate_str);
                system(tc_cmd);

                // Configure uplink rate limiting rule (matches all SOURCE IPs, global rule)
                snprintf(tc_cmd1, sizeof(tc_cmd1),
                         "sudo tc qdisc add dev %s root handle 1: htb default 20", interface1);
                system(tc_cmd1);
                snprintf(tc_cmd1, sizeof(tc_cmd1),
                         "sudo tc class add dev %s parent 1: classid 1:1 htb rate 100mbit burst 15k", interface1);
                system(tc_cmd1);
                snprintf(tc_cmd1, sizeof(tc_cmd1),
                         "sudo tc class add dev %s parent 1:1 classid 1:20 htb rate %s burst 15k", interface1, rate_str);
                system(tc_cmd1);

                ogs_info("✅ Applied base rate limit: %s on dlink interface %s using QER MBR", rate_str, interface);
                ogs_info("✅ Applied base rate limit: %s on ulink interface %s using QER MBR", rate_str, interface1);
            }
            else{
                ogs_error("❌ No QER MBR information found in PFCP Create message");
                }

            break;

        case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
            // E2E Demo enhancement(PFCP Modification)
            // Print basic header information of the entire PFCP message (no need, just for tracing purpose)
            ogs_info("PFCP MODIFICATION REQUEST received:");
            ogs_info("  Type: %d", message->h.type);
            ogs_info("  SEID: 0x%lx", (unsigned long)message->h.seid);
            ogs_info("  Length: %d", ntohs(message->h.length));
            ogs_info("  SQN: %d", message->h.sqn_only);

            /* 
            先判断是否为Remove QoS flow procedure, 因为Remove也在PFCP Modification消息中，这里使用PDR和PER来判断
            Firstly, checking if it's a Remove procedure, if it's Remove procedure,
            then remove_requested will be set to true, here, PDR and PER are used as the criteria 
            */
            bool remove_requested = false;
            ogs_pfcp_session_modification_request_t *req = &message->pfcp_session_modification_request;
            // Checking Remove PDR IE（maximum at 16 of PDR array）
            for (int i = 0; i < 16; i++){
                if (req->remove_pdr[i].presence){
                    ogs_info("Remove PDR[%d] present, pdr_id: %u", i, *(uint16_t *)&(req->remove_pdr[i].pdr_id));
                    remove_requested = true;
                    break;
                }
            }
            // Checking Remove QER IE（less than OGS_MAX_NUM_OF_QER）
            if (!remove_requested){
                for (int i = 0; i < OGS_MAX_NUM_OF_QER; i++){
                    if (req->remove_qer[i].presence){
                        ogs_info("Remove QER[%d] present, qer_id: %u", i, *(uint32_t *)&(req->remove_qer[i].qer_id));
                        remove_requested = true;
                        break;
                    }
                }
            }

            /* 
            TC限速阶段: 初始化ue_ip/server_ip信息,用于反复安装rule和删除rule的场景，不存储的话N4接口不会再有这两个信息
            TC rate limiting phase: initialize ue_ip/server_ip for scenarios involving repeated rule installation and deletion;
            without this, the N4 interface will not have these two pieces of information again 
            */
            char ue_ip[16] = {0};     // UE IP address（as the source IP）
            char server_ip[16] = {0}; // server IP address (as the destination IP）
            uint64_t mbr_ul = 0;      // uplink MBR (bps)

            /* 
            接着开始在PFCP消息体中,遍历PDR和其PDI中信息，找到SDF中的flow中提取server IP
            Begin Iterating PDR and its PDI information within the PFCP message body, 
            locate the flow in SDF to extract server IP 
            */
            
            // Iterating Create-PDR IE array（16 at maximum）
            for (int i = 0; i < 16; i++) {
                if (message->pfcp_session_modification_request.create_pdr[i].presence) {
                    // Printing the key INFO of Create-PDR (tracing purpose)
                    unsigned int pdr_id = *(uint16_t *)&(message->pfcp_session_modification_request.create_pdr[i].pdr_id);
                    unsigned int precedence = *(uint32_t *)&(message->pfcp_session_modification_request.create_pdr[i].precedence);
                    ogs_info("Create PDR[%d] present:", i);
                    ogs_info("    pdr_id: %u", pdr_id);
                    ogs_info("    precedence: %u", precedence);
            
                    // Printing the INFO of PDI if existing (tracing purpose)
                    if (message->pfcp_session_modification_request.create_pdr[i].pdi.presence) {
                        ogs_pfcp_tlv_pdi_t *pdi = &message->pfcp_session_modification_request.create_pdr[i].pdi;
                        unsigned int src_if = *(uint8_t *)&(pdi->source_interface);
                        ogs_info("PDI source_interface: %u", src_if);

                        // Printing the SDF Filter array in PDI (maximum 8)
                        for (int j = 0; j < 8; j++) {
                            if (pdi->sdf_filter[j].presence) {
                                ogs_info("PDI SDF Filter[%d]: presence=%d, len=%d", j,
                                         (int)pdi->sdf_filter[j].presence, (int)pdi->sdf_filter[j].len);
                                if ((int)pdi->sdf_filter[j].len > 4) {
                                    int txt_len = (int)pdi->sdf_filter[j].len - 4;
                                    char *txt = (char *)pdi->sdf_filter[j].data + 4;
                                    ogs_info("PDI SDF Filter[%d] as string: %.*s", j, txt_len, txt);

                                    // 预期SDF格式: The expecting SDF format: "permit out ip from <server_ip> to <ue_ip>"
                                    if (strncmp(txt, "permit out ip from ", 19) == 0){
                                        if (sscanf(txt, "permit out ip from %15s to %15s", server_ip, ue_ip) == 2){
                                            ogs_info("Extracted server IP: %s, UE IP: %s", server_ip, ue_ip);
                                            // 缓存到session中: Cache ue_ip/server_ip to Session
                                            strncpy(sess->cached_server_ip, server_ip, sizeof(sess->cached_server_ip));
                                            strncpy(sess->cached_ue_ip, ue_ip, sizeof(sess->cached_ue_ip));
                                        }
                                        else{
                                            ogs_info("Failed to extract both IPs from SDF string");
                                        }
                                    }
                                } else {
                                    ogs_info("PDI SDF Filter[%d] as string: (too short)", j);
                                }
                            } else {
                                ogs_info("PDI SDF Filter[%d]: not present", j);
                            }                       
                        }
                    }
                }
            }

            /* 
            如果此次修改中没有 Create PDR IE（即 ue_ip/server_ip为空），尝试使用会话缓存对应反复下发和删除qos flow场景，
            PFCP中只有Update QER，这里通过读取缓存中的设置来继续更改qos MBR缓存配置在context.h中的typedef struct upf_sess_s 函数中,如下
            If there is no Create PDR IE in this modification (i.e., ue_ip/server_ip is empty),
            try to use session cache. This corresponds to scenarios of repeated QoS flow delivery and deletion,
            where PFCP only has Update QER. Here continue to modify QoS MBR by reading cached settings.
            The cache configuration is in the typedef struct upf_sess_s function in context.h, as follows
            char cached_ue_ip[16];
            char cached_server_ip[16];
            */
            if (strlen(ue_ip) == 0 || strlen(server_ip) == 0){
                if (strlen(sess->cached_ue_ip) > 0 && strlen(sess->cached_server_ip) > 0){
                    strncpy(ue_ip, sess->cached_ue_ip, sizeof(ue_ip));
                    strncpy(server_ip, sess->cached_server_ip, sizeof(server_ip));
                    ogs_info("Using cached IPs: UE = %s, Server = %s", ue_ip, server_ip);
                }
                else{
                    ogs_info("No Create PDR IE found and no cached IPs available");
                }
            }

            /* 
            删除TC规则，如果想使用UE IP和Server IP信息，那么放到上边这段代码下，因为上边这段代码的作用
            是在Update/Remove等类型消息中再次读取存储到session中的UE IP和Server IP信息供使用。
            Delete TC rules. If using UE IP and Server IP info, place it under the above code block, 
            as that block's purpose is to re-read UE IP and Server IP info stored in session 
            for use in Update/Remove type messages
            */

            if (remove_requested)
            {
                const char *interface = "ogstun";
                char tc_cmd[512];
                const char *interface1 = "zthnhfhjec";
                char tc_cmd1[512];
                ogs_info("Detected remove IE in PFCP message, clearing the specific tc rules...");

                // Delete the GBR QoS flow TC rule, here is filter prio 1 and class 1:10
                // Remove downlink tc rules
                snprintf(tc_cmd, sizeof(tc_cmd), "sudo tc filter del dev %s protocol ip parent 1: prio 1", interface);
                system(tc_cmd);
                snprintf(tc_cmd, sizeof(tc_cmd), "sudo tc class del dev %s classid 1:10", interface);
                system(tc_cmd);
                
                // Remove uplink tc rules
                snprintf(tc_cmd1, sizeof(tc_cmd1), "sudo tc filter del dev %s protocol ip parent 1: prio 1", interface1);
                system(tc_cmd1);
                snprintf(tc_cmd1, sizeof(tc_cmd1), "sudo tc class del dev %s classid 1:10", interface1);
                system(tc_cmd1);

                // Printing Remove Info
                ogs_info("✅ The specific tc rules have been cleared on dlink interface %s for UE %s to Server %s", interface, ue_ip, server_ip);
                ogs_info("✅ The specific tc rules have been cleared on uplink interface1 %s for UE %s to Server %s", interface1, ue_ip, server_ip);

                /*
                继续处理PFCP请求 -> 产生响应
                如果你想让PFCP里的 remove_pdr/remove_qer真正被 UPF 层解析删除, 还需要upf_n4_handle_session_modification_request()
                内部正确处理remove_xxx,不想做任何 session 中 PDR/QER 层面的删除也没问题，但一定要发回响应.
                upf_n4_handle_session_modification_request(sess, xact, req);

                If you want the remove_pdr/remove_qer in PFCP to be actually parsed and deleted by the UPF layer,
                you still need upf_n4_handle_session_modification_request() to correctly handle remove_xxx internally.
                It's fine if you don't want to perform any PDR/QER level deletion in the session, but you must send back a response here.
                upf_n4_handle_session_modification_request(sess, xact, req);
                */
                upf_n4_handle_session_modification_request(sess, xact, req);
                break;
            }

            /*
            Below is the source code
            */
            upf_n4_handle_session_modification_request(
                sess, xact, &message->pfcp_session_modification_request);

            /*
            接下来开始尝试取出GBR QoS flow中的MBR信息, DEMO测试只取一个MBR值已经足够
            Next, start attempting to extract MBR information from GBR QoS flow. For DEMO testing, 
            extracting only one MBR value is sufficient
            */

            // Tring to iterate the array of Create QER IE（Maximum at OGS_MAX_NUM_OF_QER）
            uint8_t cause_value = 0;
            uint8_t offending_ie_value = 0;
            for (int i = 0; i < OGS_MAX_NUM_OF_QER; i++){
                if (message->pfcp_session_modification_request.create_qer[i].presence){
                    ogs_pfcp_qer_t *qer = ogs_pfcp_handle_create_qer(&sess->pfcp,
                                                                     &message->pfcp_session_modification_request.create_qer[i],
                                                                     &cause_value, &offending_ie_value);
                    if (qer == NULL)
                        break;
                    ogs_info("📊 pfcp-sm Received QER with MBR Info: UL=%" PRIu64 ", DL=%" PRIu64, qer->mbr.uplink, qer->mbr.downlink);
                    ogs_info("📊 pfcp-sm Received QER with GBR Info: UL=%" PRIu64 ", DL=%" PRIu64, qer->gbr.uplink, qer->gbr.downlink);

                    // here, mbr_ul or mbr_dl is used for TC rules
                    mbr_ul = qer->mbr.uplink;
                    //mbr_dl = qer->mbr.downlink;
                }

                /*
                下边这段代码对应反复建立GBR QoS flow的场景，因为第二次或者多次创建，都是在PFCP Update QER IE中设置的
                The code below handles repeated GBR QoS flow establishment scenarios, as second or subsequent 
                creations are all set in PFCP Update QER IE.
                */
                if (mbr_ul == 0){
                    for (int i = 0; i < OGS_MAX_NUM_OF_QER; i++){
                        if (message->pfcp_session_modification_request.update_qer[i].presence){
                            ogs_pfcp_qer_t *qer = ogs_pfcp_handle_update_qer(&sess->pfcp,
                                                                             &message->pfcp_session_modification_request.update_qer[i],
                                                                             &cause_value, &offending_ie_value);
                            if (qer == NULL)
                                break;
                            ogs_info("📊 pfcp-sm Received UPDATE QER with MBR Info: UL=%" PRIu64 ", DL=%" PRIu64,
                                     qer->mbr.uplink, qer->mbr.downlink);
                            ogs_info("📊 pfcp-sm Received UPDATE QER with GBR Info: UL=%" PRIu64 ", DL=%" PRIu64,
                                     qer->gbr.uplink, qer->gbr.downlink);

                            // here, mbr_ul or mbr_dl is used for TC rules
                            mbr_ul = qer->mbr.uplink;
                            // mbr_dl = qer->mbr.downlink;
                        }
                    }
                }
            }

            /*
            最后的TC策略调用阶段,使用ue_ip/server_ip/mbr以及downlink和uplink接口等信息共同完成TC rule的设置
            Final TC policy invocation stage, use ue_ip/server_ip/mbr along with downlink and uplink interface information 
            to complete TC rule configuration
            */

            // If UE IP, server IP and uplink MBR extraction is successful, configure tc rate limiting
            if (strlen(ue_ip) > 0 && strlen(server_ip) > 0 && mbr_ul > 0)
            {
                // Downlink interface setting
                char tc_cmd[512];
                const char *interface = "ogstun";
                // Uplink interface setting
                char tc_cmd1[512];
                const char *interface1 = "zthnhfhjec";

                ogs_info("Extracted mbr_ul: %" PRIu64 " bps", mbr_ul);

                // Convert to Mbit string format (e.g., "8Mbit")
                // uint32_t high_rate_str = (uint32_t)(mbr_ul / 1000000);
                char high_rate_str[32] = {0};
                if (mbr_ul >= 1000000){
                    snprintf(high_rate_str, sizeof(high_rate_str), "%umbit", (uint32_t)(mbr_ul / 1000000));
                } else if (mbr_ul >= 1000) {
                    snprintf(high_rate_str, sizeof(high_rate_str), "%ukbit", (uint32_t)(mbr_ul / 1000));
                } else {
                    snprintf(high_rate_str, sizeof(high_rate_str), "%ubit", (uint32_t)(mbr_ul));
                }
                ogs_info("Using high rate: %s", high_rate_str);

                /*
                1.下行速率控制，这里直接使用的就是UPF默认ogstun接口配置HTB
                Downlink rate limiting configuration (UE receiving direction)
                */
                // Add root qdisc (HTB), default flow goes to class 1:10 (e.g., 1Mbit)
                snprintf(tc_cmd, sizeof(tc_cmd),
                         "sudo tc class add dev %s parent 1:1 classid 1:10 htb rate %s burst 30k", interface, high_rate_str);
                system(tc_cmd);
                if (strcmp(server_ip, "0.0.0.0") == 0){
                    // Match all downlink traffic destined for UE
                    snprintf(tc_cmd, sizeof(tc_cmd),
                             "sudo tc filter add dev %s protocol ip parent 1: prio 1 u32 match ip dst %s flowid 1:10",
                             interface, ue_ip);
                }else{
                    // Precisely match server IP destined for UE
                    snprintf(tc_cmd, sizeof(tc_cmd),
                             "sudo tc filter add dev %s protocol ip parent 1: prio 1 u32 match ip src %s match ip dst %s flowid 1:10",
                             interface, server_ip, ue_ip);
                }
                system(tc_cmd);

                /*
                2.上行速率控制，正常应该使用ifb技术来实现，但是DEMO中我们配置了UPF到指定的Server，他们之前走单独的LAN，所以这里使用特别的接口
                Uplink rate control should normally be implemented using ifb technology, but in the DEMO we configured UPF to a specific server, 
                and they communicate through a separate LAN, so we use a special interface here.
                */
                // Add root qdisc (HTB), default flow goes to class 1:10 (e.g., 1Mbit)
                snprintf(tc_cmd1, sizeof(tc_cmd1),
                         "sudo tc class add dev %s parent 1:1 classid 1:10 htb rate %s burst 10k", interface1, high_rate_str);
                system(tc_cmd1);
                // Match all downlink traffic destined for this specific server IP
                snprintf(tc_cmd1, sizeof(tc_cmd1),
                         "sudo tc filter add dev %s protocol ip parent 1: prio 1 u32 match ip dst %s flowid 1:10", interface1, server_ip);
                system(tc_cmd1);
                
                // Printing the final TC policies
                ogs_info("✅ Applied enhanced TC rules on %s: %s for dlink traffic speed from %s to server %s", interface, high_rate_str, ue_ip, server_ip);
                ogs_info("✅ Applied enhanced TC rules on %s: %s for ulink traffic speed from %s to server %s", interface1, high_rate_str, ue_ip, server_ip);
            }
            else{
                ogs_error("Failed to extract UE IP, server IP or UL MBR for tc rate limiting in modification");
            }

            // source code
            break;       
    
        case OGS_PFCP_SESSION_DELETION_REQUEST_TYPE:
            upf_n4_handle_session_deletion_request(
                sess, xact, &message->pfcp_session_deletion_request);
            break;
        case OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE:
            upf_n4_handle_session_report_response(
                sess, xact, &message->pfcp_session_report_response);
            break;
        default:
            ogs_error("Not implemented PFCP message type[%d]",
                    message->h.type);
            break;
        }

        break;
    case UPF_EVT_N4_TIMER:
        switch(e->timer_id) {
        case UPF_TIMER_NO_HEARTBEAT:
            node = e->pfcp_node;
            ogs_assert(node);

            ogs_assert(OGS_OK ==
                ogs_pfcp_send_heartbeat_request(node, node_timeout));
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    upf_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case UPF_EVT_N4_NO_HEARTBEAT:
        ogs_warn("No Heartbeat from SMF %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        OGS_FSM_TRAN(s, upf_pfcp_state_will_associate);
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

void upf_pfcp_state_exception(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

static void pfcp_restoration(ogs_pfcp_node_t *node)
{
    upf_sess_t *sess = NULL, *next = NULL;
    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];

    ogs_list_for_each_safe(&upf_self()->sess_list, next, sess) {
        if (node == sess->pfcp_node) {
            ogs_info("DELETION: F-SEID[UP:0x%lx CP:0x%lx] IPv4[%s] IPv6[%s]",
                (long)sess->upf_n4_seid, (long)sess->smf_n4_f_seid.seid,
                sess->ipv4 ? OGS_INET_NTOP(&sess->ipv4->addr, buf1) : "",
                sess->ipv6 ? OGS_INET6_NTOP(&sess->ipv6->addr, buf2) : "");
            upf_sess_remove(sess);
        }
    }
}

static void node_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    int rv;

    upf_event_t *e = NULL;
    uint8_t type;

    ogs_assert(xact);
    type = xact->seq[0].type;

    switch (type) {
    case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
        ogs_assert(data);

        e = upf_event_new(UPF_EVT_N4_NO_HEARTBEAT);
        e->pfcp_node = data;

        rv = ogs_queue_push(ogs_app()->queue, e);
        if (rv != OGS_OK) {
            ogs_error("ogs_queue_push() failed:%d", (int)rv);
            upf_event_free(e);
        }
        break;
    case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
        break;
    default:
        ogs_error("Not implemented [type:%d]", type);
        break;
    }
}
