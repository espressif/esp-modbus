/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */ 
#include <stdbool.h>
#include <string.h>

#include "port_tcp_common.h"
#include "port_tcp_driver.h"
#include "port_tcp_master.h"
#include "port_tcp_utils.h"

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

typedef struct
{
    mb_port_base_t base;
    // TCP communication properties
    mb_tcp_opts_t tcp_opts;
    uint8_t ptemp_buf[MB_TCP_BUFF_MAX_SIZE];
    port_driver_t *pdriver;
} mbm_tcp_port_t;

/* ----------------------- Static variables & functions ----------------------*/
static const char *TAG = "mb_port.tcp.master";
static uint64_t mbm_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event);
bool mbm_port_timer_expired(void *inst);
extern int port_scan_addr_string(char *buffer, mb_uid_info_t *pslave_info);

static esp_err_t mbm_port_tcp_register_handlers(void *ctx)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;

    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_READY_NUM, mbm_on_ready);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_READY);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_OPEN_NUM, mbm_on_open);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_OPEN);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_RESOLVE_NUM, mbm_on_resolve);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_RESOLVE);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_CONNECT_NUM, mbm_on_connect);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_CONNECT);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_ERROR_NUM, mbm_on_error);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_ERROR);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_SEND_DATA_NUM, mbm_on_send_data);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_SEND_DATA);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_RECV_DATA_NUM, mbm_on_recv_data);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_RECV_DATA);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_CLOSE_NUM, mbm_on_close);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_CLOSE);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_TIMEOUT_NUM, mbm_on_timeout);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_TIMEOUT);
    return ESP_OK;
}

static esp_err_t mbm_port_tcp_unregister_handlers(void *ctx)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    ESP_LOGD(TAG, "%p, event handler %p, unregister.", pdrv_ctx, pdrv_ctx->event_handler);

    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_READY_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_READY);
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_OPEN_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_OPEN);
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_RESOLVE_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_RESOLVE);
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_CONNECT_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_CONNECT);
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_ERROR_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_ERROR);
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_SEND_DATA_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_SEND_DATA);
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_RECV_DATA_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_RECV_DATA);
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_CLOSE_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_CLOSE);
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_TIMEOUT_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                        "%x, mb tcp port event registration failed.", (int)MB_EVENT_TIMEOUT);
    return ESP_OK;
}

mb_err_enum_t mbm_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **port_obj)
{
    MB_RETURN_ON_FALSE((port_obj && tcp_opts), MB_EINVAL, TAG, "mb tcp port invalid arguments.");
    mbm_tcp_port_t *ptcp = NULL;
    esp_err_t err = ESP_OK;
    mb_err_enum_t ret = MB_EILLSTATE;

    ptcp = (mbm_tcp_port_t*)calloc(1, sizeof(mbm_tcp_port_t));
    MB_GOTO_ON_FALSE(ptcp, MB_EILLSTATE, error, TAG, "mb tcp port creation error.");
    ptcp->pdriver = NULL;
    CRITICAL_SECTION_INIT(ptcp->base.lock);
    ptcp->base.descr = ((mb_port_base_t *)*port_obj)->descr;

    err = mb_drv_register(&ptcp->pdriver);
    MB_GOTO_ON_FALSE(((err == ESP_OK) && ptcp->pdriver), MB_EILLSTATE, error, 
                        TAG, "mb tcp port driver registration failed, err = (%x).", (int)err);
    ptcp->pdriver->parent = ptcp;

    err = mbm_port_tcp_register_handlers(ptcp->pdriver);
    MB_GOTO_ON_FALSE(((err == ESP_OK) && ptcp->pdriver), MB_EILLSTATE, error, 
                        TAG, "mb tcp port driver event handlers registration failed, err = (%x).", (int)err);

    ptcp->pdriver->network_iface_ptr = tcp_opts->ip_netif_ptr;
    ptcp->pdriver->mb_proto = tcp_opts->mode;
    ptcp->pdriver->port = tcp_opts->port;
    ptcp->pdriver->uid = tcp_opts->uid;
    ptcp->pdriver->is_master = true;
    ptcp->pdriver->dns_name = tcp_opts->dns_name;
    ptcp->pdriver->event_cbs.mb_sync_event_cb = mbm_port_tcp_sync_event;
    ptcp->pdriver->event_cbs.port_arg = (void *)ptcp;

    ptcp->base.cb.tmr_expired = mbm_port_timer_expired;
    ptcp->base.cb.tx_empty = NULL;
    ptcp->base.cb.byte_rcvd = NULL;
    ptcp->base.arg = (void *)ptcp;

    char **paddr_table = tcp_opts->ip_addr_table;
    MB_GOTO_ON_FALSE((paddr_table && *paddr_table), MB_EILLSTATE, error, 
                        TAG, "mb tcp port nodes registration failed %p, %p.", paddr_table, *paddr_table);
    mb_uid_info_t slave_address_info;
    int fd = 0;

    while(*paddr_table) {
        int res = port_scan_addr_string((char *)*paddr_table, &slave_address_info);
        if (res > 0) {
            ESP_LOGD(TAG, "Config: %s, IP: %s, port: %d, slave_addr: %d, ip_ver: %s", 
                        (char *)*paddr_table, slave_address_info.ip_addr_str, slave_address_info.port, 
                        slave_address_info.uid, (slave_address_info.addr_type == MB_IPV4 ? "IPV4" : "IPV6"));
            fd = mb_drv_open(ptcp->pdriver, slave_address_info, 0);
            if (fd < 0) {
                ESP_LOGE(TAG, "%p, unable to open slave: %s", ptcp->pdriver, slave_address_info.ip_addr_str);
            } else {
                ESP_LOGD(TAG, "%p, open slave: %d, %s:%d", 
                                    ptcp->pdriver, fd, slave_address_info.ip_addr_str, slave_address_info.port);
            }
        } else {
            ESP_LOGE(TAG, "%p, unable to open slave: %s, check configuration.", ptcp->pdriver, (char *)*paddr_table);
        }
        paddr_table++;
    }

#ifdef MB_MDNS_IS_INCLUDED
    err = port_start_mdns_service(&ptcp->pdriver->dns_name, true, tcp_opts->uid, ptcp->pdriver->network_iface_ptr);
    MB_GOTO_ON_FALSE((err == ESP_OK), MB_EILLSTATE, error, 
                        TAG, "mb tcp port mdns service init failure.");
#endif

    *port_obj = &(ptcp->base);
    ESP_LOGD(TAG, "created object @%p", ptcp);
    return MB_ENOERR;

error:
#ifdef MB_MDNS_IS_INCLUDED
    port_stop_mdns_service(&ptcp->pdriver->dns_name);
#endif
    if (ptcp && ptcp->pdriver) {
        (void)mbm_port_tcp_unregister_handlers(ptcp->pdriver);
        (void)mb_drv_unregister(ptcp->pdriver);
        CRITICAL_SECTION_CLOSE(ptcp->base.lock);
        // if the MDNS resolving is enabled, then free it
    }
    free(ptcp);
    return ret;
}

void mbm_port_tcp_delete(mb_port_base_t *inst)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    esp_err_t err = MB_EILLSTATE;
    err = mbm_port_tcp_unregister_handlers(port_obj->pdriver);
    MB_RETURN_ON_FALSE((err == ESP_OK), ;, TAG, "mb tcp port can not unregister handlers.");
#ifdef MB_MDNS_IS_INCLUDED
    port_stop_mdns_service(&port_obj->pdriver->dns_name);
#endif
    err = mb_drv_unregister(port_obj->pdriver);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "driver unregister fail, returns (0x%d).", (uint16_t)err);
    }
    CRITICAL_SECTION_CLOSE(inst->lock);
    free(port_obj);
}

void mbm_port_tcp_enable(mb_port_base_t *inst)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    (void)mb_drv_start_task(port_obj->pdriver);
    (void)mb_drv_clear_status_flag(port_obj->pdriver, MB_FLAG_DISCONNECTED);
    DRIVER_SEND_EVENT(port_obj->pdriver, MB_EVENT_RESOLVE, UNDEF_FD);
}

void mbm_port_tcp_disable(mb_port_base_t *inst)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    // Change the state of all slaves to close
    DRIVER_SEND_EVENT(port_obj->pdriver, MB_EVENT_CLOSE, UNDEF_FD);
    (void)mb_drv_wait_status_flag(port_obj->pdriver, MB_FLAG_DISCONNECTED, pdMS_TO_TICKS(MB_RECONNECT_TIME_MS));
}

bool mbm_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);

    mb_node_info_t *pinfo = port_obj->pdriver->mb_node_curr;
    MB_RETURN_ON_FALSE((pinfo), false, TAG, "incorrect current slave pointer.");
    bool status = false;

    size_t sz = mb_drv_read(port_obj->pdriver, pinfo->fd, port_obj->ptemp_buf, MB_BUFFER_SIZE);
    if (sz > MB_TCP_FUNC) {
        uint16_t tid_counter = MB_TCP_MBAP_GET_FIELD(port_obj->ptemp_buf, MB_TCP_TID);
        if (tid_counter == (pinfo->tid_counter - 1)) {
            *ppframe = port_obj->ptemp_buf;
            *plength = sz;
            ESP_LOGD(TAG, "%p, "MB_NODE_FMT(", get packet TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p."),
                            port_obj->pdriver, pinfo->index, pinfo->sock_id, pinfo->addr_info.ip_addr_str, 
                            (unsigned)tid_counter, (unsigned)pinfo->tid_counter, *ppframe);

            uint64_t time = 0;
            time = port_get_timestamp() - pinfo->send_time;
            ESP_LOGD(TAG, "%p, "MB_NODE_FMT(", processing time[us] = %ju."), port_obj->pdriver, pinfo->index,
                        pinfo->sock_id, pinfo->addr_info.ip_addr_str, time);
            status = true;
        } else {
            ESP_LOGE(TAG, "%p, "MB_NODE_FMT(", drop packet TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p."),
                            port_obj->pdriver, pinfo->index, pinfo->sock_id,
                            pinfo->addr_info.ip_addr_str, (unsigned)tid_counter, (unsigned)pinfo->tid_counter, *ppframe);
        }
    }
    return status;
}

bool mbm_port_tcp_send_data(mb_port_base_t *inst, uint8_t address, uint8_t *pframe, uint16_t length)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);

    bool frame_sent = false;
    // get slave descriptor from its address
    mb_node_info_t *pinfo = (mb_node_info_t *)mb_drv_get_node_info_from_addr(port_obj->pdriver, address);

    bool all_nodes_connected = mb_drv_wait_status_flag(port_obj->pdriver, MB_FLAG_CONNECTED, pdMS_TO_TICKS(MB_RECONNECT_TIME_MS));

    MB_RETURN_ON_FALSE((all_nodes_connected && pinfo && (MB_GET_NODE_STATE(pinfo) >= MB_SOCK_STATE_CONNECTED)),
                        false, TAG, "The node UID #%d, is not connected.", address);

    if (pinfo && pframe) {
        // Apply TID field to the frame before send
        MB_TCP_MBAP_SET_FIELD(pframe, MB_TCP_TID, pinfo->tid_counter);
        pframe[MB_TCP_UID] = (uint8_t)(pinfo->addr_info.uid);
    }

    ESP_LOGD(TAG, "%p,  send fd: %d, sock_id: %d[%s], %p, len: %d", 
                port_obj->pdriver, pinfo->fd, pinfo->sock_id, pinfo->addr_info.ip_addr_str, pframe, length);

    // Write data to the modbus driver send queue of the slave 
    int write_length = mb_drv_write(port_obj->pdriver, pinfo->fd, pframe, length);
    if (write_length) {
        frame_sent = true;
    } else {
        ESP_LOGE(TAG, "mbm_write fail, returns %d.", write_length);
    }
    // mb_port_timer_respond_timeout_enable(inst); // the timer is set in the transport

    return frame_sent;
}

void mbm_port_tcp_set_conn_cb(mb_port_base_t *inst, void *conn_fp, void *arg)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    mb_drv_set_cb(port_obj->pdriver, conn_fp, arg);
}

// Timer handler to check timeout of socket response
bool mbm_port_timer_expired(void *inst)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    bool need_poll = false;
    BaseType_t task_unblocked;
    mb_event_info_t mb_event;
    esp_err_t err = ESP_FAIL;

    mb_port_timer_disable(inst);
    // If timer mode is respond timeout, the master event then turns EV_MASTER_EXECUTE status.
    if (mb_port_get_cur_timer_mode(inst) == MB_TMODE_RESPOND_TIMEOUT) {
        // It is now to check solution.
        mb_event.event_id = MB_EVENT_TIMEOUT;
        mb_event.opt_fd = port_obj->pdriver->curr_node_index;
        err = esp_event_isr_post_to(port_obj->pdriver->event_loop_hdl, MB_EVENT_BASE(port_obj->pdriver), 
                                    (int32_t)MB_EVENT_TIMEOUT, (void *)&mb_event, sizeof(mb_event_info_t*), &task_unblocked);
        if (err != ESP_OK) {
            ESP_EARLY_LOGE(TAG, "Timeout event send error: %d", err);
        }
        need_poll = task_unblocked;
        mb_port_event_set_err_type(inst, EV_ERROR_RESPOND_TIMEOUT);
        need_poll = mb_port_event_post(inst, EVENT(EV_ERROR_PROCESS));
    }
    return need_poll;
}

mb_uid_info_t *mbm_port_tcp_get_slave_info(mb_port_base_t *inst, uint8_t slave_addr, mb_sock_state_t exp_state)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    mb_uid_info_t *paddr_info = NULL;
    mb_node_info_t *pinfo = mb_drv_get_node_info_from_addr(port_obj->pdriver, slave_addr);
    if (pinfo && (MB_GET_NODE_STATE(pinfo) >= exp_state)) {
        paddr_info = &pinfo->addr_info;
    }
    return paddr_info;
}

static uint64_t mbm_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event)
{
    switch(sync_event) {
        case MB_SYNC_EVENT_RECV_OK:
            mb_port_timer_disable(inst);
            mb_port_event_set_err_type(inst, EV_ERROR_INIT);
            mb_port_event_post(inst, EVENT(EV_FRAME_RECEIVED));
            break;

        case MB_SYNC_EVENT_RECV_FAIL:
            mb_port_timer_disable(inst);
            mb_port_event_set_err_type(inst, EV_ERROR_RECEIVE_DATA);
            mb_port_event_post(inst, EVENT(EV_ERROR_PROCESS));
            break;

        case MB_SYNC_EVENT_SEND_OK:
            mb_port_event_post(inst, EVENT(EV_FRAME_SENT));
            break;
        default:
            break;
    }
    return mb_port_get_trans_id(inst);
}

MB_EVENT_HANDLER(mbm_on_ready)
{
    // The driver is registered
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
}

MB_EVENT_HANDLER(mbm_on_open)
{
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
}

MB_EVENT_HANDLER(mbm_on_resolve)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);

    if (MB_CHECK_FD_RANGE(pevent_info->opt_fd)) {
        ESP_LOGD(TAG, "%p, Node: %d, resolve.", ctx, (int)pevent_info->opt_fd);
        // The mdns is not used in the main app, then can use manually defined IPs
        int fd = pevent_info->opt_fd;
        mb_node_info_t *pslave = mb_drv_get_node(pdrv_ctx, fd);
        if (pslave && (MB_GET_NODE_STATE(pslave) == MB_SOCK_STATE_OPENED)
                    && FD_ISSET(pslave->index, &pdrv_ctx->open_set)) {
            mb_status_flags_t status = mb_drv_wait_status_flag(pdrv_ctx, MB_FLAG_DISCONNECTED, 0);
            if ((status & MB_FLAG_DISCONNECTED)) {
                ESP_LOGV(TAG, "%p, slave: %d, sock: %d, IP:%s, disconnected.",
                            ctx, (int)pslave->index, (int)pslave->sock_id, pslave->addr_info.ip_addr_str);
                return;
            }
            // The slave IP is defined manually
            if (port_check_host_addr(pslave->addr_info.node_name_str, NULL)) {
                pslave->addr_info.ip_addr_str = pslave->addr_info.node_name_str;
                ESP_LOGD(TAG, "%p, slave: %d, IP address [%s], added to connection list.", ctx, (int)fd, pslave->addr_info.ip_addr_str);
                MB_SET_NODE_STATE(pslave, MB_SOCK_STATE_RESOLVED);
                DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pslave->index);
            } else {
#ifdef MB_MDNS_IS_INCLUDED
                int ret = port_resolve_mdns_host(pslave->addr_info.node_name_str, (char **)&pslave->addr_info.ip_addr_str);
                if (ret > 0) {
                    ESP_LOGI(TAG, "%p, slave: %d, resolved with IP:%s.", ctx, (int)fd, pslave->addr_info.ip_addr_str);
                    MB_SET_NODE_STATE(pslave, MB_SOCK_STATE_RESOLVED);
                    DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pslave->index);
                } else {
                    // continue resolve while not resolved
                    DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pslave->index);
                }
#else
                ESP_LOGE(TAG, "%p, slave: %d, IP:%s, mdns service is not supported.", ctx, (int)fd, pslave->addr_info.node_name_str);
                DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pslave->index);
#endif
            }
        }
    } else if (pevent_info->opt_fd < 0) {
        // Todo: query for services is removed from this version 
        // #ifdef MB_MDNS_IS_INCLUDED
        //         // If the mDNS feature support is enabled, use it to resolve the slave IP
        //         res = mb_drv_resolve_mdns_service(ctx, "_modbus", "_tcp", pdrv_ctx->addr_type);
        //         ESP_LOGD(TAG, "%p, use mdns to resolve slave: %d, resolved: %d devices.", ctx, (int)pevent_info->opt_fd, res);
        // #else
        for (int fd = 0; fd < pdrv_ctx->mb_node_open_count; fd++) {
            mb_node_info_t *pslave = mb_drv_get_node(pdrv_ctx, fd);
            if (pslave && (MB_GET_NODE_STATE(pslave) == MB_SOCK_STATE_OPENED) 
                    && FD_ISSET(pslave->index, &pdrv_ctx->open_set)) {
                DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pslave->index);
            }
            mb_drv_check_suspend_shutdown(ctx);
        }
        // #endif
    }
}

MB_EVENT_HANDLER(mbm_on_connect)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *pnode_info = NULL;
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    err_t err = ERR_CONN;
    if (MB_CHECK_FD_RANGE(pevent_info->opt_fd)) {
        pnode_info = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
        if (pnode_info &&
            (MB_GET_NODE_STATE(pnode_info) < MB_SOCK_STATE_CONNECTED) &&
            (MB_GET_NODE_STATE(pnode_info) >= MB_SOCK_STATE_RESOLVED)) {
            ESP_LOGD(TAG, "%p, connection phase, slave: #%d(%d) [%s].",
                     ctx, (int)pevent_info->opt_fd, (int)pnode_info->sock_id, pnode_info->addr_info.ip_addr_str);
            err = port_connect(ctx, pnode_info);
            switch (err) {
                case ERR_OK:
                    FD_SET(pnode_info->sock_id, &pdrv_ctx->conn_set);
                    mb_drv_lock(ctx);
                    pdrv_ctx->node_conn_count++;
                    // Update time stamp for connected slaves
                    pnode_info->send_time = esp_timer_get_time();
                    pnode_info->recv_time = esp_timer_get_time();
                    mb_drv_unlock(ctx);
                    ESP_LOGI(TAG, "%p, slave: #%d, sock:%d, IP: %s, is connected.",
                                ctx, (int)pevent_info->opt_fd, (int)pnode_info->sock_id, 
                                pnode_info->addr_info.ip_addr_str);
                    MB_SET_NODE_STATE(pnode_info, MB_SOCK_STATE_CONNECTED);
                    (void)port_keep_alive(pnode_info->sock_id);
                    ESP_LOGD(TAG, "Opened/connected: %u, %u.",
                                (unsigned)pdrv_ctx->mb_node_open_count, (unsigned)pdrv_ctx->node_conn_count);
                    if (pdrv_ctx->mb_node_open_count == pdrv_ctx->node_conn_count) {
                        if (pdrv_ctx->event_cbs.on_conn_done_cb) {
                            pdrv_ctx->event_cbs.on_conn_done_cb(pdrv_ctx->event_cbs.arg);
                        }
                        ESP_LOGI(TAG, "%p, Connected: %u, %u, start polling.", 
                                    ctx, (unsigned)pdrv_ctx->mb_node_open_count, (unsigned)pdrv_ctx->node_conn_count);
                        mb_drv_set_status_flag(ctx, MB_FLAG_CONNECTED);
                    }
                    break;
                case ERR_INPROGRESS:
                    if (FD_ISSET(pnode_info->sock_id, &pdrv_ctx->conn_set)) {
                        FD_CLR(pnode_info->sock_id, &pdrv_ctx->conn_set);
                        ESP_LOGD(TAG, "%p, slave: #%d, sock:%d, IP:%s, connect fail error = %d.",
                                ctx, (int)pevent_info->opt_fd, (int)pnode_info->sock_id,
                                pnode_info->addr_info.ip_addr_str, (int)err);
                        mb_drv_lock(ctx);
                        if (pdrv_ctx->node_conn_count) {
                            pdrv_ctx->node_conn_count--;
                        }
                        mb_drv_unlock(ctx);
                        DRIVER_SEND_EVENT(ctx, MB_EVENT_CLOSE, pevent_info->opt_fd);
                        port_close_connection(pnode_info);
                    } else {
                        ESP_LOGD(TAG, "%p, slave: #%d, sock:%d, IP:%s, connection is in progress.",
                                ctx, (int)pevent_info->opt_fd, (int)pnode_info->sock_id,
                                pnode_info->addr_info.ip_addr_str);
                        MB_SET_NODE_STATE(pnode_info, MB_SOCK_STATE_CONNECTING);
                        vTaskDelay(MB_CONN_TICK_TIMEOUT);
                        // try to connect to slave and check connection again if it is not connected
                        DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pevent_info->opt_fd);
                    }
                    break;
                case ERR_CONN:
                    ESP_LOGE(TAG, "Modbus connection phase, slave: %d (%s), connection error (%d).",
                            (int)pevent_info->opt_fd, pnode_info->addr_info.ip_addr_str, (int)err);
                    break;
                default:
                    ESP_LOGE(TAG, "Invalid error state, slave: %d (%s), error = %d.",
                            (int)pevent_info->opt_fd, pnode_info->addr_info.ip_addr_str, (int)err);
                    break;
            }
        }
    } else {
        // if the event fd is UNDEF_FD (an event for all slaves),
        // then perform connection phase for all resolved slaves sending the connection event
        for (int node = 0; (node < MB_TCP_PORT_MAX_CONN); node++) {
            pnode_info = mb_drv_get_node(pdrv_ctx, node);
            if (pnode_info && 
                (MB_GET_NODE_STATE(pnode_info) < MB_SOCK_STATE_CONNECTED) &&
                (MB_GET_NODE_STATE(pnode_info) >= MB_SOCK_STATE_RESOLVED)) {
                if (((pnode_info->sock_id < 0) || !FD_ISSET(pnode_info->sock_id, &pdrv_ctx->conn_set))
                            && FD_ISSET(node, &pdrv_ctx->open_set)) {
                    DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pnode_info->index);
                }
            }
            mb_drv_check_suspend_shutdown(ctx);
        }
    }
}

MB_EVENT_HANDLER(mbm_on_error)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    mb_node_info_t *pnode_info = NULL;
    if (MB_CHECK_FD_RANGE(pevent_info->opt_fd)) {
        mb_drv_check_suspend_shutdown(ctx);
        mb_status_flags_t status = mb_drv_wait_status_flag(pdrv_ctx, MB_FLAG_DISCONNECTED, 1);
        if ((status & MB_FLAG_DISCONNECTED)) {
            ESP_LOGE(TAG, "%p, node: %d, is in disconnected state.", ctx, (int)pevent_info->opt_fd);
            mb_drv_clear_status_flag(ctx, MB_FLAG_CONNECTED);
            return;
        }
        int ret = mb_drv_check_node_state(pdrv_ctx, (int *)&pevent_info->opt_fd, MB_RECONNECT_TIME_MS);
        if ((ret != ERR_OK) && (ret != ERR_TIMEOUT)) {
            pnode_info = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
            ESP_LOGW(TAG, "%p, "MB_NODE_FMT(", error handling."), ctx, (int)pnode_info->fd,
                                            (int)pnode_info->sock_id, pnode_info->addr_info.ip_addr_str);
            ESP_LOGE(TAG, "Node: %d, try to repair lost connection, err= %d", (int)pevent_info->opt_fd, ret);
            FD_CLR(pnode_info->sock_id, &pdrv_ctx->conn_set);
            mb_drv_lock(ctx);
            if (pdrv_ctx->node_conn_count) {
                pdrv_ctx->node_conn_count--;
            }
            mb_drv_unlock(ctx);
            port_close_connection(pnode_info);
            DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pnode_info->index);
        }
    } else if (pevent_info->opt_fd < 0) {
        // send resolve event to all slaves
        for (int fd = 0; fd < pdrv_ctx->mb_node_open_count; fd++) {
            mb_drv_check_suspend_shutdown(ctx);
            mb_node_info_t *pslave = mb_drv_get_node(pdrv_ctx, fd);
            if (pslave && (MB_GET_NODE_STATE(pslave) == MB_SOCK_STATE_OPENED)
                && FD_ISSET(pslave->index, &pdrv_ctx->open_set)) {
                DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pslave->index);
            }
        }
    }
}

MB_EVENT_HANDLER(mbm_on_send_data)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    mb_drv_check_suspend_shutdown(ctx);
    mb_node_info_t *pinfo = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
    if (pinfo && !queue_is_empty(pinfo->tx_queue)) {
        uint8_t tx_buffer[MB_TCP_BUFF_MAX_SIZE] = {0};
        ESP_LOGD(TAG, "%p, get info: %d, sock_id: %d, queue_state: %d, state: %d.",
                    ctx, (int)pevent_info->opt_fd, (int)pinfo->sock_id, 
                    (int)queue_is_empty(pinfo->tx_queue), (int)MB_GET_NODE_STATE(pinfo));
        size_t sz = queue_pop(pinfo->tx_queue, tx_buffer, sizeof(tx_buffer), NULL);
        if (MB_GET_NODE_STATE(pinfo) < MB_SOCK_STATE_CONNECTED) {
            // if slave is not connected, drop data.
            ESP_LOGE(TAG, "%p, "MB_NODE_FMT(", is invalid, drop send data."),
                        ctx, (int)pinfo->index, (int)pinfo->sock_id, pinfo->addr_info.ip_addr_str);
            return;
        }
        int ret = port_write_poll(pinfo, tx_buffer, sz, MB_TCP_SEND_TIMEOUT_MS);
        if (ret < 0) {
            ESP_LOGE(TAG, "%p, "MB_NODE_FMT(", send data failure, err(errno) = %d(%u)."),
                        ctx, (int)pinfo->index, (int)pinfo->sock_id, 
                        pinfo->addr_info.ip_addr_str, (int)ret, (unsigned)errno);
            DRIVER_SEND_EVENT(ctx, MB_EVENT_ERROR, pinfo->index);
            pinfo->error = ret;
        } else {
            ESP_LOGD(TAG, "%p, "MB_NODE_FMT(", send data successful: TID:0x%04x, %d (bytes), errno %d"),
                        ctx, (int)pinfo->index, (int)pinfo->sock_id, 
                        pinfo->addr_info.ip_addr_str, (unsigned)pinfo->tid_counter, (int)ret, (unsigned)errno);
            pinfo->error = 0;
            // Every successful write increase TID counter
            if (pinfo->tid_counter < (USHRT_MAX - 1)) {
                pinfo->tid_counter++;
            } else {
                pinfo->tid_counter = (uint16_t)(pinfo->index << 8U);
            }
        }
        pdrv_ctx->event_cbs.mb_sync_event_cb(pdrv_ctx->event_cbs.port_arg, MB_SYNC_EVENT_SEND_OK);
        mb_drv_lock(ctx);
        pdrv_ctx->mb_node_curr = pinfo;
        pdrv_ctx->curr_node_index = pinfo->index;
        pinfo->send_time = esp_timer_get_time();
        pinfo->send_counter = (pinfo->send_counter < (USHRT_MAX - 1)) ? (pinfo->send_counter + 1) : 0;
        mb_drv_unlock(ctx);
        // Get send buffer from stack
        ESP_LOG_BUFFER_HEX_LEVEL("SENT", tx_buffer, sz, ESP_LOG_DEBUG);
    }
}

MB_EVENT_HANDLER(mbm_on_recv_data)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    size_t sz = 0;
    uint8_t pbuf[MB_TCP_BUFF_MAX_SIZE] = {0};
    mb_drv_check_suspend_shutdown(ctx);
    // Get frame from queue, check for correctness, push back correct frame and generate receive condition.
    // Removes incorrect or expired frames from the queue, leave just correct one then sent sync event
    mb_node_info_t *pnode_info = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
    if (pnode_info) {
        ESP_LOGD(TAG, "%p, slave #%d(%d) [%s], receive data ready.", ctx, (int)pevent_info->opt_fd,
                    (int)pnode_info->sock_id, pnode_info->addr_info.ip_addr_str);
        while ((sz <= 0) && !queue_is_empty(pnode_info->rx_queue)) {
            size_t sz = queue_pop(pnode_info->rx_queue, pbuf, MB_TCP_BUFF_MAX_SIZE, NULL);
            if ((sz > MB_TCP_FUNC) && (sz < sizeof(pbuf))) {
                uint16_t tid = MB_TCP_MBAP_GET_FIELD(pbuf, MB_TCP_TID);
                ESP_LOGD(TAG, "%p, packet TID: 0x%04" PRIx16 " received.", ctx, tid);
                if (tid == (pnode_info->tid_counter - 1)) {
                    queue_push(pnode_info->rx_queue, pbuf, sz, NULL);
                    mb_drv_lock(ctx);
                    pnode_info->recv_time = esp_timer_get_time();
                    mb_drv_unlock(ctx);
                    // send receive event to modbus object
                    pdrv_ctx->event_cbs.mb_sync_event_cb(pdrv_ctx->event_cbs.port_arg, MB_SYNC_EVENT_RECV_OK);
                    break;
                }
            }
            mb_drv_check_suspend_shutdown(ctx);
        }
    }
}

MB_EVENT_HANDLER(mbm_on_close)
{
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s, fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *pnode = NULL;
    // if close all sockets event is received
    if (pevent_info->opt_fd < 0) {
        ESP_LOGD(TAG, "%p, Close all nodes...", ctx);
        (void)mb_drv_clear_status_flag(pdrv_ctx, MB_FLAG_DISCONNECTED);
        for (int fd = 0; fd < MB_MAX_FDS; fd++) {
            mb_node_info_t *pnode = mb_drv_get_node(pdrv_ctx, fd);
            if (pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_OPENED)
                    && FD_ISSET(pnode->index, &pdrv_ctx->open_set)) {
                // Close node immediately
                mb_drv_close(pdrv_ctx, fd);
                MB_SET_NODE_STATE(pnode, MB_SOCK_STATE_READY);
                ESP_LOGD(TAG, "%p, Close node %d, sock #%d.", ctx, fd, pnode->sock_id);
            }
        }
        (void)mb_drv_set_status_flag(pdrv_ctx, MB_FLAG_DISCONNECTED);
        mb_drv_check_suspend_shutdown(ctx);
    } else if (MB_CHECK_FD_RANGE(pevent_info->opt_fd)) {
        pnode = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
        if (pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_OPENED)) {
            ESP_LOGD(TAG, "%p, Close node %d, sock #%d, intentionally.", ctx, (int)pevent_info->opt_fd, pnode->sock_id);
            if ((pnode->sock_id < 0) && FD_ISSET(pnode->sock_id, &pdrv_ctx->open_set)) {
                mb_drv_close(pdrv_ctx, pevent_info->opt_fd);
            }
        }
        mb_drv_check_suspend_shutdown(ctx);
    }
}

MB_EVENT_HANDLER(mbm_on_timeout)
{
    // Socket read/write timeout is triggered
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    // Todo: this event can be used to check network state (kkep empty for now)
    mb_drv_check_suspend_shutdown(ctx);
}

#endif
