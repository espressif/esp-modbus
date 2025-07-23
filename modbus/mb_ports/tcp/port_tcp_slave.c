/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <string.h>

#include "port_tcp_common.h"
#include "port_tcp_slave.h"
#include "port_tcp_driver.h"
#include "port_tcp_utils.h"

#include "mb_transaction.h"

#include "port_common.h" // use common port functions

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

typedef struct
{
    mb_port_base_t base;
    // TCP communication properties
    mb_tcp_opts_t tcp_opts;
    mb_uid_info_t addr_info;
    uint8_t ptemp_buf[MB_TCP_BUFF_MAX_SIZE];
    // The driver object for the slave
    port_driver_t *drv_obj;
    transaction_handle_t transaction;
    uint16_t trans_count;
} mbs_tcp_port_t;

/* ----------------------- Static variables & functions ----------------------*/
static const char *TAG = "mb_port.tcp.slave";

static uint64_t mbs_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event);

static esp_err_t mbs_port_tcp_register_handlers(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;

    ret = mb_drv_register_handler(drv_obj, MB_EVENT_READY_NUM, mbs_on_ready);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_READY);
    ret = mb_drv_register_handler(drv_obj, MB_EVENT_OPEN_NUM, mbs_on_open);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_OPEN);
    ret = mb_drv_register_handler(drv_obj, MB_EVENT_CONNECT_NUM, mbs_on_connect);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_CONNECT);
    ret = mb_drv_register_handler(drv_obj, MB_EVENT_ERROR_NUM, mbs_on_error);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_ERROR);
    ret = mb_drv_register_handler(drv_obj, MB_EVENT_SEND_DATA_NUM, mbs_on_send_data);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_SEND_DATA);
    ret = mb_drv_register_handler(drv_obj, MB_EVENT_RECV_DATA_NUM, mbs_on_recv_data);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_RECV_DATA);
    ret = mb_drv_register_handler(drv_obj, MB_EVENT_CLOSE_NUM, mbs_on_close);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_CLOSE);
    ret = mb_drv_register_handler(drv_obj, MB_EVENT_TIMEOUT_NUM, mbs_on_timeout);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_TIMEOUT);
    return ESP_OK;
}

static esp_err_t mbs_port_tcp_unregister_handlers(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    ESP_LOGD(TAG, "%p, event handler %p, unregister.", drv_obj, drv_obj->event_handler);

    ret = mb_drv_unregister_handler(drv_obj, MB_EVENT_READY_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_READY);
    ret = mb_drv_unregister_handler(drv_obj, MB_EVENT_OPEN_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_OPEN);
    ret = mb_drv_unregister_handler(drv_obj, MB_EVENT_CONNECT_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_CONNECT);
    ret = mb_drv_unregister_handler(drv_obj, MB_EVENT_SEND_DATA_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_SEND_DATA);
    ret = mb_drv_unregister_handler(drv_obj, MB_EVENT_RECV_DATA_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_RECV_DATA);
    ret = mb_drv_unregister_handler(drv_obj, MB_EVENT_CLOSE_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_CLOSE);
    ret = mb_drv_unregister_handler(drv_obj, MB_EVENT_TIMEOUT_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_TIMEOUT);
    return ESP_OK;
}

mb_err_enum_t mbs_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **port_obj)
{
    MB_RETURN_ON_FALSE((port_obj && tcp_opts), MB_EINVAL, TAG, "mb tcp port invalid arguments.");
    mbs_tcp_port_t *ptcp = NULL;
    esp_err_t err = ESP_ERR_INVALID_STATE;
    mb_err_enum_t ret = MB_EILLSTATE;
    ptcp = (mbs_tcp_port_t *)calloc(1, sizeof(mbs_tcp_port_t));
    MB_GOTO_ON_FALSE((ptcp && port_obj), MB_EILLSTATE, error, TAG, "mb tcp port creation error.");

    CRITICAL_SECTION_INIT(ptcp->base.lock);

    // Copy object descriptor from parent object (is used for logging)
    ptcp->base.descr = (*port_obj)->descr;
    ptcp->drv_obj = NULL;
    ptcp->transaction = transaction_init();
    MB_GOTO_ON_FALSE((ptcp->transaction), MB_EILLSTATE, error,
                     TAG, "mb transaction init failed.");

    ESP_MEM_CHECK(TAG, ptcp->transaction, goto error);

    err = mb_drv_register(&ptcp->drv_obj);
    MB_GOTO_ON_FALSE(((err == ESP_OK) && ptcp->drv_obj), MB_EILLSTATE, error,
                     TAG, "mb tcp port driver registration failed, err = (%x).", (int)err);

    err = mbs_port_tcp_register_handlers(ptcp->drv_obj);
    MB_GOTO_ON_FALSE(((err == ESP_OK) && ptcp->drv_obj), MB_EILLSTATE, error,
                     TAG, "mb tcp port driver registration failed, err = (%x).", (int)err);

    ptcp->drv_obj->parent = ptcp; // just for logging purposes
    ptcp->tcp_opts = *tcp_opts;
    ptcp->drv_obj->network_iface_ptr = tcp_opts->ip_netif_ptr;
    ptcp->drv_obj->mb_proto = tcp_opts->mode;
    ptcp->drv_obj->uid = tcp_opts->uid;
    ptcp->drv_obj->is_master = false;
    ptcp->drv_obj->event_cbs.mb_sync_event_cb = mbs_port_tcp_sync_event;
    ptcp->drv_obj->event_cbs.port_arg = (void *)ptcp;

#ifdef MB_MDNS_IS_INCLUDED
err = port_start_mdns_service(&ptcp->drv_obj->dns_name, false, tcp_opts->uid, ptcp->drv_obj->network_iface_ptr);
    MB_GOTO_ON_FALSE((err == ESP_OK), MB_EILLSTATE, error, 
                        TAG, "mb tcp port mdns service init failure.");
    ESP_LOGD(TAG, "Start mdns for @%p", ptcp);
#endif
    // ptcp->base.cb.tmr_expired = mbs_port_timer_expired;
    ptcp->base.cb.tx_empty = NULL;
    ptcp->base.cb.byte_rcvd = NULL;
    ptcp->base.arg = (void *)ptcp;
    *port_obj = &(ptcp->base);
    ESP_LOGD(TAG, "created object @%p", ptcp);
    return MB_ENOERR;

error:
    if (ptcp && ptcp->transaction)
    {
        transaction_destroy(ptcp->transaction);
    }
    if (ptcp && ptcp->drv_obj) {
#ifdef MB_MDNS_IS_INCLUDED
        port_stop_mdns_service(&ptcp->drv_obj->dns_name);
#endif
        if (ptcp->drv_obj->event_handler[0]) {
            mbs_port_tcp_unregister_handlers(ptcp->drv_obj);
        }
        (void)mb_drv_unregister(ptcp->drv_obj);
        CRITICAL_SECTION_CLOSE(ptcp->base.lock);
    }
    free(ptcp);
    return ret;
}

void mbs_port_tcp_delete(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    if (port_obj && port_obj->transaction) {
        transaction_destroy(port_obj->transaction);
    }
    if (port_obj && port_obj->drv_obj) {
#ifdef MB_MDNS_IS_INCLUDED
        port_stop_mdns_service(&port_obj->drv_obj->dns_name);
#endif
        if (port_obj->drv_obj->event_handler[0]) {
            mbs_port_tcp_unregister_handlers(port_obj->drv_obj);
        }
        (void)mb_drv_unregister(port_obj->drv_obj);
    }
    CRITICAL_SECTION_CLOSE(inst->lock);
    free(port_obj);
}

void mbs_port_tcp_enable(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    (void)mb_drv_start_task(port_obj->drv_obj);
    DRIVER_SEND_EVENT(port_obj->drv_obj, MB_EVENT_READY, UNDEF_FD);
}

void mbs_port_tcp_disable(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    // Change the state of all slaves to close
    DRIVER_SEND_EVENT(port_obj->drv_obj, MB_EVENT_CLOSE, UNDEF_FD);
    (void)mb_drv_wait_status_flag(port_obj->drv_obj, MB_FLAG_DISCONNECTED, pdMS_TO_TICKS(MB_RECONNECT_TIME_MS));
}

bool mbs_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **frame, uint16_t *length)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    port_driver_t *drv_obj = port_obj->drv_obj;
    mb_node_info_t *pnode = NULL;
    bool status = false;
    transaction_item_handle_t item;

    if (length && frame && *frame) {
        mb_drv_lock(drv_obj);
        item = transaction_get_first(port_obj->transaction);
        if (item && (transaction_item_get_state(item) == ACKNOWLEDGED)) {
            uint16_t tid = 0;
            int node_id = 0;
            size_t len = 0;
            uint8_t *buf = transaction_item_get_data(item, &len, &tid, &node_id);
            pnode = mb_drv_get_node(drv_obj, node_id);
            if (buf && pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_CONNECTED)) {
                memcpy(*frame, buf, len);
                *length = (uint16_t)len;
                status = true;
                ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", read packet, TID: 0x%04" PRIx16 ", %p."),
                         port_obj, pnode->index, pnode->sock_id,
                         pnode->addr_info.ip_addr_str, (unsigned)pnode->tid_counter, *frame);
                if (ESP_OK != transaction_item_set_state(item, CONFIRMED)) {
                    ESP_LOGE(TAG, "transaction queue set state fail.");
                }
            }
        } else {
            // Delete expired frames
            int frame_cnt = transaction_delete_expired(port_obj->transaction, port_get_timestamp(), MB_DROP_TRANSACTION_TIME_US);
            if (frame_cnt) {
                ESP_LOGE(TAG, "Deleted %d expired frames.", frame_cnt);
            }
        }
        mb_drv_unlock(drv_obj);
    }
    return status;
}

bool mbs_port_tcp_send_data(mb_port_base_t *inst, uint8_t *frame, uint16_t length)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);

    MB_RETURN_ON_FALSE((frame && (length > 0)), false, TAG, "incorrect arguments.");
    bool frame_sent = false;

    uint16_t tid = MB_TCP_MBAP_GET_FIELD(frame, MB_TCP_TID);
    port_driver_t *drv_obj = port_obj->drv_obj;
    transaction_item_handle_t item;

    mb_drv_lock(drv_obj);
    item = transaction_get_first(port_obj->transaction);
    if (item && transaction_item_get_state(item) == CONFIRMED) {
        uint16_t msg_id = 0;
        int node_id = 0;
        mb_node_info_t *pnode = NULL;
        uint8_t *buf = transaction_item_get_data(item, NULL, &msg_id, &node_id);
        pnode = mb_drv_get_node(drv_obj, node_id);
        if (pnode && buf && (tid == msg_id)) {
            int write_length = mb_drv_write(drv_obj, node_id, frame, length);
            if (pnode && write_length) {
                frame_sent = true;
                ESP_LOGD(TAG, "%p, node: #%d, socket(#%d)[%s], send packet TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p, len: %d, ",
                            drv_obj, pnode->index, pnode->sock_id,
                            pnode->addr_info.node_name_str, (unsigned)tid, (unsigned)msg_id, frame, length);
            } else {
                ESP_LOGE(TAG, "%p, node: #%d, socket(#%d)[%s], modbus write fail, TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p, len: %d, ",
                            drv_obj, pnode->index, pnode->sock_id,
                            pnode->addr_info.node_name_str, (unsigned)tid, (unsigned)msg_id, frame, length);
            }
            if (ESP_OK != transaction_item_set_state(item, REPLIED)) {
                ESP_LOGE(TAG, "transaction queue set reply state fail.");
            }
        } else {
            ESP_LOGE(TAG, "%p, node: #%d, socket(#%d)[%s], could not write transaction, TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p, len: %d, ",
                            drv_obj, pnode->index, pnode->sock_id, pnode->addr_info.node_name_str,
                            (unsigned)tid, (unsigned)msg_id, frame, length);
            if (item && transaction_delete_item(port_obj->transaction, item) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to remove queued TID:0x%04" PRIx16, tid);
            } else {
                ESP_LOGD(TAG, "Remove the message TID:0x%04" PRIx16, tid);
            }
            (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
        }
    } else {
        ESP_LOGE(TAG, "can not find the confirmed transaction TID: 0x%04" PRIx16 ", drop the frame", tid);
    }
    mb_drv_unlock(drv_obj);

    return frame_sent;
}

static uint64_t mbs_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event)
{
    switch (sync_event)
    {
        case MB_SYNC_EVENT_RECV_OK:
            mb_port_timer_disable(inst);
            mb_port_event_set_err_type(inst, EV_ERROR_INIT);
            mb_port_event_post(inst, EVENT(EV_FRAME_RECEIVED));
            break;

        case MB_SYNC_EVENT_READY:
            mb_port_event_post(inst, EVENT(EV_READY));
            break;

        case MB_SYNC_EVENT_RECV_FAIL:
            mb_port_timer_disable(inst);
            mb_port_event_set_err_type(inst, EV_ERROR_RECEIVE_DATA);
            mb_port_event_post(inst, EVENT(EV_ERROR_PROCESS));
            break;

        case MB_SYNC_EVENT_SEND_OK:
            mb_port_event_post(inst, EVENT(EV_FRAME_SENT));
            break;

        case MB_SYNC_EVENT_SEND_ERR:
            mb_port_timer_disable(inst);
            mb_port_event_set_err_type(inst, EV_ERROR_RESPOND_TIMEOUT);
            mb_port_event_post(inst, EVENT(EV_ERROR_PROCESS));
            break;

        default:
            break;
    }
    return mb_port_get_trans_id(inst);
}

MB_EVENT_HANDLER(mbs_on_ready)
{
    // The driver is registered
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mbs_tcp_port_t *port_obj = __containerof(drv_obj->parent, mbs_tcp_port_t, base);
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    ESP_LOGD(TAG, "addr_table:%p, addr_type:%d, mode:%d, port:%d", port_obj->tcp_opts.ip_addr_table,
             (int)port_obj->tcp_opts.addr_type,
             (int)port_obj->tcp_opts.mode,
             (int)port_obj->tcp_opts.port);

    int listen_sock = port_bind_addr(port_obj->tcp_opts.ip_addr_table,
                                     port_obj->tcp_opts.addr_type,
                                     port_obj->tcp_opts.mode,
                                     port_obj->tcp_opts.port);
    if (listen_sock < 0) {
        mb_drv_check_suspend_shutdown(ctx);
        ESP_LOGE(TAG, "%s, sock: %d, bind error", (char *)base, listen_sock);
        mb_drv_lock(drv_obj);
        if (drv_obj->retry_cnt) drv_obj->retry_cnt--;
        mb_drv_unlock(drv_obj);
        if (drv_obj->retry_cnt) {
            vTaskDelay(TRANSACTION_TICKS);
            DRIVER_SEND_EVENT(ctx, MB_EVENT_READY, UNDEF_FD);
        } else {
            DRIVER_SEND_EVENT(ctx, MB_EVENT_CLOSE, UNDEF_FD);
            ESP_LOGE(TAG, "%s, stop binding.", (char *)base);
            // mbs_port_tcp_disable(&port_obj->base);
        }
    } else {
        mb_drv_lock(ctx);
        drv_obj->listen_sock_fd = listen_sock;
        // so, all accepted sockets will inherit the keep-alive feature
        (void)port_keep_alive_enable(drv_obj->listen_sock_fd, CONFIG_FMB_TCP_KEEP_ALIVE_TOUT_SEC);
        (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
        mb_drv_unlock(ctx);
        drv_obj->event_cbs.mb_sync_event_cb(drv_obj->event_cbs.port_arg, MB_SYNC_EVENT_READY);
        ESP_LOGI(TAG, "%s  %s: fd: %d, bind is done", (char *)base, __func__, (int)event_info->opt_fd);
    }
}

MB_EVENT_HANDLER(mbs_on_open)
{
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
}

MB_EVENT_HANDLER(mbs_on_connect)
{
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    mb_node_info_t *pnode = mb_drv_get_node(drv_obj, event_info->opt_fd);
    if (!pnode) {
        ESP_LOGD(TAG, "%s %s: fd: %d, is closed.", (char *)base, __func__, (int)event_info->opt_fd);
        return;
    }
    (void)port_keep_alive_enable(pnode->sock_id, CONFIG_FMB_TCP_KEEP_ALIVE_TOUT_SEC);
    mb_drv_lock(ctx);
    MB_SET_NODE_STATE(pnode, MB_SOCK_STATE_CONNECTED);
    FD_SET(pnode->sock_id, &drv_obj->conn_set);
    if (drv_obj->node_conn_count < MB_MAX_FDS) {
        drv_obj->node_conn_count++;
    }
    mb_drv_unlock(ctx);
}

MB_EVENT_HANDLER(mbs_on_recv_data)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    mbs_tcp_port_t *port_obj = (mbs_tcp_port_t *)drv_obj->parent;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    mb_node_info_t *pnode = mb_drv_get_node(drv_obj, event_info->opt_fd);
    transaction_item_handle_t item = NULL;
    if (pnode) {
        if (!queue_is_empty(pnode->rx_queue)) {
            ESP_LOGD(TAG, "%p, node #%d, socket(#%d) [%s], receive data ready.", ctx, (int)event_info->opt_fd,
                     (int)pnode->sock_id, pnode->addr_info.ip_addr_str);
            frame_entry_t frame_entry;
            size_t sz = queue_pop(pnode->rx_queue, NULL, MB_BUFFER_SIZE, &frame_entry);
            if (sz > MB_TCP_FUNC) {
                uint16_t tid_counter = MB_TCP_MBAP_GET_FIELD(frame_entry.buf, MB_TCP_TID);
                ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", received packet TID: 0x%04" PRIx16 ", frame: %p, %u"),
                         drv_obj, pnode->index, pnode->sock_id,
                         pnode->addr_info.ip_addr_str, (unsigned)tid_counter, frame_entry.buf, frame_entry.len);
                mb_drv_lock(drv_obj);
                transaction_message_t msg;
                msg.buffer = frame_entry.buf;
                msg.len = frame_entry.len;
                msg.msg_id = frame_entry.tid;
                msg.node_id = pnode->index;
                msg.pnode = pnode;
                // Enqueue the transaction, keep time of receiving.
                item = transaction_enqueue(port_obj->transaction, &msg, port_get_timestamp());
                pnode->tid_counter = tid_counter; // assign the TID from frame to use it on send
                mb_drv_unlock(drv_obj);
            }
        }
        item = transaction_get_first(port_obj->transaction);
        if (item) {
            if (transaction_item_get_state(item) == QUEUED) {
                // Check if the main FSM is not busy
                if (mb_port_event_res_take(&port_obj->base, TRANSACTION_TICKS)) {
                    (void)mb_drv_clear_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
                } else {
                    if (port_get_timestamp() - transaction_item_get_tick(item) > MB_DROP_TRANSACTION_TIME_US) {
                        ESP_LOGD(TAG, "Transaction TID:0x%04" PRIx16 " is expired.", transaction_item_get_id(item));
                    } else {
                        // postpone the packet processing to next cycle
                        DRIVER_SEND_EVENT(ctx, MB_EVENT_RECV_DATA, pnode->index);
                    }
                    mb_drv_lock(drv_obj);
                    transaction_delete_expired(port_obj->transaction, port_get_timestamp(), MB_DROP_TRANSACTION_TIME_US);
                    mb_drv_unlock(drv_obj);
                    mb_drv_check_suspend_shutdown(ctx);
                    return;
                }
                // send receive event to modbus object to get the new data
                drv_obj->event_cbs.mb_sync_event_cb(drv_obj->event_cbs.port_arg, MB_SYNC_EVENT_RECV_OK);
                mb_drv_lock(drv_obj);
                uint16_t msg_id = 0;
                int node_id = 0;
                (void)transaction_item_get_data(item, NULL, &msg_id, &node_id);
                pnode = mb_drv_get_node(drv_obj, node_id);
                ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", acknoledged packet TID: 0x%04" PRIx16 ", start transaction."),
                             drv_obj, pnode->index, pnode->sock_id,
                             pnode->addr_info.ip_addr_str, (unsigned)msg_id);
                if (ESP_OK == transaction_item_set_state(item, ACKNOWLEDGED)) {
                    ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", acknoledged packet TID: 0x%04" PRIx16 "."),
                             drv_obj, pnode->index, pnode->sock_id,
                             pnode->addr_info.ip_addr_str, (unsigned)msg_id);
                }
                mb_drv_unlock(drv_obj);
            } else {
                if (transaction_item_get_state(item) != TRANSMITTED) {
                    // Transaction procesing is ongoing, just delete expired transactions
                    mb_drv_lock(drv_obj);
                    transaction_delete_expired(port_obj->transaction, port_get_timestamp(), MB_DROP_TRANSACTION_TIME_US);
                    mb_drv_unlock(drv_obj);
                }
            }
        } else {
            ESP_LOGD(TAG, "%p, no queued items found", ctx);
        }
    }
    mb_drv_check_suspend_shutdown(ctx);
}

MB_EVENT_HANDLER(mbs_on_send_data)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    mbs_tcp_port_t *port_obj = (mbs_tcp_port_t *)drv_obj->parent;
    transaction_item_handle_t item = NULL;
    esp_err_t err = ESP_ERR_INVALID_STATE;
    frame_entry_t frame_entry = {0};
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    mb_node_info_t *pnode = mb_drv_get_node(drv_obj, event_info->opt_fd);
    if (pnode && !queue_is_empty(pnode->tx_queue)) {
        // Pop the frame entry, keep the buffer
        size_t sz = queue_pop(pnode->tx_queue, NULL, MB_BUFFER_SIZE, &frame_entry);
        if (sz) {
            uint16_t tid = MB_TCP_MBAP_GET_FIELD(frame_entry.buf, MB_TCP_TID);
            // Try to find actual transaction for current TID,
            // if not found just ignore the frame as expired
            item = transaction_get_first(port_obj->transaction);
            if (item && pnode) {
                uint16_t msg_id = 0;
                int node_id = 0;
                (void)transaction_item_get_data(item, NULL, &msg_id, &node_id);
                // Check if the TID is equal to the current received TID for this node.
                // If not, means the slave was not able to process the previous transaction on time.
                // The reason is too much active connections or incorrect response time or request rate in the master.
                if ((node_id != pnode->index) || (tid != msg_id) || (tid != pnode->tid_counter) || (MB_GET_NODE_STATE(pnode) < MB_SOCK_STATE_CONNECTED)) {
                    mb_drv_lock(drv_obj);
                    err = transaction_delete(port_obj->transaction, tid);
                    mb_drv_unlock(drv_obj);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to remove queued TID:0x%04" PRIx16, (int)tid);
                    } else {
                        ESP_LOGD(TAG, "Remove the message TID:0x%04" PRIx16, (int)tid);
                    }
                    (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
                    uint64_t tick = (transaction_tick_t)transaction_item_get_tick(item);
                    uint64_t time_div_us = (esp_timer_get_time() - tick);
                    ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", frame TID:0x%04" PRIx16 "!=0x%04" PRIx16 ", slave is busy."),
                                ctx, (int)pnode->index, (int)pnode->sock_id,
                                pnode->addr_info.ip_addr_str, pnode->tid_counter, tid);
                    ESP_LOGW(TAG, "%p, " MB_NODE_FMT(", handling time [ms]: %" PRIu64 ", exceeds slave response time in master."),
                                ctx, (int)pnode->index, (int)pnode->sock_id,
                                pnode->addr_info.ip_addr_str, (time_div_us / 1000));
                    // Hard hack to fix the expired frames (unsafe in some cases, do not implement)
                    // MB_TCP_MBAP_SET_FIELD(frame_entry.buf, MB_TCP_TID, pnode->tid_counter);
                } else {
                    mb_drv_lock(drv_obj);
                    int ret = port_write_poll(pnode, frame_entry.buf, sz, MB_TCP_SEND_TIMEOUT_MS);
                    if (ret < 0) {
                        ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", send data failure, err(errno) = %d(%u)."),
                                ctx, (int)pnode->index, (int)pnode->sock_id,
                                pnode->addr_info.ip_addr_str, (int)ret, (unsigned)errno);
                        DRIVER_SEND_EVENT(ctx, MB_EVENT_ERROR, pnode->index);
                        pnode->error = ret;
                    } else {
                        pnode->error = 0;
                        ESP_LOG_BUFFER_HEX_LEVEL("SENT", frame_entry.buf, ret, ESP_LOG_DEBUG);
                    }
                    (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
                    err = transaction_set_state(port_obj->transaction, tid, TRANSMITTED);
                    if (err == ESP_OK) {
                        ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", sent packet TID: 0x%04" PRIx16 ", %p."),
                                    drv_obj, pnode->index, pnode->sock_id,
                                    pnode->addr_info.ip_addr_str, tid, frame_entry.buf);
                    } else {
                        ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", transaction set state fail for TID: 0x%04" PRIx16 ", %p."),
                                    drv_obj, pnode->index, pnode->sock_id,
                                    pnode->addr_info.ip_addr_str, tid, frame_entry.buf);
                    }
                    if (transaction_delete_item(port_obj->transaction, item) != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to remove queued TID:0x%04" PRIx16, tid);
                    } else {
                        ESP_LOGD(TAG, "Remove the message TID:0x%04" PRIx16, tid);
                    }
                    pnode->send_time = port_get_timestamp();
                    pnode->send_counter = (pnode->send_counter < (USHRT_MAX - 1)) ? (pnode->send_counter + 1) : 0;
                    mb_drv_unlock(drv_obj);
                }
            } else {
                // It looks like no current registered transaction. It might be happen if the transaction has deleted as expired.
                // Note: the transaction processing time is increased proportional to a number of connected Masters.
                // If it is still needed to connect several number of Masters simultaneously,
                // then the slave response time option needs to be increased in all Masters.
                ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", transaction not found for TID: 0x%04" PRIx16 ", drop data %p."),
                            ctx, (int)pnode->index, (int)pnode->sock_id,
                            pnode->addr_info.ip_addr_str, tid, pnode);
                (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
            }
        } else {
            ESP_LOGE(TAG, "%p, "MB_NODE_FMT(", frame is invalid, drop data."),
                        ctx, (int)pnode->index, (int)pnode->sock_id, pnode->addr_info.ip_addr_str);
        }
        free(frame_entry.buf);
    }
    mb_drv_check_suspend_shutdown(ctx);
}

MB_EVENT_HANDLER(mbs_on_error)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    mbs_tcp_port_t *port_obj = __containerof(drv_obj->parent, mbs_tcp_port_t, base);
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    mb_node_info_t *pnode = mb_drv_get_node(drv_obj, event_info->opt_fd);
    if (!pnode) {
        ESP_LOGD(TAG, "%s %s: fd: %d, is closed.", (char *)base, __func__, (int)event_info->opt_fd);
        return;
    }
    // Check if the node is not alive for timeout
    int ret = mb_drv_check_node_state(drv_obj, (int *)&event_info->opt_fd, MB_EVENT_SEND_RCV_TOUT_MS);
    if ((ret != ERR_OK) && (ret != ERR_TIMEOUT)) {
        ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", communication fail, err= %d"),
                        port_obj, pnode->index, pnode->sock_id,
                        pnode->addr_info.ip_addr_str, (int)ret);
        mb_drv_lock(drv_obj);
        // delete all queued transactions for the node to be closed.
        (void)transaction_delete_by_node_id(port_obj->transaction, event_info->opt_fd);
        mb_drv_unlock(drv_obj);
        mb_drv_close(drv_obj, event_info->opt_fd);
    }
    mb_drv_check_suspend_shutdown(ctx);
}

MB_EVENT_HANDLER(mbs_on_close)
{
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s, fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mbs_tcp_port_t *port_obj = __containerof(drv_obj->parent, mbs_tcp_port_t, base);
    mb_node_info_t *pnode =NULL;
    // if close all sockets event is received
    if (event_info->opt_fd < 0)
    {
        (void)mb_drv_clear_status_flag(drv_obj, MB_FLAG_DISCONNECTED);
        for (int fd = 0; fd < MB_MAX_FDS; fd++)
        {
            mb_node_info_t *pnode = mb_drv_get_node(drv_obj, fd);
            if (pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_OPENED)
                      && FD_ISSET(pnode->index, &drv_obj->open_set))
            {
                mb_drv_close(drv_obj, fd);
            }
        }
        (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_DISCONNECTED);
        mb_drv_check_suspend_shutdown(ctx);
    } else if (MB_CHECK_FD_RANGE(event_info->opt_fd)) {
        pnode = mb_drv_get_node(drv_obj, event_info->opt_fd);
        if (pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_OPENED)) {
            if ((pnode->sock_id < 0) && FD_ISSET(pnode->sock_id, &drv_obj->open_set)) {
                mb_drv_lock(drv_obj);
                (void)transaction_delete_by_node_id(port_obj->transaction, event_info->opt_fd);
                mb_drv_unlock(drv_obj);
                mb_drv_close(ctx, event_info->opt_fd);
            }
        }
        mb_drv_check_suspend_shutdown(ctx);
    }
}

MB_EVENT_HANDLER(mbs_on_timeout)
{
    // Slave timeout triggered
    //mb_event_info_t *event_info = (mb_event_info_t *)data;
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mbs_tcp_port_t *port_obj = __containerof(drv_obj->parent, mbs_tcp_port_t, base);
    static int curr_fd = 0;
    mb_node_info_t *pnode = mb_drv_get_node(drv_obj, curr_fd);
    ESP_LOGD(TAG, "%s %s: fd: %d, count: %d", (char *)base, __func__, (int)curr_fd, drv_obj->node_conn_count);
    mb_drv_check_suspend_shutdown(ctx);
    int ret = mb_drv_check_node_state(drv_obj, &curr_fd, MB_TCP_KEEP_ALIVE_TOUT_MS);
    if ((ret != ERR_OK) && (ret != ERR_TIMEOUT)) {
        ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", connection lost, err=%d, drop connection."),
                        port_obj, pnode->index, pnode->sock_id,
                        pnode->addr_info.ip_addr_str, (int)ret);
        mb_drv_lock(drv_obj);
        (void)transaction_delete_by_node_id(port_obj->transaction, curr_fd);
        mb_drv_unlock(drv_obj);
        mb_drv_close(drv_obj, curr_fd);
    }
    if ((curr_fd + 1) >= (drv_obj->node_conn_count)) {
        curr_fd = 0;
    } else {
        curr_fd++;
    }
}

#endif