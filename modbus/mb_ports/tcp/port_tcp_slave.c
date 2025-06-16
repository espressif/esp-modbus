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
    port_driver_t *pdriver;
    transaction_handle_t transaction;
    uint16_t trans_count;
} mbs_tcp_port_t;

/* ----------------------- Static variables & functions ----------------------*/
static const char *TAG = "mb_port.tcp.slave";

static uint64_t mbs_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event);

static esp_err_t mbs_port_tcp_register_handlers(void *ctx)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;

    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_READY_NUM, mbs_on_ready);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_READY);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_OPEN_NUM, mbs_on_open);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_OPEN);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_CONNECT_NUM, mbs_on_connect);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_CONNECT);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_ERROR_NUM, mbs_on_error);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_ERROR);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_SEND_DATA_NUM, mbs_on_send_data);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_SEND_DATA);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_RECV_DATA_NUM, mbs_on_recv_data);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_RECV_DATA);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_CLOSE_NUM, mbs_on_close);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_CLOSE);
    ret = mb_drv_register_handler(pdrv_ctx, MB_EVENT_TIMEOUT_NUM, mbs_on_timeout);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_TIMEOUT);
    return ESP_OK;
}

static esp_err_t mbs_port_tcp_unregister_handlers(void *ctx)
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
    ret = mb_drv_unregister_handler(pdrv_ctx, MB_EVENT_CONNECT_NUM);
    MB_RETURN_ON_FALSE((ret == ESP_OK), MB_EINVAL, TAG,
                       "%x, mb tcp port event registration failed.", (int)MB_EVENT_CONNECT);
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

mb_err_enum_t mbs_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **port_obj)
{
    MB_RETURN_ON_FALSE((port_obj && tcp_opts), MB_EINVAL, TAG, "mb tcp port invalid arguments.");
    mbs_tcp_port_t *ptcp = NULL;
    esp_err_t err = ESP_ERR_INVALID_STATE;
    ptcp = (mbs_tcp_port_t *)calloc(1, sizeof(mbs_tcp_port_t));
    MB_RETURN_ON_FALSE((ptcp && port_obj), MB_EILLSTATE, TAG, "mb tcp port creation error.");
    CRITICAL_SECTION_INIT(ptcp->base.lock);
    mb_err_enum_t ret = MB_EILLSTATE;

    // Copy object descriptor from parent object (is used for logging)
    ptcp->base.descr = ((mb_port_base_t *)*port_obj)->descr;
    ptcp->pdriver = NULL;
    ptcp->transaction = transaction_init();
    MB_GOTO_ON_FALSE((ptcp->transaction), MB_EILLSTATE, error,
                     TAG, "mb transaction init failed.");

    ESP_MEM_CHECK(TAG, ptcp->transaction, goto error);

    err = mb_drv_register(&ptcp->pdriver);
    MB_GOTO_ON_FALSE(((err == ESP_OK) && ptcp->pdriver), MB_EILLSTATE, error,
                     TAG, "mb tcp port driver registration failed, err = (%x).", (int)err);

    err = mbs_port_tcp_register_handlers(ptcp->pdriver);
    MB_GOTO_ON_FALSE(((err == ESP_OK) && ptcp->pdriver), MB_EILLSTATE, error,
                     TAG, "mb tcp port driver registration failed, err = (%x).", (int)err);

    ptcp->pdriver->parent = ptcp; // just for logging purposes
    ptcp->tcp_opts = *tcp_opts;
    ptcp->pdriver->network_iface_ptr = tcp_opts->ip_netif_ptr;
    ptcp->pdriver->mb_proto = tcp_opts->mode;
    ptcp->pdriver->uid = tcp_opts->uid;
    ptcp->pdriver->is_master = false;
    ptcp->pdriver->event_cbs.mb_sync_event_cb = mbs_port_tcp_sync_event;
    ptcp->pdriver->event_cbs.port_arg = (void *)ptcp;

#ifdef MB_MDNS_IS_INCLUDED
err = port_start_mdns_service(&ptcp->pdriver->dns_name, false, tcp_opts->uid, ptcp->pdriver->network_iface_ptr);
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
#ifdef MB_MDNS_IS_INCLUDED
    port_stop_mdns_service(&ptcp->pdriver->dns_name);
#endif
    if (ptcp && ptcp->pdriver)
    {
        if (ptcp->pdriver->event_handler[0]) {
            mbs_port_tcp_unregister_handlers(ptcp->pdriver);
        }
        (void)mb_drv_unregister(ptcp->pdriver);
        CRITICAL_SECTION_CLOSE(ptcp->base.lock);
    }
    free(ptcp);
    return ret;
}

void mbs_port_tcp_delete(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    if (port_obj && port_obj->transaction)
    {
        transaction_destroy(port_obj->transaction);
    }
#ifdef MB_MDNS_IS_INCLUDED
    port_stop_mdns_service(&port_obj->pdriver->dns_name);
#endif
    if (port_obj && port_obj->pdriver)
    {
        if (port_obj->pdriver->event_handler[0])
        {
            mbs_port_tcp_unregister_handlers(port_obj->pdriver);
        }
        (void)mb_drv_unregister(port_obj->pdriver);
    }
    CRITICAL_SECTION_CLOSE(inst->lock);
    free(port_obj);
}

void mbs_port_tcp_enable(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    (void)mb_drv_start_task(port_obj->pdriver);
    DRIVER_SEND_EVENT(port_obj->pdriver, MB_EVENT_READY, UNDEF_FD);
}

void mbs_port_tcp_disable(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    // Change the state of all slaves to close
    DRIVER_SEND_EVENT(port_obj->pdriver, MB_EVENT_CLOSE, UNDEF_FD);
    (void)mb_drv_wait_status_flag(port_obj->pdriver, MB_FLAG_DISCONNECTED, pdMS_TO_TICKS(MB_RECONNECT_TIME_MS));
}

bool mbs_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    port_driver_t *pdrv_ctx = port_obj->pdriver;
    mb_node_info_t *pnode = NULL;
    bool status = false;
    transaction_item_handle_t item;

    if (plength && ppframe && *ppframe)
    {
        mb_drv_lock(pdrv_ctx);
        item = transaction_get_first(port_obj->transaction);
        if (item && (transaction_item_get_state(item) == ACKNOWLEDGED))
        {
            uint16_t tid = 0;
            int node_id = 0;
            size_t len = 0;
            uint8_t *pbuf = transaction_item_get_data(item, &len, &tid, &node_id);
            pnode = mb_drv_get_node(pdrv_ctx, node_id);
            if (pbuf && pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_CONNECTED))
            {
                memcpy(*ppframe, pbuf, len);
                //*ppframe = pbuf;
                *plength = (uint16_t)len;
                status = true;
                ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", get packet TID: 0x%04" PRIx16 ", %p."),
                         port_obj, pnode->index, pnode->sock_id,
                         pnode->addr_info.ip_addr_str, (unsigned)pnode->tid_counter, *ppframe);
                if (ESP_OK != transaction_item_set_state(item, CONFIRMED)) {
                    ESP_LOGE(TAG, "transaction queue set state fail.");
                }
            }
        } else {
            // Delete expired frames
            int frame_cnt = transaction_delete_expired(port_obj->transaction, 
                                        port_get_timestamp(), 
                                        (1000 * MB_MASTER_TIMEOUT_MS_RESPOND));
            if (frame_cnt) {
                ESP_LOGE(TAG, "Deleted %d expired frames.", frame_cnt);
            }
        }
        mb_drv_unlock(pdrv_ctx);
    }
    return status;
}

bool mbs_port_tcp_send_data(mb_port_base_t *inst, uint8_t *pframe, uint16_t length)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);

    MB_RETURN_ON_FALSE((pframe && (length > 0)), false, TAG, "incorrect arguments.");
    bool frame_sent = false;

    uint16_t tid = MB_TCP_MBAP_GET_FIELD(pframe, MB_TCP_TID);
    port_driver_t *pdrv_ctx = port_obj->pdriver;
    transaction_item_handle_t item;

    mb_drv_lock(pdrv_ctx);
    item = transaction_dequeue(port_obj->transaction, CONFIRMED, NULL);
    if (item) {
        uint16_t msg_id = 0;
        int node_id = 0;
        uint8_t *pbuf = transaction_item_get_data(item, NULL, &msg_id, &node_id);
        if (pbuf && (tid == msg_id)) {
            mb_node_info_t *pnode = mb_drv_get_node(pdrv_ctx, node_id);
            int write_length = mb_drv_write(pdrv_ctx, node_id, pframe, length);
            if (pnode && write_length) {
                frame_sent = true;
                ESP_LOGD(TAG, "%p, node: #%d, socket(#%d)[%s], send packet TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p, len: %d, ",
                            pdrv_ctx, pnode->index, pnode->sock_id,
                            pnode->addr_info.node_name_str, (unsigned)tid, (unsigned)msg_id, pframe, length);
            } else {
                ESP_LOGE(TAG, "%p, node: #%d, socket(#%d)[%s], mbs_write fail, TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p, len: %d, ",
                            pdrv_ctx, pnode->index, pnode->sock_id,
                            pnode->addr_info.node_name_str, (unsigned)tid, (unsigned)msg_id, pframe, length);
            }
            if (ESP_OK != transaction_item_set_state(item, REPLIED)) {
                ESP_LOGE(TAG, "transaction queue set state fail.");
            }
        }
    } else {
        ESP_LOGE(TAG, "queue can not find the item to send.");
    }
    mb_drv_unlock(pdrv_ctx);

    if (!frame_sent)
    {
        ESP_LOGE(TAG, "incorrect frame to send.");
    }
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

MB_EVENT_HANDLER(mbs_on_ready)
{
    // The driver is registered
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mbs_tcp_port_t *port_obj = __containerof(pdrv_ctx->parent, mbs_tcp_port_t, base);
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    ESP_LOGD(TAG, "addr_table:%p, addr_type:%d, mode:%d, port:%d", port_obj->tcp_opts.ip_addr_table,
             (int)port_obj->tcp_opts.addr_type,
             (int)port_obj->tcp_opts.mode,
             (int)port_obj->tcp_opts.port);

    int listen_sock = port_bind_addr(port_obj->tcp_opts.ip_addr_table,
                                     port_obj->tcp_opts.addr_type,
                                     port_obj->tcp_opts.mode,
                                     port_obj->tcp_opts.port);
    if (listen_sock < 0)
    {
        mb_drv_check_suspend_shutdown(ctx);
        ESP_LOGE(TAG, "%s, sock: %d, bind error", (char *)base, listen_sock);
        mb_drv_lock(pdrv_ctx);
        if (pdrv_ctx->retry_cnt) pdrv_ctx->retry_cnt--;
        mb_drv_unlock(pdrv_ctx);
        if (pdrv_ctx->retry_cnt) {
            vTaskDelay(TRANSACTION_TICKS);
            DRIVER_SEND_EVENT(ctx, MB_EVENT_READY, UNDEF_FD);
        } else {
            DRIVER_SEND_EVENT(ctx, MB_EVENT_CLOSE, UNDEF_FD);
            ESP_LOGE(TAG, "%s, stop binding.", (char *)base);
            // mbs_port_tcp_disable(&port_obj->base);
        }
    }
    else
    {
        mb_drv_lock(ctx);
        pdrv_ctx->listen_sock_fd = listen_sock;
        // so, all accepted sockets will inherit the keep-alive feature
        (void)port_keep_alive(pdrv_ctx->listen_sock_fd);
        mb_drv_unlock(ctx);
        ESP_LOGI(TAG, "%s  %s: fd: %d, bind is done", (char *)base, __func__, (int)pevent_info->opt_fd);
    }
}

MB_EVENT_HANDLER(mbs_on_open)
{
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
}

MB_EVENT_HANDLER(mbs_on_connect)
{
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    mb_node_info_t *pnode = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
    if (!pnode) {
        ESP_LOGD(TAG, "%s %s: fd: %d, is closed.", (char *)base, __func__, (int)pevent_info->opt_fd);
        return;
    }
    (void)port_keep_alive(pnode->sock_id);
    mb_drv_lock(ctx);
    MB_SET_NODE_STATE(pnode, MB_SOCK_STATE_CONNECTED);
    FD_SET(pnode->sock_id, &pdrv_ctx->conn_set);
    if (pdrv_ctx->node_conn_count < MB_MAX_FDS) {
        pdrv_ctx->node_conn_count++;
    }
    mb_drv_unlock(ctx);
}

MB_EVENT_HANDLER(mbs_on_recv_data)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    mbs_tcp_port_t *port_obj = (mbs_tcp_port_t *)pdrv_ctx->parent;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    mb_node_info_t *pnode = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
    transaction_item_handle_t item = NULL;
    if (pnode)
    {
        if (!queue_is_empty(pnode->rx_queue))
        {
            ESP_LOGD(TAG, "%p, node #%d(%d) [%s], receive data ready.", ctx, (int)pevent_info->opt_fd,
                     (int)pnode->sock_id, pnode->addr_info.ip_addr_str);
            frame_entry_t frame_entry;
            size_t sz = queue_pop(pnode->rx_queue, NULL, MB_BUFFER_SIZE, &frame_entry);
            if (sz > MB_TCP_FUNC)
            {
                uint16_t tid_counter = MB_TCP_MBAP_GET_FIELD(frame_entry.pbuf, MB_TCP_TID);
                ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", received packet TID: 0x%04" PRIx16 ", %p."),
                         pdrv_ctx, pnode->index, pnode->sock_id,
                         pnode->addr_info.ip_addr_str, (unsigned)tid_counter, frame_entry.pbuf);
                mb_drv_lock(pdrv_ctx);
                transaction_message_t msg;
                msg.buffer = frame_entry.pbuf;
                msg.len = frame_entry.len;
                msg.msg_id = frame_entry.tid;
                msg.node_id = pnode->index;
                msg.pnode = pnode;
                item = transaction_enqueue(port_obj->transaction, &msg, port_get_timestamp());
                pnode->tid_counter = tid_counter; // assign the TID from frame to use it on send
                mb_drv_unlock(pdrv_ctx);
            }
        }
        mb_drv_lock(pdrv_ctx);
        item = transaction_get_first(port_obj->transaction);
        if (item)
        {
            if (transaction_item_get_state(item) == QUEUED)
            {
                // send receive event to modbus object to get the new data
                uint16_t msg_id = 0;
                uint64_t tick = 0;
                (void)transaction_item_get_data(item, NULL, &msg_id, NULL);
                tick = port_get_timestamp();
                pdrv_ctx->event_cbs.mb_sync_event_cb(pdrv_ctx->event_cbs.port_arg, MB_SYNC_EVENT_RECV_OK);
                transaction_set_tick(port_obj->transaction, msg_id, (transaction_tick_t)tick);
                if (ESP_OK == transaction_item_set_state(item, ACKNOWLEDGED)) {
                    ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", acknoledged packet TID: 0x%04" PRIx16 "."),
                             pdrv_ctx, pnode->index, pnode->sock_id,
                             pnode->addr_info.ip_addr_str, (unsigned)msg_id);
                }
            }
            else
            {
                if (transaction_item_get_state(item) != TRANSMITTED) {
                    // Todo: for test removing expired item
                    transaction_delete_expired(port_obj->transaction, port_get_timestamp(), 1000 * 1000);
                }
                if (MB_FLAG_TRANSACTION_DONE == mb_drv_wait_status_flag(port_obj->pdriver,
                                                                        MB_FLAG_TRANSACTION_DONE, 
                                                                        TRANSACTION_TICKS)) {
                    (void)mb_drv_clear_status_flag(pdrv_ctx, MB_FLAG_TRANSACTION_DONE);
                }
                // postpone the packet processing
                DRIVER_SEND_EVENT(ctx, MB_EVENT_RECV_DATA, pnode->index);
            }
        } else {
            ESP_LOGE(TAG, "%p, no queued items found", ctx);
        }
        mb_drv_unlock(pdrv_ctx);
    }
    mb_drv_check_suspend_shutdown(ctx);
}

MB_EVENT_HANDLER(mbs_on_send_data)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    mbs_tcp_port_t *port_obj = (mbs_tcp_port_t *)pdrv_ctx->parent;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    mb_node_info_t *pnode = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
    if (pnode && !queue_is_empty(pnode->tx_queue))
    {
        frame_entry_t frame_entry;
        // pop the frame entry, keep the buffer
        size_t sz = queue_pop(pnode->tx_queue, NULL, MB_BUFFER_SIZE, &frame_entry);
        if (!sz || (MB_GET_NODE_STATE(pnode) < MB_SOCK_STATE_CONNECTED)) {
            ESP_LOGE(TAG, "%p, "MB_NODE_FMT(", is invalid, drop data."),
                            ctx, (int)pnode->index, (int)pnode->sock_id, pnode->addr_info.ip_addr_str);
            return;
        }
        uint16_t tid = MB_TCP_MBAP_GET_FIELD(frame_entry.pbuf, MB_TCP_TID);
        pnode->error = 0;
        int ret = port_write_poll(pnode, frame_entry.pbuf, sz, MB_TCP_SEND_TIMEOUT_MS);
        if (ret < 0)
        {
            ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", send data failure, err(errno) = %d(%u)."),
                     ctx, (int)pnode->index, (int)pnode->sock_id,
                     pnode->addr_info.ip_addr_str, (int)ret, (unsigned)errno);
            DRIVER_SEND_EVENT(ctx, MB_EVENT_ERROR, pnode->index);
            pnode->error = ret;
        }
        else
        {
            pnode->error = 0;
            if (tid != pnode->tid_counter)
            {
                ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", send incorrect frame  TID:0x%04" PRIx16 "!= 0x%04" PRIx16 ", %d (bytes), errno %d"),
                         ctx, (int)pnode->index, (int)pnode->sock_id,
                         pnode->addr_info.ip_addr_str, pnode->tid_counter, tid, (int)ret, (unsigned)errno);
            }
            else
            {
                ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", send data successful: TID:0x%04" PRIx16 ":0x%04" PRIx16 ", %d (bytes), errno %d"),
                         ctx, (int)pnode->index, (int)pnode->sock_id,
                         pnode->addr_info.ip_addr_str, pnode->tid_counter, tid, (int)ret, (unsigned)errno);
            }
            ESP_LOG_BUFFER_HEX_LEVEL("SENT", frame_entry.pbuf, ret, ESP_LOG_DEBUG);
        }
        (void)mb_drv_set_status_flag(pdrv_ctx, MB_FLAG_TRANSACTION_DONE);
        pdrv_ctx->event_cbs.mb_sync_event_cb(pdrv_ctx->event_cbs.port_arg, MB_SYNC_EVENT_SEND_OK);
        mb_drv_lock(pdrv_ctx);
        transaction_set_state(port_obj->transaction, tid, TRANSMITTED);
        if (transaction_delete(port_obj->transaction, tid) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to remove queued TID:0x%04" PRIx16, tid);
        } else {
            ESP_LOGD(TAG, "Remove the message TID:0x%04" PRIx16, tid);
        }
        free(frame_entry.pbuf);
        pnode->send_time = esp_timer_get_time();
        pnode->send_counter = (pnode->send_counter < (USHRT_MAX - 1)) ? (pnode->send_counter + 1) : 0;
        mb_drv_unlock(pdrv_ctx);
    }
}

MB_EVENT_HANDLER(mbs_on_error)
{
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    mb_node_info_t *pnode = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
    if (!pnode) {
        ESP_LOGD(TAG, "%s %s: fd: %d, is closed.", (char *)base, __func__, (int)pevent_info->opt_fd);
        return;
    }
    // Check if the node is not alive for timeout
    int ret = mb_drv_check_node_state(pdrv_ctx, (int *)&pevent_info->opt_fd, MB_TCP_EVENT_LOOP_TICK_MS);
    if ((ret != ERR_OK) && (ret != ERR_TIMEOUT)) {
        ESP_LOGE(TAG, "Node: #%d is not alive, err= %d", (int)pevent_info->opt_fd, ret);
        mb_drv_close(pdrv_ctx, pevent_info->opt_fd);
    }
}

MB_EVENT_HANDLER(mbs_on_close)
{
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s, fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *pnode =NULL;
    // if close all sockets event is received
    if (pevent_info->opt_fd < 0)
    {
        (void)mb_drv_clear_status_flag(pdrv_ctx, MB_FLAG_DISCONNECTED);
        for (int fd = 0; fd < MB_MAX_FDS; fd++)
        {
            mb_node_info_t *pnode = mb_drv_get_node(pdrv_ctx, fd);
            if (pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_OPENED)
                      && FD_ISSET(pnode->index, &pdrv_ctx->open_set))
            {
                mb_drv_close(pdrv_ctx, fd);
            }
        }
        (void)mb_drv_set_status_flag(pdrv_ctx, MB_FLAG_DISCONNECTED);
        mb_drv_check_suspend_shutdown(ctx);
    } else if (MB_CHECK_FD_RANGE(pevent_info->opt_fd)) {
        pnode = mb_drv_get_node(pdrv_ctx, pevent_info->opt_fd);
        if (pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_OPENED)) {
            if ((pnode->sock_id < 0) && FD_ISSET(pnode->sock_id, &pdrv_ctx->open_set)) {
                mb_drv_close(ctx, pevent_info->opt_fd);
            }
        }
        mb_drv_check_suspend_shutdown(ctx);
    }
}

MB_EVENT_HANDLER(mbs_on_timeout)
{
    // Slave timeout triggered
    //mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    static int curr_fd = 0;
    ESP_LOGD(TAG, "%s  %s: fd: %d, %d", (char *)base, __func__, (int)curr_fd, pdrv_ctx->node_conn_count);
    mb_drv_check_suspend_shutdown(ctx);
    int ret = mb_drv_check_node_state(pdrv_ctx, &curr_fd, MB_RECONNECT_TIME_MS);
    if ((ret != ERR_OK) && (ret != ERR_TIMEOUT)) {
        ESP_LOGE(TAG, "Node: %d, connection lost, err= %d", curr_fd, ret);
        mb_drv_close(pdrv_ctx, curr_fd);
    }
    if ((curr_fd + 1) >= (pdrv_ctx->node_conn_count)) {
        curr_fd = 0;
    } else {
        curr_fd++;
    }
}

#endif