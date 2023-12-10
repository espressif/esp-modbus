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
static void mbm_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event);
bool mbm_port_timer_expired(void *inst);
extern int port_scan_addr_string(char *buffer, mb_uid_info_t *pslave_info);

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

    err = mbm_drv_register(&ptcp->pdriver);
    MB_GOTO_ON_FALSE(((err == ESP_OK) && ptcp->pdriver), MB_EILLSTATE, error, 
                        TAG, "mb tcp port driver registration failed.");
    ptcp->pdriver->parent = ptcp;

    ptcp->pdriver->network_iface_ptr = tcp_opts->ip_netif_ptr;
    ptcp->pdriver->mb_proto = tcp_opts->mode;
    ptcp->pdriver->event_cbs.mb_sync_event_cb = mbm_port_tcp_sync_event;
    ptcp->pdriver->event_cbs.port_arg = (void *)ptcp;

    ptcp->base.cb.tmr_expired = mbm_port_timer_expired;
    ptcp->base.cb.tx_empty = NULL;
    ptcp->base.cb.byte_rcvd = NULL;
    ptcp->base.arg = (void *)ptcp;

    char **paddr_table = tcp_opts->ip_addr_table;
    MB_GOTO_ON_FALSE((paddr_table && *paddr_table), MB_EILLSTATE, error, 
                        TAG, "mb tcp port driver registration failed.");
    mb_uid_info_t slave_address_info;
    int fd = 0;

    // Just for test now
    while(*paddr_table) {
        int res = port_scan_addr_string((char *)*paddr_table, &slave_address_info);
        if (res > 0) {
            ESP_LOGW(TAG, "Config: %s, IP: %s, port: %d, slave_addr: %d, ip_ver: %s", 
                        (char *)*paddr_table, slave_address_info.ip_addr_str, slave_address_info.port, 
                        slave_address_info.uid, (slave_address_info.addr_type == MB_IPV4 ? "IPV4" : "IPV6"));            
            fd = mbm_drv_open(ptcp->pdriver, slave_address_info, 0);
            if (fd < 0) {
                ESP_LOGE(TAG, "%p, unable to open slave: %s", ptcp->pdriver, slave_address_info.ip_addr_str);
            } else {
                ESP_LOGW(TAG, "%p, open slave: %d, %s:%d", 
                                    ptcp->pdriver, fd, slave_address_info.ip_addr_str, slave_address_info.port);
            }
        } else {
            ESP_LOGE(TAG, "%p, unable to open slave: %s, check configuration.", ptcp->pdriver, (char *)*paddr_table);
        }
        paddr_table++;
    }
    *port_obj = &(ptcp->base);
    ESP_LOGD(TAG, "created object @%p", ptcp);
    return MB_ENOERR;

error:
    if (ptcp && ptcp->pdriver) {
        (void)mbm_drv_unregister(ptcp->pdriver);
        CRITICAL_SECTION_CLOSE(ptcp->base.lock);
    }
    free(ptcp);
    return ret;
}

void mbm_port_tcp_delete(mb_port_base_t *inst)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    esp_err_t err = mbm_drv_unregister(port_obj->pdriver);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "driver unregister fail, returns (0x%d).", (uint16_t)err);
    }
    CRITICAL_SECTION_CLOSE(inst->lock);
    free(port_obj);
}

void mbm_port_tcp_enable(mb_port_base_t *inst)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    //esp_err_t err = ESP_ERR_INVALID_STATE;
    // if (!port_obj->pdriver->is_registered && !port_obj->pdriver) {
    //     err = mbm_drv_register(&port_obj->pdriver);
    //     MB_RETURN_ON_FALSE((err == ESP_OK), ;, TAG, "mb tcp port driver register failed.");
    // }
    (void)mbm_drv_start_task(port_obj->pdriver);
    DRIVER_SEND_EVENT(port_obj->pdriver, MB_EVENT_RESOLVE, -1);
}

void mbm_port_tcp_disable(mb_port_base_t *inst)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    // Change the state of all slaves to close
    DRIVER_SEND_EVENT(port_obj->pdriver, MB_EVENT_CLOSE, -1);
    (void)mbm_drv_wait_status_flag(port_obj->pdriver, MB_FLAG_DISCONNECTED, MB_RECONNECT_TIME_MS);
    //(void)mbm_drv_stop_task(port_obj->pdriver); // do not stop the task if we want to gracefully shutdown the task
}

bool mbm_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);

    mb_slave_info_t *pinfo = port_obj->pdriver->mb_slave_curr_info;
    MB_RETURN_ON_FALSE((pinfo), false, TAG, "incorrect current slave pointer.");
    bool status = false;

    size_t sz = mbm_drv_read(port_obj->pdriver, pinfo->fd, port_obj->ptemp_buf, MB_BUFFER_SIZE);
    if (sz > MB_TCP_FUNC) {
        uint16_t tid_counter = MB_TCP_MBAP_GET_FIELD(port_obj->ptemp_buf, MB_TCP_TID);
        if (tid_counter == (pinfo->tid_counter - 1)) {
            *ppframe = port_obj->ptemp_buf;
            *plength = sz;
            ESP_LOGW(TAG, "%p, "MB_SLAVE_FMT(", received packet TID = 0x%.4x:(0x%.4x), %p."),
                            port_obj->pdriver, pinfo->index, pinfo->sock_id, pinfo->addr_info.ip_addr_str, 
                            tid_counter, pinfo->tid_counter, *ppframe);

            uint64_t time = 0;
            time = port_get_timestamp() - pinfo->send_time;
            ESP_LOGW(TAG, "%p, "MB_SLAVE_FMT(", processing time[us] = %ju."), port_obj->pdriver, pinfo->index,
                        pinfo->sock_id, pinfo->addr_info.ip_addr_str, time);
            status = true;
        } else {
            ESP_LOGE(TAG, "%p, "MB_SLAVE_FMT(", drop packet TID = 0x%.4x:0x%.4x, %p."),
                            port_obj->pdriver, pinfo->index, pinfo->sock_id,
                            pinfo->addr_info.ip_addr_str, tid_counter, pinfo->tid_counter, *ppframe);
        }
    }
    return status;
}

bool mbm_port_tcp_send_data(mb_port_base_t *inst, uint8_t address, uint8_t *pframe, uint16_t length)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);

    bool frame_sent = false;
    // get slave descriptor from its address
    mb_slave_info_t *pinfo = (mb_slave_info_t *)mbm_drv_get_slave_info_from_addr(port_obj->pdriver, address);
    MB_RETURN_ON_FALSE((pinfo && (MB_GET_SLAVE_STATE(pinfo) >= MB_SOCK_STATE_CONNECTED)), 
                        false, TAG, "the slave address #%d is not registered.", address);

    if (pinfo && pframe) {
        // Apply TID field to the frame before send
        MB_TCP_MBAP_SET_FIELD(pframe, MB_TCP_TID, pinfo->tid_counter);
        pframe[MB_TCP_UID] = (uint8_t)(pinfo->addr_info.uid);
    }

    ESP_LOGW(TAG, "%p,  send fd: %d, sock_id: %d[%s], %p, len: %d", 
                port_obj->pdriver, pinfo->fd, pinfo->sock_id, pinfo->addr_info.node_name_str, pframe, length);

    // Write data to the modbus vfs driver send queue of the slave 
    int write_length = mbm_drv_write(port_obj->pdriver, pinfo->fd, pframe, length);
    if (write_length) {
        frame_sent = true;
    } else {
        ESP_LOGE(TAG, "mbm_write fail, returns %d.", write_length);
    }
    // mb_port_tmr_respond_timeout_enable(inst); // the timer is set in the transport

    return frame_sent;
}

void mbm_port_tcp_set_conn_cb(mb_port_base_t *inst, void *conn_fp, void *arg)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    mbm_drv_set_cb(port_obj->pdriver, conn_fp, arg);
}

// Timer handler to check timeout of socket response
bool mbm_port_timer_expired(void *inst)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    bool need_poll = false;
    BaseType_t task_unblocked;
    mb_event_info_t mb_event;
    esp_err_t err = ESP_FAIL;

    mb_port_tmr_disable(inst);
    // If timer mode is respond timeout, the master event then turns EV_MASTER_EXECUTE status.
    if (mb_port_get_cur_tmr_mode(inst) == MB_TMODE_RESPOND_TIMEOUT) {
        // It is now to check solution.
        mb_event.event_id = MB_EVENT_TIMEOUT;
        mb_event.opt_fd = port_obj->pdriver->curr_slave_index;
        err = esp_event_isr_post_to(port_obj->pdriver->event_loop_hdl, MB_EVENT_BASE(port_obj->pdriver), 
                                    (int32_t)MB_EVENT_TIMEOUT, (void *)&mb_event, sizeof(mb_event_info_t*), &task_unblocked);
        if (err != ESP_OK) {
            ESP_EARLY_LOGE(TAG, "Timeout event send error: %d", err);
        }
        need_poll = task_unblocked;
        mb_port_evt_set_err_type(inst, EV_ERROR_RESPOND_TIMEOUT);
        need_poll = mb_port_evt_post(inst, EVENT(EV_ERROR_PROCESS));
    }
    return need_poll;
}

mb_uid_info_t *mbm_port_tcp_get_slave_info(mb_port_base_t *inst, uint8_t slave_addr, mb_sock_state_t exp_state)
{
    mbm_tcp_port_t *port_obj = __containerof(inst, mbm_tcp_port_t, base);
    mb_uid_info_t *paddr_info = NULL;
    mb_slave_info_t *pinfo = mbm_drv_get_slave_info_from_addr(port_obj->pdriver, slave_addr);
    if (pinfo && (MB_GET_SLAVE_STATE(pinfo) >= exp_state)) {
        paddr_info = &pinfo->addr_info;
    }
    return paddr_info;
}

static void mbm_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event)
{
    switch(sync_event) {
        case MB_SYNC_EVENT_RECV_OK:
            mb_port_tmr_disable(inst);
            mb_port_evt_set_err_type(inst, EV_ERROR_INIT);
            mb_port_evt_post(inst, EVENT(EV_FRAME_RECEIVED));
            break;

        case MB_SYNC_EVENT_RECV_FAIL:
            mb_port_tmr_disable(inst);
            mb_port_evt_set_err_type(inst, EV_ERROR_RECEIVE_DATA);
            mb_port_evt_post(inst, EVENT(EV_ERROR_PROCESS));
            break;

        case MB_SYNC_EVENT_SEND_OK:
            mb_port_evt_post(inst, EVENT(EV_FRAME_SENT));
            break;
        default:
            break;
    }
}

#endif
