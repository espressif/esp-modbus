/*
 * SPDX-FileCopyrightText: 2021-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <string.h>
#include <sys/param.h>

#include "port_tcp_common.h"
#include "port_tcp_slave.h"
#include "port_tcp_driver.h"
#include "port_tcp_utils.h"

#include "mb_transaction.h"

#include "port_common.h" // use common port functions

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

// Lifecycle of the listener, changed only by the driver task
typedef enum {
    MBS_LC_STOPPED = 0,                 // no listener, no clients
    MBS_LC_STARTING,                    // trying to create the listener (with retries)
    MBS_LC_RUNNING                      // the listener accepts connections
} mbs_lc_state_t;

typedef enum {
    MBS_LC_CMD_START = 1,
    MBS_LC_CMD_STOP = 2
} mbs_lc_cmd_t;

typedef struct {
    uint32_t seq;                       // sequence number of the acknowledged command
    esp_err_t err;                      // result of the command
} mbs_lc_ack_t;

// The time given to create the listener before the start fails
#define MBS_LC_START_BUDGET_MS          (5000)
// Additional time the caller waits for the driver task (only matters if the task is blocked)
#define MBS_LC_ACK_MARGIN_MS            (2000)
#define MBS_LC_STOP_TIMEOUT_MS          (MB_WAIT_DONE_MS)
#define MBS_LC_RETRY_FIRST_MS           (20)
#define MBS_LC_RETRY_MAX_MS             (500)
#define MBS_LC_QUEUE_DEPTH              (4)
#define MBS_LC_POST_TICKS               (pdMS_TO_TICKS(100))

typedef struct {
    mb_port_base_t base;
    // TCP communication properties
    mb_tcp_opts_t tcp_opts;
    mb_uid_info_t addr_info;
    uint8_t ptemp_buf[MB_TCP_BUFF_MAX_SIZE];
    // The driver object for the slave
    port_driver_t *drv_obj;
    transaction_handle_t transaction;
    uint16_t trans_count;
    int tout_curr_fd;                   // cursor of the connection check in mbs_on_timeout
    // Lifecycle, caller side (protected by lc_api_mutex)
    SemaphoreHandle_t lc_api_mutex;     // serializes the lifecycle requests of this instance
    SemaphoreHandle_t lc_ack_sema;      // given by the driver task after an acknowledge is written
    portMUX_TYPE lc_ack_spin;           // protects the acknowledge slots
    mbs_lc_ack_t lc_start_ack;
    mbs_lc_ack_t lc_stop_ack;
    uint32_t lc_next_seq;
    uint32_t lc_start_seq;              // sequence of the START posted by enable
    esp_err_t lc_start_post_err;        // result of posting the START in enable
    esp_err_t lc_stop_err;              // result of the last disable
    bool lc_enabled;                    // enable has been called and disable has not completed yet
    // Lifecycle, driver task side (lc_state is also read under the driver lock)
    mbs_lc_state_t lc_state;
    uint32_t lc_pending_start_seq;
    int64_t lc_start_deadline_us;
    uint32_t lc_backoff_ms;
    uint16_t lc_attempts;
} mbs_tcp_port_t;

/* ----------------------- Static variables & functions ----------------------*/
static const char *TAG = "mb_port.tcp.slave";

static uint64_t mbs_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event);
static void mbs_retrigger_pending_transactions(void *ctx, mbs_tcp_port_t *port_obj);
static void mbs_lc_on_cmd(void *arg, const mb_drv_cmd_t *cmd);
static void mbs_lc_on_timer(void *arg);
static bool mbs_lc_is_running(mbs_tcp_port_t *port_obj);

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

    portMUX_INITIALIZE(&ptcp->lc_ack_spin);
    ptcp->lc_api_mutex = xSemaphoreCreateMutex();
    ptcp->lc_ack_sema = xSemaphoreCreateBinary();
    MB_GOTO_ON_FALSE((ptcp->lc_api_mutex && ptcp->lc_ack_sema), MB_EILLSTATE, error,
                     TAG, "mb tcp port lifecycle objects creation failed.");
    ptcp->lc_state = MBS_LC_STOPPED;
    const mb_drv_lc_ops_t lc_ops = {
        .on_cmd = mbs_lc_on_cmd,
        .on_timer = mbs_lc_on_timer,
        .arg = ptcp
    };
    err = mb_drv_lc_init(ptcp->drv_obj, &lc_ops, MBS_LC_QUEUE_DEPTH);
    MB_GOTO_ON_FALSE((err == ESP_OK), MB_EILLSTATE, error,
                     TAG, "mb tcp port lifecycle init failed, err = (%x).", (int)err);

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
    if (ptcp && ptcp->drv_obj) {
#ifdef MB_MDNS_IS_INCLUDED
        port_stop_mdns_service(&ptcp->drv_obj->dns_name);
#endif
        if (ptcp->drv_obj->event_handler[0]) {
            mbs_port_tcp_unregister_handlers(ptcp->drv_obj);
        }
        (void)mb_drv_unregister(ptcp->drv_obj);
    }
    if (ptcp && ptcp->transaction) {
        transaction_destroy(ptcp->transaction);
    }
    if (ptcp) {
        if (ptcp->lc_api_mutex) {
            vSemaphoreDelete(ptcp->lc_api_mutex);
        }
        if (ptcp->lc_ack_sema) {
            vSemaphoreDelete(ptcp->lc_ack_sema);
        }
        CRITICAL_SECTION_CLOSE(ptcp->base.lock);
    }
    free(ptcp);
    return ret;
}

void mbs_port_tcp_delete(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    if (port_obj->drv_obj) {
        // Close the listener and the clients while the driver task is still running
        mbs_port_tcp_disable(inst);
#ifdef MB_MDNS_IS_INCLUDED
        port_stop_mdns_service(&port_obj->drv_obj->dns_name);
#endif
        if (port_obj->drv_obj->event_handler[0]) {
            mbs_port_tcp_unregister_handlers(port_obj->drv_obj);
        }
        // The driver task exits here, only after that the objects it uses can be destroyed
        (void)mb_drv_unregister(port_obj->drv_obj);
        port_obj->drv_obj = NULL;
    }
    if (port_obj->transaction) {
        transaction_destroy(port_obj->transaction);
        port_obj->transaction = NULL;
    }
    if (port_obj->lc_api_mutex) {
        vSemaphoreDelete(port_obj->lc_api_mutex);
    }
    if (port_obj->lc_ack_sema) {
        vSemaphoreDelete(port_obj->lc_ack_sema);
    }
    CRITICAL_SECTION_CLOSE(inst->lock);
    free(port_obj);
}

/* ----------------------- Lifecycle: caller side ----------------------*/

static uint32_t mbs_lc_next_seq(mbs_tcp_port_t *port_obj)
{
    // 0 is never used, so a zeroed acknowledge slot never matches
    if (++port_obj->lc_next_seq == 0) {
        port_obj->lc_next_seq = 1;
    }
    return port_obj->lc_next_seq;
}

// Waits for the acknowledge of the command with the sequence number seq
static esp_err_t mbs_lc_wait_ack(mbs_tcp_port_t *port_obj, bool is_start, uint32_t seq, uint32_t timeout_ms)
{
    const TickType_t start = xTaskGetTickCount();
    const TickType_t timeout = pdMS_TO_TICKS(timeout_ms);
    mbs_lc_ack_t *slot = is_start ? &port_obj->lc_start_ack : &port_obj->lc_stop_ack;
    for (;;) {
        portENTER_CRITICAL(&port_obj->lc_ack_spin);
        mbs_lc_ack_t ack = *slot;
        portEXIT_CRITICAL(&port_obj->lc_ack_spin);
        if (ack.seq == seq) {
            return ack.err;
        }
        TickType_t elapsed = xTaskGetTickCount() - start;
        if (elapsed >= timeout) {
            return ESP_ERR_TIMEOUT;
        }
        // The semaphore might be given for another acknowledge, the slot is checked again anyway
        (void)xSemaphoreTake(port_obj->lc_ack_sema, timeout - elapsed);
    }
}

static mbs_lc_state_t mbs_lc_get_state(mbs_tcp_port_t *port_obj)
{
    mb_drv_lock(port_obj->drv_obj);
    mbs_lc_state_t state = port_obj->lc_state;
    mb_drv_unlock(port_obj->drv_obj);
    return state;
}

void mbs_port_tcp_enable(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    (void)mb_drv_start_task(port_obj->drv_obj);
    // Only post the start here: this is called under the object locks. The result is
    // received by mbs_port_tcp_wait_started() without the locks held.
    (void)xSemaphoreTake(port_obj->lc_api_mutex, portMAX_DELAY);
    mb_drv_cmd_t cmd = {
        .id = MBS_LC_CMD_START,
        .seq = mbs_lc_next_seq(port_obj)
    };
    port_obj->lc_start_seq = cmd.seq;
    port_obj->lc_enabled = true;
    port_obj->lc_start_post_err = mb_drv_lc_post(port_obj->drv_obj, &cmd, MBS_LC_POST_TICKS);
    (void)xSemaphoreGive(port_obj->lc_api_mutex);
}

esp_err_t mbs_port_tcp_wait_started(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    MB_RETURN_ON_FALSE(!mb_drv_is_task_context(port_obj->drv_obj), ESP_ERR_INVALID_STATE, TAG,
                       "%p, can not wait for the start in the driver task.", port_obj);
    (void)xSemaphoreTake(port_obj->lc_api_mutex, portMAX_DELAY);
    esp_err_t err = port_obj->lc_start_post_err;
    if (err == ESP_OK) {
        err = mbs_lc_wait_ack(port_obj, true, port_obj->lc_start_seq,
                              MBS_LC_START_BUDGET_MS + MBS_LC_ACK_MARGIN_MS);
    }
    (void)xSemaphoreGive(port_obj->lc_api_mutex);
    return err;
}

void mbs_port_tcp_disable(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    esp_err_t err = ESP_OK;
    if (mb_drv_is_task_context(port_obj->drv_obj)) {
        // The driver task can not wait for itself
        ESP_LOGE(TAG, "%p, can not stop the port in the driver task.", port_obj);
        port_obj->lc_stop_err = ESP_ERR_INVALID_STATE;
        return;
    }
    (void)xSemaphoreTake(port_obj->lc_api_mutex, portMAX_DELAY);
    if (port_obj->lc_enabled || (mbs_lc_get_state(port_obj) != MBS_LC_STOPPED)) {
        mb_drv_cmd_t cmd = {
            .id = MBS_LC_CMD_STOP,
            .seq = mbs_lc_next_seq(port_obj)
        };
        err = mb_drv_lc_post(port_obj->drv_obj, &cmd, MBS_LC_POST_TICKS);
        if (err == ESP_OK) {
            err = mbs_lc_wait_ack(port_obj, false, cmd.seq, MBS_LC_STOP_TIMEOUT_MS);
        }
        if (err == ESP_OK) {
            port_obj->lc_enabled = false;
        } else {
            ESP_LOGE(TAG, "%p, stop of the port failed, err = 0x%x.", port_obj, (int)err);
        }
    }
    port_obj->lc_stop_err = err;
    (void)xSemaphoreGive(port_obj->lc_api_mutex);
}

esp_err_t mbs_port_tcp_get_stop_status(mb_port_base_t *inst)
{
    mbs_tcp_port_t *port_obj = __containerof(inst, mbs_tcp_port_t, base);
    return port_obj->lc_stop_err;
}

/* ----------------------- Lifecycle: driver task side ----------------------*/

static void mbs_lc_ack(mbs_tcp_port_t *port_obj, bool is_start, uint32_t seq, esp_err_t err)
{
    portENTER_CRITICAL(&port_obj->lc_ack_spin);
    mbs_lc_ack_t *slot = is_start ? &port_obj->lc_start_ack : &port_obj->lc_stop_ack;
    slot->seq = seq;
    slot->err = err;
    portEXIT_CRITICAL(&port_obj->lc_ack_spin);
    (void)xSemaphoreGive(port_obj->lc_ack_sema);
}

static bool mbs_lc_is_running(mbs_tcp_port_t *port_obj)
{
    // Called by the driver task (the only writer) or under the driver lock
    return (port_obj->lc_state == MBS_LC_RUNNING);
}

static bool mbs_bind_is_retryable(const mb_bind_diag_t *diag)
{
    switch (diag->stage) {
    case MB_BIND_STAGE_RESOLVE:
        return (diag->err == EAI_MEMORY);
    case MB_BIND_STAGE_SOCKET:
        return ((diag->err == ENFILE) || (diag->err == EMFILE)
                || (diag->err == ENOBUFS) || (diag->err == ENOMEM));
    case MB_BIND_STAGE_BIND:
    case MB_BIND_STAGE_LISTEN:
        // EADDRINUSE: the port can still be held by a closing listener (or another service)
        return ((diag->err == EADDRINUSE) || (diag->err == ENOBUFS) || (diag->err == ENOMEM));
    default:
        return false;
    }
}

static esp_err_t mbs_bind_to_esp_err(const mb_bind_diag_t *diag)
{
    switch (diag->stage) {
    case MB_BIND_STAGE_RESOLVE:
        return (diag->err == EAI_MEMORY) ? ESP_ERR_NO_MEM : ESP_ERR_INVALID_ARG;
    case MB_BIND_STAGE_SOCKET:
        if ((diag->err == ENFILE) || (diag->err == EMFILE) || (diag->err == ENOBUFS) || (diag->err == ENOMEM)) {
            return ESP_ERR_NO_MEM;
        }
        if ((diag->err == EAFNOSUPPORT) || (diag->err == EINVAL) || (diag->err == EPROTONOSUPPORT)) {
            return ESP_ERR_INVALID_ARG;
        }
        return ESP_FAIL;
    case MB_BIND_STAGE_BIND:
    case MB_BIND_STAGE_LISTEN:
        if (diag->err == EADDRINUSE) {
            return ESP_ERR_TIMEOUT;
        }
        if ((diag->err == ENOBUFS) || (diag->err == ENOMEM)) {
            return ESP_ERR_NO_MEM;
        }
        if ((diag->err == EADDRNOTAVAIL) || (diag->err == EINVAL)) {
            return ESP_ERR_INVALID_ARG;
        }
        return ESP_FAIL;
    default:
        return ESP_FAIL;
    }
}

// Prepares a new session: clears the state left by the previous one
static void mbs_lc_reset_session(mbs_tcp_port_t *port_obj)
{
    port_driver_t *drv_obj = port_obj->drv_obj;
    (void)mb_drv_clear_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY | MB_FLAG_DISCONNECTED | MB_FLAG_CONNECTED);
    mb_drv_lock(drv_obj);
    transaction_delete_all_items(port_obj->transaction);
    mb_drv_unlock(drv_obj);
    port_obj->tout_curr_fd = 0;
    drv_obj->accept_hold_until_us = 0;
    // A request that was taken by the stack before the stop is never answered, so release
    // the resource here, otherwise every request of the new session would be postponed.
    mb_port_event_res_release(&port_obj->base);
}

// Closes the listener and all the clients. The port is STOPPED when it returns.
static void mbs_lc_teardown(mbs_tcp_port_t *port_obj)
{
    port_driver_t *drv_obj = port_obj->drv_obj;
    mb_drv_lock(drv_obj);
    // From now on the data path does not post new events
    port_obj->lc_state = MBS_LC_STOPPED;
    int listen_fd = drv_obj->listen_sock_fd;
    drv_obj->listen_sock_fd = UNDEF_FD;
    transaction_delete_all_items(port_obj->transaction);
    mb_drv_unlock(drv_obj);
    if (MB_FD_IS_VALID(listen_fd)) {
        shutdown(listen_fd, SHUT_RDWR);
        close(listen_fd);
    }
    for (int fd = 0; fd < MB_MAX_FDS; fd++) {
        mb_node_info_t *pnode = mb_drv_get_node(drv_obj, fd);
        if (pnode) {
            if (MB_FD_IS_VALID(pnode->sock_id)) {
                mb_set_linger(pnode->sock_id, 0); // send RST immediately
            }
            mb_drv_close(drv_obj, fd);
        }
    }
    mb_drv_lock(drv_obj);
    FD_ZERO(&drv_obj->conn_set);
    drv_obj->node_conn_count = 0;
    mb_drv_unlock(drv_obj);
    mb_drv_lc_set_timer(drv_obj, 0);
    // Drain the events of the closed session, the handlers ignore them in the STOPPED state
    (void)esp_event_loop_run(drv_obj->event_loop_hdl, 0);
    (void)mb_drv_clear_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY | MB_FLAG_CONNECTED);
    (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_DISCONNECTED);
}

static void mbs_lc_try_bind(mbs_tcp_port_t *port_obj)
{
    port_driver_t *drv_obj = port_obj->drv_obj;
    mb_bind_diag_t diag;
    int listen_fd = port_bind_addr(port_obj->tcp_opts.ip_addr_table,
                                   port_obj->tcp_opts.addr_type,
                                   port_obj->tcp_opts.mode,
                                   port_obj->tcp_opts.port,
                                   &diag);
    port_obj->lc_attempts++;
    int64_t now = esp_timer_get_time();
    uint32_t elapsed_ms = (uint32_t)((now - (port_obj->lc_start_deadline_us - (MBS_LC_START_BUDGET_MS * 1000LL))) / 1000);
    if (MB_FD_IS_VALID(listen_fd)) {
        // so, all accepted sockets will inherit the keep-alive feature
        (void)port_keep_alive_enable(listen_fd, CONFIG_FMB_TCP_KEEP_ALIVE_TOUT_SEC);
        mb_drv_lock(drv_obj);
        drv_obj->listen_sock_fd = listen_fd;
        port_obj->lc_state = MBS_LC_RUNNING;
        mb_drv_unlock(drv_obj);
        mb_drv_lc_set_timer(drv_obj, 0);
        (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
        drv_obj->event_cbs.mb_sync_event_cb(drv_obj->event_cbs.port_arg, MB_SYNC_EVENT_READY);
        ESP_LOGI(TAG, "%p, listening on port %u (attempts: %u, %" PRIu32 " ms).", port_obj,
                 (unsigned)port_obj->tcp_opts.port, (unsigned)port_obj->lc_attempts, elapsed_ms);
        mbs_lc_ack(port_obj, true, port_obj->lc_pending_start_seq, ESP_OK);
        return;
    }
    bool retry = mbs_bind_is_retryable(&diag)
                 && ((now + (port_obj->lc_backoff_ms * 1000LL)) < port_obj->lc_start_deadline_us);
    if (!retry) {
        esp_err_t err = mbs_bind_to_esp_err(&diag);
        ESP_LOGE(TAG, "%p, listener on port %u failed: stage=%s, err=%d, family=%d, attempts=%u, %" PRIu32 " ms (%s).",
                 port_obj, (unsigned)port_obj->tcp_opts.port, port_bind_stage_str(diag.stage), diag.err, diag.family,
                 (unsigned)port_obj->lc_attempts, elapsed_ms, esp_err_to_name(err));
        mbs_lc_teardown(port_obj);
        mbs_lc_ack(port_obj, true, port_obj->lc_pending_start_seq, err);
        return;
    }
    ESP_LOGW(TAG, "%p, listener on port %u failed: stage=%s, err=%d, retry in %" PRIu32 " ms.",
             port_obj, (unsigned)port_obj->tcp_opts.port, port_bind_stage_str(diag.stage), diag.err,
             port_obj->lc_backoff_ms);
    mb_drv_lc_set_timer(drv_obj, now + (port_obj->lc_backoff_ms * 1000LL));
    port_obj->lc_backoff_ms = MIN(port_obj->lc_backoff_ms * 2, MBS_LC_RETRY_MAX_MS);
}

static void mbs_lc_on_cmd(void *arg, const mb_drv_cmd_t *cmd)
{
    mbs_tcp_port_t *port_obj = (mbs_tcp_port_t *)arg;
    switch (cmd->id) {
    case MBS_LC_CMD_START:
        if (port_obj->lc_state != MBS_LC_STOPPED) {
            mbs_lc_ack(port_obj, true, cmd->seq, ESP_ERR_INVALID_STATE);
            break;
        }
        mbs_lc_reset_session(port_obj);
        port_obj->lc_pending_start_seq = cmd->seq;
        port_obj->lc_attempts = 0;
        port_obj->lc_backoff_ms = MBS_LC_RETRY_FIRST_MS;
        port_obj->lc_start_deadline_us = esp_timer_get_time() + (MBS_LC_START_BUDGET_MS * 1000LL);
        mb_drv_lock(port_obj->drv_obj);
        port_obj->lc_state = MBS_LC_STARTING;
        mb_drv_unlock(port_obj->drv_obj);
        mbs_lc_try_bind(port_obj);
        break;
    case MBS_LC_CMD_STOP:
        if (port_obj->lc_state == MBS_LC_STARTING) {
            // The start is cancelled by this stop
            mbs_lc_ack(port_obj, true, port_obj->lc_pending_start_seq, ESP_ERR_INVALID_STATE);
        }
        mbs_lc_teardown(port_obj);
        ESP_LOGD(TAG, "%p, port is stopped.", port_obj);
        mbs_lc_ack(port_obj, false, cmd->seq, ESP_OK);
        break;
    default:
        ESP_LOGE(TAG, "%p, unknown lifecycle command %" PRIu32 ".", port_obj, cmd->id);
        break;
    }
}

static void mbs_lc_on_timer(void *arg)
{
    mbs_tcp_port_t *port_obj = (mbs_tcp_port_t *)arg;
    if (port_obj->lc_state == MBS_LC_STARTING) {
        mbs_lc_try_bind(port_obj);
    }
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
        if (port_obj->lc_state != MBS_LC_RUNNING) {
            mb_drv_unlock(drv_obj);
            return false;
        }
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
    bool retrigger_pending = false;

    mb_drv_lock(drv_obj);
    if (port_obj->lc_state != MBS_LC_RUNNING) {
        // The port is stopped, the connection of this request is closed already
        mb_drv_unlock(drv_obj);
        return false;
    }
    item = transaction_get_first(port_obj->transaction);
    if (item && transaction_item_get_state(item) == CONFIRMED) {
        uint16_t msg_id = 0;
        int node_id = 0;
        mb_node_info_t *pnode = NULL;
        uint8_t *buf = transaction_item_get_data(item, NULL, &msg_id, &node_id);
        pnode = mb_drv_get_node(drv_obj, node_id);
        if (pnode && buf && (tid == msg_id)) {
            int write_length = mb_drv_write(drv_obj, node_id, frame, length);
            if (pnode && write_length > 0) {
                frame_sent = true;
                ESP_LOGD(TAG, "%p, node: #%d, socket(#%d)[%s], send packet TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p, len: %d, ",
                         drv_obj, pnode->index, pnode->sock_id,
                         pnode->addr_info.node_name_str, (unsigned)tid, (unsigned)msg_id, frame, length);
                (void)transaction_item_set_state(item, REPLIED);
            } else {
                ESP_LOGE(TAG, "%p, node: #%d, socket(#%d)[%s], modbus write fail, TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p, len: %d, ",
                         drv_obj, pnode->index, pnode->sock_id,
                         pnode->addr_info.node_name_str, (unsigned)tid, (unsigned)msg_id, frame, length);
                (void)transaction_delete_item(port_obj->transaction, item);
                retrigger_pending = true;
            }
        } else {
            if (pnode) {
                ESP_LOGE(TAG, "%p, node: #%d, socket(#%d)[%s], could not write transaction, TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", %p, len: %d, ",
                         drv_obj, pnode->index, pnode->sock_id, pnode->addr_info.node_name_str,
                         (unsigned)tid, (unsigned)msg_id, frame, length);
            } else {
                ESP_LOGE(TAG, "%p, node #%d is closed, drop transaction TID: 0x%04" PRIx16 ":0x%04" PRIx16 ", len: %d",
                         drv_obj, node_id, (unsigned)tid, (unsigned)msg_id, length);
            }
            (void)transaction_delete_item(port_obj->transaction, item);
            retrigger_pending = true;
        }
        (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
    } else {
        ESP_LOGE(TAG, "can not find the confirmed transaction TID: 0x%04" PRIx16 ", drop the frame", tid);
        retrigger_pending = true;
    }
    mb_drv_unlock(drv_obj);
    if (retrigger_pending) {
        mbs_retrigger_pending_transactions(port_obj->drv_obj, port_obj);
    }

    return frame_sent;
}

static uint64_t mbs_port_tcp_sync_event(void *inst, mb_sync_event_t sync_event)
{
    switch (sync_event) {
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
    // The listener is created by the lifecycle commands (see mbs_lc_on_cmd), this event is not used by the slave
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
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
    if (!mbs_lc_is_running((mbs_tcp_port_t *)drv_obj->parent)) {
        return;
    }
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
    if (!mbs_lc_is_running(port_obj)) {
        return;
    }
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
                mb_drv_lock(drv_obj);
                uint16_t msg_id = 0;
                int node_id = 0;
                (void)transaction_item_get_data(item, NULL, &msg_id, &node_id);
                pnode = mb_drv_get_node(drv_obj, node_id);
                ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", acknowledged packet TID: 0x%04" PRIx16 ", start transaction."),
                         drv_obj, pnode->index, pnode->sock_id,
                         pnode->addr_info.ip_addr_str, (unsigned)msg_id);
                if (ESP_OK == transaction_item_set_state(item, ACKNOWLEDGED)) {
                    ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", acknowledged packet TID: 0x%04" PRIx16 "."),
                             drv_obj, pnode->index, pnode->sock_id,
                             pnode->addr_info.ip_addr_str, (unsigned)msg_id);
                }
                mb_drv_unlock(drv_obj);
                // send receive event to modbus object to get the new data
                drv_obj->event_cbs.mb_sync_event_cb(drv_obj->event_cbs.port_arg, MB_SYNC_EVENT_RECV_OK);
            } else {
                if (transaction_item_get_state(item) != TRANSMITTED) {
                    // Transaction processing is ongoing, just delete expired transactions
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
    int ret = 0;
    bool retrigger_pending = false;
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    if (!mbs_lc_is_running(port_obj)) {
        return;
    }
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
                // Check if the first queued transaction matches this response.
                // Only a genuine cross-node mismatch or disconnected state should trigger
                // the "slave busy" exception. The tid_counter comparison is not used here
                // because it reflects the latest received TID, which may have been bumped
                // by a master retry while the current transaction was still in-progress.
                if ((node_id != pnode->index) || (tid != msg_id) || (MB_GET_NODE_STATE(pnode) < MB_SOCK_STATE_CONNECTED)) {
                    ESP_LOGD(TAG, "%p, " MB_NODE_FMT(", frame TID:0x%04" PRIx16 "!=0x%04" PRIx16 ", slave is busy."),
                             ctx, (int)pnode->index, (int)pnode->sock_id,
                             pnode->addr_info.ip_addr_str, tid, msg_id);
                    // Build the exception frame to inform that slave is busy
                    frame_entry.buf[MB_TCP_FUNC] = (frame_entry.buf[MB_TCP_FUNC] | 0x80);
                    frame_entry.buf[MB_TCP_LEN + 1] = 3;
                    frame_entry.buf[MB_TCP_FUNC + 1] = MB_EX_SLAVE_BUSY;
                    ret = port_write_poll(pnode, frame_entry.buf, MB_TCP_FUNC + 2, MB_TCP_SEND_TIMEOUT_MS);
                    mb_drv_lock(drv_obj);
                    if (ret >= 0) {
                        if (transaction_delete(port_obj->transaction, tid) != ESP_OK) {
                            ESP_LOGE(TAG, "Failed to remove queued TID:0x%04" PRIx16, tid);
                        } else {
                            ESP_LOGD(TAG, "Remove the message TID:0x%04" PRIx16, tid);
                        }
                        retrigger_pending = true;
                    } else {
                        DRIVER_SEND_EVENT(ctx, MB_EVENT_ERROR, pnode->index);
                    }
                    (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
                    mb_drv_unlock(drv_obj);
                } else {
                    // Warn user if master sent a new request before this response was dispatched.
                    // The response is still sent normally — this only indicates that the master's
                    // response timeout is too short for the number of active connections.
                    uint64_t tick = (transaction_tick_t)transaction_item_get_tick(item);
                    uint64_t time_div_us = (esp_timer_get_time() - tick);
                    if (tid != pnode->tid_counter) {
                        ESP_LOGW(TAG, "%p, " MB_NODE_FMT(", handling time [ms]: %" PRIu64 ", exceeds slave response time in master, TID:0x%04" PRIx16 " != TID:0x%04" PRIx16),
                                 ctx, (int)pnode->index, (int)pnode->sock_id,
                                 pnode->addr_info.ip_addr_str, (time_div_us / 1000),
                                 pnode->tid_counter, tid
                                );
                    }
                    ret = port_write_poll(pnode, frame_entry.buf, frame_entry.len, MB_TCP_SEND_TIMEOUT_MS);
                    mb_drv_lock(drv_obj);
                    if (ret >= 0) {
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
                        retrigger_pending = true;
                    } else {
                        DRIVER_SEND_EVENT(ctx, MB_EVENT_ERROR, pnode->index);
                    }
                    (void)mb_drv_set_status_flag(drv_obj, MB_FLAG_TRANSACTION_READY);
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
    if (retrigger_pending) {
        mbs_retrigger_pending_transactions(ctx, port_obj);
    }
    mb_drv_check_suspend_shutdown(ctx);
}

static void mbs_retrigger_pending_transactions(void *ctx, mbs_tcp_port_t *port_obj)
{
    transaction_item_handle_t pending = transaction_get_first(port_obj->transaction);
    if (pending && (transaction_item_get_state(pending) == QUEUED)) {
        int pending_node_id = 0;
        uint16_t pending_msg_id = 0;
        (void)transaction_item_get_data(pending, NULL, &pending_msg_id, &pending_node_id);
        mb_node_info_t *pending_node = mb_drv_get_node(MB_GET_DRV_PTR(ctx), pending_node_id);
        if (pending_node) {
            ESP_LOGD(TAG, "Re-trigger pending transaction TID:0x%04x for node #%d.",
                     pending_msg_id, pending_node_id);
            DRIVER_SEND_EVENT(MB_GET_DRV_PTR(ctx), MB_EVENT_RECV_DATA, pending_node_id);
        }
    }
}

MB_EVENT_HANDLER(mbs_on_error)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    mbs_tcp_port_t *port_obj = __containerof(drv_obj->parent, mbs_tcp_port_t, base);
    ESP_LOGD(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    if (!mbs_lc_is_running(port_obj)) {
        return;
    }
    mb_node_info_t *pnode = mb_drv_get_node(drv_obj, event_info->opt_fd);
    if (!pnode) {
        ESP_LOGD(TAG, "%s %s: fd: %d, is closed.", (char *)base, __func__, (int)event_info->opt_fd);
        return;
    }
    mb_drv_check_suspend_shutdown(ctx);
    if (event_info->opt_val == ERR_CONN) {
        ESP_LOGW(TAG, "%p, " MB_NODE_FMT(", connection closed?, err= %d."),
                 port_obj, pnode->index, pnode->sock_id,
                 pnode->addr_info.ip_addr_str, (int)event_info->opt_val);
    } else {
        ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", communication fail, err=%d, drop connection."),
                 port_obj, pnode->index, pnode->sock_id,
                 pnode->addr_info.ip_addr_str, (int)event_info->opt_val);
    }
    // An error happened, disconnect and close node immediately.
    // Protocol violation treated as a DoS and cause disconnection.
    // The master need to reconnect again to send new transaction.
    mb_drv_lock(drv_obj);
    // delete all queued transactions for the node to be closed.
    (void)transaction_delete_by_node_id(port_obj->transaction, event_info->opt_fd);
    mb_set_linger(pnode->sock_id, 0); // send RST immediately
    mb_drv_unlock(drv_obj);
    mb_drv_close(drv_obj, event_info->opt_fd);
    // Re-trigger any pending QUEUED transactions for surviving other clients
    mbs_retrigger_pending_transactions(ctx, port_obj);
    mb_drv_check_suspend_shutdown(ctx);
}

MB_EVENT_HANDLER(mbs_on_close)
{
    mb_event_info_t *event_info = (mb_event_info_t *)data;
    ESP_LOGD(TAG, "%s  %s, fd: %d", (char *)base, __func__, (int)event_info->opt_fd);
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mbs_tcp_port_t *port_obj = __containerof(drv_obj->parent, mbs_tcp_port_t, base);
    mb_node_info_t *pnode = NULL;
    // if close all sockets event is received
    if (event_info->opt_fd < 0) {
        (void)mb_drv_clear_status_flag(drv_obj, MB_FLAG_DISCONNECTED);
        for (int fd = 0; fd < MB_MAX_FDS; fd++) {
            mb_node_info_t *pnode = mb_drv_get_node(drv_obj, fd);
            if (pnode && (MB_GET_NODE_STATE(pnode) >= MB_SOCK_STATE_OPENED)
                    && FD_ISSET(pnode->index, &drv_obj->open_set)) {
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
    int curr_fd = port_obj->tout_curr_fd;
    ESP_LOGD(TAG, "%s %s: fd: %d, count: %d", (char *)base, __func__, (int)curr_fd, drv_obj->node_conn_count);
    if (!mbs_lc_is_running(port_obj)) {
        return;
    }
    mb_drv_check_suspend_shutdown(ctx);
    int ret = mb_drv_check_node_state(drv_obj, &curr_fd, CONFIG_FMB_TCP_CONNECTION_TOUT_SEC * 1000);
    if ((ret != ERR_OK) && (ret != ERR_TIMEOUT)) {
        // the cursor may have moved to the next connected node, so resolve the node after the check
        mb_node_info_t *pnode = mb_drv_get_node(drv_obj, curr_fd);
        if (pnode) {
            ESP_LOGE(TAG, "%p, " MB_NODE_FMT(", connection lost, err=%d, drop connection."),
                     port_obj, pnode->index, pnode->sock_id,
                     pnode->addr_info.ip_addr_str, (int)ret);
        }
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
    port_obj->tout_curr_fd = curr_fd;
    vTaskDelay(1);
}

#endif
