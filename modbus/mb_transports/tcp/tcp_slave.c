/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tcp_transport.h"
#include "port_tcp_common.h"

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

static const char *TAG = "mb_transp.tcp_slave";

typedef struct
{
    mb_trans_base_t base;
    mb_port_base_t *port_obj;
    uint8_t recv_buf[MB_TCP_BUF_SIZE];
    uint8_t send_buf[MB_TCP_BUF_SIZE];
    mb_tcp_state_enum_t state;
    uint16_t snd_pdu_len;
} mbs_tcp_transp_t;

/* ----------------------- Defines ------------------------------------------*/

/* ----------------------- Function prototypes ------------------------------*/
static void mbs_tcp_transp_start(mb_trans_base_t *inst);
static void mbs_tcp_transp_stop(mb_trans_base_t *inst);
static mb_err_enum_t mbs_tcp_transp_receive(mb_trans_base_t *inst, uint8_t *rcv_addr, uint8_t **frame_ptr_buf, uint16_t *pbuf_len);
static mb_err_enum_t mbs_tcp_transp_send(mb_trans_base_t *inst, uint8_t _unused, const uint8_t *frame_ptr, uint16_t len);
static void mbs_tcp_transp_get_rcv_buf(mb_trans_base_t *inst, uint8_t **frame_ptr_buf);
static void mbs_tcp_transp_get_snd_buf(mb_trans_base_t *inst, uint8_t **frame_ptr_buf);
bool mbs_tcp_transp_delete(mb_trans_base_t *inst);
static bool mbs_tcp_transp_timer_expired(void *inst);

mb_err_enum_t mbs_tcp_transp_create(mb_tcp_opts_t *tcp_opts, void **in_out_inst)
{
    mb_err_enum_t ret = MB_ENOERR;
    mbs_tcp_transp_t *transp = NULL;
    transp = (mbs_tcp_transp_t *)calloc(1, sizeof(mbs_tcp_transp_t));
    MB_RETURN_ON_FALSE(transp, MB_EILLSTATE, TAG, "no mem for instance.");
    CRITICAL_SECTION_INIT(transp->base.lock);
    CRITICAL_SECTION_LOCK(transp->base.lock);
    transp->base.frm_rcv = mbs_tcp_transp_receive;
    transp->base.frm_send = mbs_tcp_transp_send;
    transp->base.frm_start = mbs_tcp_transp_start;
    transp->base.frm_stop = mbs_tcp_transp_stop;
    transp->base.get_rx_frm = mbs_tcp_transp_get_rcv_buf;
    transp->base.get_tx_frm = mbs_tcp_transp_get_snd_buf;
    transp->base.frm_delete = mbs_tcp_transp_delete;
    transp->base.frm_is_bcast = NULL;
    // Copy parent object descriptor
    transp->base.descr = ((mb_port_base_t *)*in_out_inst)->descr;
    transp->base.descr.obj_name = (char *)TAG;
    mb_port_base_t *port_obj = (mb_port_base_t *)*in_out_inst;
    ret = mbs_port_tcp_create(tcp_opts, &port_obj);
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EPORTERR, error, TAG, "tcp port creation, err: %d", ret);
    ret = mb_port_timer_create(port_obj, MB_TCP_TIMEOUT_MS * MB_TIMER_TICS_PER_MS);
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EPORTERR, error, TAG, "timer port creation, err: %d", ret);
    // Override default response time if defined
    if (tcp_opts->response_tout_ms) {
        mb_port_timer_set_response_time(port_obj, tcp_opts->response_tout_ms);
    }
    ret = mb_port_event_create(port_obj);
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EPORTERR, error, TAG, "event port creation, err: %d", ret);
    transp->base.port_obj = port_obj;
    // Set callback function pointer for the timer
    port_obj->cb.tmr_expired = mbs_tcp_transp_timer_expired;
    port_obj->cb.tx_empty = NULL;
    port_obj->cb.byte_rcvd = NULL;
    port_obj->arg = (void *)transp;
    transp->port_obj = port_obj;
    *in_out_inst = &(transp->base);
    ESP_LOGD(TAG, "created %s object @%p", TAG, transp);
    CRITICAL_SECTION_UNLOCK(transp->base.lock);
    return MB_ENOERR;
error:
    if (port_obj) {
        free(port_obj->event_obj);
        free(port_obj->timer_obj);
    }
    free(port_obj);
    CRITICAL_SECTION_UNLOCK(transp->base.lock);
    CRITICAL_SECTION_CLOSE(transp->base.lock);
    free(transp);
    return ret;
}

bool mbs_tcp_transp_delete(mb_trans_base_t *inst)
{
    mbs_tcp_transp_t *transp = __containerof(inst, mbs_tcp_transp_t, base);
    // destroy method of port tcp slave is here
    CRITICAL_SECTION(inst->lock) {
        mb_port_timer_delete(inst->port_obj);
        mb_port_event_delete(inst->port_obj);
        mbs_port_tcp_delete(inst->port_obj);
    }
    CRITICAL_SECTION_CLOSE(inst->lock);
    free(transp);
    return true;
}

static void mbs_tcp_transp_start(mb_trans_base_t *inst)
{
    CRITICAL_SECTION(inst->lock) {
        mbs_port_tcp_enable(inst->port_obj);
        mb_port_timer_enable(inst->port_obj);
    };
    /* No special startup required for TCP. */
    (void)mb_port_event_post(inst->port_obj, EVENT(EV_READY));
}

static void mbs_tcp_transp_stop(mb_trans_base_t *inst)
{
    /* Make sure that no more clients are connected. */
    CRITICAL_SECTION(inst->lock) {
        mbs_port_tcp_disable(inst->port_obj);
        mb_port_timer_disable(inst->port_obj);
    };
}

static mb_err_enum_t mbs_tcp_transp_receive(mb_trans_base_t *inst, uint8_t *rcv_addr, uint8_t **frame_ptr_buf, uint16_t *pbuf_len)
{
    if (!pbuf_len || !frame_ptr_buf || !pbuf_len) {
        return MB_EIO;
    }

    mbs_tcp_transp_t *transp = __containerof(inst, mbs_tcp_transp_t, base);

    uint8_t *frame_ptr = (uint8_t *)transp->recv_buf;
    uint16_t length = *pbuf_len;
    mb_err_enum_t status = MB_EIO;
    uint16_t pid;

    if (mbs_port_tcp_recv_data(inst->port_obj, &frame_ptr, &length) != false) {
        pid = frame_ptr[MB_TCP_PID] << 8U;
        pid |= frame_ptr[MB_TCP_PID + 1];

        if (pid == MB_TCP_PROTOCOL_ID) {
            *frame_ptr_buf = &frame_ptr[MB_TCP_FUNC];
            *pbuf_len = length - MB_TCP_FUNC;
            status = MB_ENOERR;

            /* Get MBAP UID field if its support is enabled.
             * Otherwise just ignore this field.
             */
#if MB_TCP_UID_ENABLED
            *rcv_addr = frame_ptr[MB_TCP_UID];
#else
            *rcv_addr = MB_TCP_PSEUDO_ADDRESS;
#endif
        }
    } else {
        status = MB_EIO;
    }
    return status;
}

static mb_err_enum_t mbs_tcp_transp_send(mb_trans_base_t *inst, uint8_t _unused, const uint8_t *pframe, uint16_t len)
{
    mb_err_enum_t status = MB_ENOERR;
    uint8_t *frame_ptr = (uint8_t *)pframe - MB_TCP_FUNC;
    uint16_t tcp_len = len + MB_TCP_FUNC;

    /* The MBAP header is already initialized because the caller calls this
     * function with the buffer returned by the previous call. Therefore we
     * only have to update the length in the header. Note that the length
     * header includes the size of the Modbus PDU and the UID Byte. Therefore
     * the length is len plus one.
     */
    frame_ptr[MB_TCP_LEN] = (len + 1) >> 8U;
    frame_ptr[MB_TCP_LEN + 1] = (len + 1) & 0xFF;

    if (mbs_port_tcp_send_data(inst->port_obj, frame_ptr, tcp_len) == false) {
        status = MB_EIO;
    }
    return status;
}

static bool mbs_tcp_transp_timer_expired(void *inst)
{
    mbs_tcp_transp_t *transp = __containerof(inst, mbs_tcp_transp_t, base);
    
    bool need_poll = false;
    mb_timer_mode_enum_t timer_mode = mb_port_get_cur_timer_mode(transp->base.port_obj);

    mb_port_timer_disable(transp->base.port_obj);

    switch(timer_mode) {
        case MB_TMODE_T35:
            need_poll = mb_port_event_post(transp->base.port_obj, EVENT(EV_READY));
            ESP_EARLY_LOGD(TAG, "EV_READY");
            break;

        case MB_TMODE_RESPOND_TIMEOUT:
            mb_port_event_set_err_type(transp->base.port_obj, EV_ERROR_RESPOND_TIMEOUT);
            need_poll = mb_port_event_post(transp->base.port_obj, EVENT(EV_ERROR_PROCESS));
            ESP_EARLY_LOGD(TAG, "EV_ERROR_RESPOND_TIMEOUT");
            break;

        case MB_TMODE_CONVERT_DELAY:
            /* If timer mode is convert delay, the master event then turns EV_MASTER_EXECUTE status. */
            need_poll = mb_port_event_post(transp->base.port_obj, EVENT(EV_EXECUTE));
            ESP_EARLY_LOGD(TAG, "MB_TMODE_CONVERT_DELAY");
            break;

        default:
            need_poll = mb_port_event_post(transp->base.port_obj, EVENT(EV_READY));
            break;
    }
    
    return need_poll;
}

static void mbs_tcp_transp_get_rcv_buf(mb_trans_base_t *inst, uint8_t **frame_ptr_buf)
{
    mbs_tcp_transp_t *transp = __containerof(inst, mbs_tcp_transp_t, base);
    CRITICAL_SECTION(inst->lock) {
        *frame_ptr_buf = transp->recv_buf + MB_TCP_FUNC;
    }
}

static void mbs_tcp_transp_get_snd_buf(mb_trans_base_t *inst, uint8_t **frame_ptr_buf)
{
    mbs_tcp_transp_t *transp = __containerof(inst, mbs_tcp_transp_t, base);
    CRITICAL_SECTION(inst->lock) {
        *frame_ptr_buf = transp->send_buf + MB_TCP_FUNC;
    }
}

#endif