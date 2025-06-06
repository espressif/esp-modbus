/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "rtu_transport.h"
#include "port_serial_common.h"

#if (CONFIG_FMB_COMM_MODE_RTU_EN)

static const char *TAG = "mb_transp.rtu_slave";

typedef struct
{
    mb_trans_base_t base;
    mb_port_base_t *port_obj;
    
    uint8_t snd_buf[MB_RTU_SER_PDU_SIZE_MAX]; // pdu_buf
    uint8_t rcv_buf[MB_RTU_SER_PDU_SIZE_MAX];
    uint16_t snd_pdu_len;
    uint8_t *snd_buf_cur;
    uint16_t snd_buf_cnt;
    uint16_t rcv_buf_pos;
    volatile mb_timer_mode_enum_t cur_timer_mode;
    mb_rtu_state_enum_t state;
} mbs_rtu_transp_t;

mb_err_enum_t mbs_rtu_transp_create(mb_serial_opts_t *ser_opts, void **in_out_inst);
static void mbs_rtu_transp_start(mb_trans_base_t *inst);
static void mbs_rtu_transp_stop(mb_trans_base_t *inst);
static mb_err_enum_t mbs_rtu_transp_receive(mb_trans_base_t *inst, uint8_t *rcv_addr_buf, uint8_t **frame_ptr_buf, uint16_t *len_buf);
static mb_err_enum_t mbs_rtu_transp_send(mb_trans_base_t *inst, uint8_t slv_addr, const uint8_t *frame_ptr, uint16_t len);
static bool mbs_rtu_transp_rcv_fsm(mb_trans_base_t *inst);
static bool mbs_rtu_transp_snd_fsm(mb_trans_base_t *inst);
static bool mbs_rtu_transp_timer_expired(void *inst);
static void mbs_rtu_transp_get_snd_buf(mb_trans_base_t *inst, uint8_t **frame_ptr_buf);
void mbs_rtu_transp_get_rcv_buf(mb_trans_base_t *inst, uint8_t **frame_ptr_buf);
static uint16_t mbs_rtu_transp_get_snd_len(mb_trans_base_t *inst);
static void mbs_rtu_transp_set_snd_len(mb_trans_base_t *inst, uint16_t snd_pdu_len);
bool mbs_rtu_transp_delete(mb_trans_base_t *inst);

mb_err_enum_t mbs_rtu_transp_create(mb_serial_opts_t *ser_opts, void **in_out_inst)
{
    MB_RETURN_ON_FALSE((ser_opts && in_out_inst), MB_EINVAL, TAG, "invalid options for the instance.");
    mb_err_enum_t ret = MB_ENOERR;
    mbs_rtu_transp_t *transp = NULL;
    transp = (mbs_rtu_transp_t *)calloc(1, sizeof(mbs_rtu_transp_t));
    MB_RETURN_ON_FALSE(transp, MB_EILLSTATE, TAG, "no mem for rtu slave transport instance.");
    CRITICAL_SECTION_INIT(transp->base.lock);
    CRITICAL_SECTION_LOCK(transp->base.lock);
    transp->base.frm_rcv = mbs_rtu_transp_receive;
    transp->base.frm_send = mbs_rtu_transp_send;
    transp->base.frm_start = mbs_rtu_transp_start;
    transp->base.frm_stop = mbs_rtu_transp_stop;
    transp->base.get_rx_frm = mbs_rtu_transp_get_rcv_buf;
    transp->base.get_tx_frm = mbs_rtu_transp_get_snd_buf;
    transp->base.frm_delete = mbs_rtu_transp_delete;
    transp->base.frm_is_bcast = NULL;
    transp->base.descr = ((mb_port_base_t *)*in_out_inst)->descr;
    transp->base.descr.obj_name = (char *)TAG;
    mb_port_base_t *port_obj = (mb_port_base_t *)*in_out_inst;
    ret = mb_port_ser_create(ser_opts, &port_obj);
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EPORTERR, error, TAG, "serial port creation, err: %d", ret);
    ret = mb_port_timer_create(port_obj, MB_RTU_GET_T35_VAL(ser_opts->baudrate));
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EPORTERR, error, TAG, "timer port creation, err: %d", ret);
    ret = mb_port_event_create(port_obj);
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EPORTERR, error, TAG, "event port creation, err: %d", ret);
    transp->base.port_obj = port_obj;
    // Set callback function pointer for the timer
    port_obj->cb.tmr_expired = mbs_rtu_transp_timer_expired;
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
    CRITICAL_SECTION_CLOSE(transp->base.lock);
    free(transp);
    return ret;
}


bool mbs_rtu_transp_delete(mb_trans_base_t *inst)
{
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    CRITICAL_SECTION(inst->lock) {
        mb_port_timer_delete(transp->base.port_obj);
        mb_port_event_delete(transp->base.port_obj);
        mb_port_ser_delete(transp->base.port_obj);
    }
    CRITICAL_SECTION_CLOSE(inst->lock);
    free(transp);
    return true;
}

static void mbs_rtu_transp_start(mb_trans_base_t *inst)
{
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    transp->state = MB_RTU_STATE_INIT;
    CRITICAL_SECTION(inst->lock) {
        mb_port_ser_enable(inst->port_obj);
        //mb_port_timer_enable(inst->port_obj);
    };
    (void)mb_port_event_post(transp->base.port_obj, EVENT(EV_READY));
}

static void mbs_rtu_transp_stop(mb_trans_base_t *inst)
{
    CRITICAL_SECTION(inst->lock) {
        mb_port_ser_disable(inst->port_obj);
        mb_port_timer_disable(inst->port_obj);
    };
}

static mb_err_enum_t mbs_rtu_transp_receive(mb_trans_base_t *inst, uint8_t *prcv_addr, uint8_t **ppframe_buf, uint16_t *pbuf_len)
{
    if (!pbuf_len || !prcv_addr || !ppframe_buf || !pbuf_len) {
        return MB_EIO;
    }
    
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    mb_err_enum_t status = MB_ENOERR;

    uint8_t *pbuf = (uint8_t *)transp->rcv_buf;
    uint16_t length = *pbuf_len;

    if (mb_port_ser_recv_data(inst->port_obj, &pbuf, &length) == false){
        *pbuf_len = 0;
        return MB_EPORTERR;
    }

    assert(length < MB_RTU_SER_PDU_SIZE_MAX);
    assert(pbuf);

    /* Check length and CRC checksum */
    if ((length >= MB_RTU_SER_PDU_SIZE_MIN)
        && (mb_crc16((uint8_t *)pbuf, length) == 0)) {
        /* Save the address field. All frames are passed to the upper layed
         * and the decision if a frame is used is done there.
         */
        *prcv_addr = pbuf[MB_SER_PDU_ADDR_OFF];

        /* Total length of Modbus-PDU is Modbus-Serial-Line-PDU minus
         * size of address field and CRC checksum.
         */
        *pbuf_len = (uint16_t)(length - MB_SER_PDU_PDU_OFF - MB_SER_PDU_SIZE_CRC);
        transp->rcv_buf_pos = length;

        /* Return the start of the Modbus PDU to the caller. */
        *ppframe_buf = (uint8_t *)&pbuf[MB_SER_PDU_PDU_OFF];
    } else {
        status = MB_EIO;
    }
    return status;
}

static mb_err_enum_t mbs_rtu_transp_send(mb_trans_base_t *inst, uint8_t slv_addr, const uint8_t *frame_ptr, uint16_t frame_len)
{
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    mb_err_enum_t status = MB_ENOERR;
    uint16_t crc16 = 0;

    if (slv_addr > MB_MASTER_TOTAL_SLAVE_NUM) {
        return MB_EINVAL;
    }

    if (frame_ptr && frame_len) {
        /* First byte before the Modbus-PDU is the slave address. */
        transp->snd_buf_cur = (uint8_t *)frame_ptr - 1;
        transp->snd_buf_cnt = 1;

        /* Now copy the Modbus-PDU into the Modbus-Serial-Line-PDU. */
        transp->snd_buf_cur[MB_SER_PDU_ADDR_OFF] = slv_addr;
        transp->snd_buf_cnt += frame_len;
        /* Calculate CRC16 checksum for Modbus-Serial-Line-PDU. */
        crc16 = mb_crc16((uint8_t *) transp->snd_buf_cur, transp->snd_buf_cnt);
        transp->snd_buf_cur[transp->snd_buf_cnt++] = (uint8_t)(crc16 & 0xFF);
        transp->snd_buf_cur[transp->snd_buf_cnt++] = (uint8_t)(crc16 >> 8);

        bool ret = mb_port_ser_send_data(inst->port_obj, (uint8_t *)transp->snd_buf_cur, transp->snd_buf_cnt);
        if (!ret) {
            return MB_EPORTERR;
        }
    } else {
        status = MB_EIO;
    }
    return status;
}

__attribute__((unused))
static bool mbs_rtu_transp_rcv_fsm(mb_trans_base_t *inst)
{
    return false;
}

__attribute__((unused))
static bool mbs_rtu_transp_snd_fsm(mb_trans_base_t *inst)
{
    return false;
}

static bool mbs_rtu_transp_timer_expired(void *inst)
{
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    bool need_poll = false;
    //mb_timer_mode_enum_t timer_mode = mb_port_get_cur_timer_mode(transp->base.port_obj);

    mb_port_timer_disable(transp->base.port_obj);
    
    return need_poll;
}

static void mbs_rtu_transp_get_snd_buf(mb_trans_base_t *inst, uint8_t **frame_ptr_buf)
{
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    CRITICAL_SECTION(inst->lock) {
        *frame_ptr_buf = (uint8_t *)&transp->snd_buf[MB_RTU_SER_PDU_PDU_OFF];
    }
}

void mbs_rtu_transp_get_rcv_buf(mb_trans_base_t *inst, uint8_t **frame_ptr_buf)
{
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    CRITICAL_SECTION(inst->lock) {
        *frame_ptr_buf = (uint8_t *)&transp->rcv_buf[MB_PDU_FUNC_OFF];
    }
}

__attribute__((unused))
static uint16_t mbs_rtu_transp_get_snd_len(mb_trans_base_t *inst)
{
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    return transp->snd_buf_cnt;
}

__attribute__((unused))
static void mbs_rtu_transp_set_snd_len(mb_trans_base_t *inst, uint16_t snd_pdu_len)
{
    mbs_rtu_transp_t *transp = __containerof(inst, mbs_rtu_transp_t, base);
    CRITICAL_SECTION(inst->lock) {
        transp->snd_buf_cnt = snd_pdu_len;
    }   
}

#endif