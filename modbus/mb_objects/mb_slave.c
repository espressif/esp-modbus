/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "mb_config.h"
#include "mb_common.h"
#include "mb_proto.h"
#include "mb_func.h"
#include "mb_slave.h"
#include "transport_common.h"
#include "port_common.h"
#include "ascii_transport.h"
#include "rtu_transport.h"
#include "tcp_transport.h"

static const char *TAG = "mb_object.slave";

#if (MB_SLAVE_ASCII_ENABLED || MB_SLAVE_RTU_ENABLED || MB_TCP_ENABLED)

#if (MB_SLAVE_ASCII_ENABLED || MB_SLAVE_RTU_ENABLED)

typedef struct _port_serial_opts mb_serial_opts_t;

#endif

typedef struct
{
    mb_base_t base;
    // here are slave object properties and methods
    uint8_t mb_address;
    mb_comm_mode_t cur_mode;
    const mb_fn_handler_t *func_handlers;
    mb_state_enum_t cur_state;
    uint8_t *frame;
    uint16_t length;
    uint8_t func_code;
    uint8_t rcv_addr;
    uint64_t curr_trans_id;
    volatile uint16_t *pdu_snd_len;
} mbs_object_t;

static mb_fn_handler_t slave_handlers[MB_FUNC_HANDLERS_MAX] =
    {
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
        {MB_FUNC_OTHER_REPORT_SLAVEID, (void *)mbs_fn_report_slave_id},
#endif
#if MB_FUNC_READ_INPUT_ENABLED
        {MB_FUNC_READ_INPUT_REGISTER, (void *)mbs_fn_read_input_reg},
#endif
#if MB_FUNC_READ_HOLDING_ENABLED
        {MB_FUNC_READ_HOLDING_REGISTER, (void *)mbs_fn_read_holding_reg},
#endif
#if MB_FUNC_WRITE_MULTIPLE_HOLDING_ENABLED
        {MB_FUNC_WRITE_MULTIPLE_REGISTERS, (void *)mbs_fn_write_multi_holding_reg},
#endif
#if MB_FUNC_WRITE_HOLDING_ENABLED
        {MB_FUNC_WRITE_REGISTER, (void *)mbs_fn_write_holding_reg},
#endif
#if MB_FUNC_READWRITE_HOLDING_ENABLED
        {MB_FUNC_READWRITE_MULTIPLE_REGISTERS, (void *)mbs_fn_rw_multi_holding_reg},
#endif
#if MB_FUNC_READ_COILS_ENABLED
        {MB_FUNC_READ_COILS, (void *)mbs_fn_read_coils},
#endif
#if MB_FUNC_WRITE_COIL_ENABLED
        {MB_FUNC_WRITE_SINGLE_COIL, (void *)mbs_fn_write_coil},
#endif
#if MB_FUNC_WRITE_MULTIPLE_COILS_ENABLED
        {MB_FUNC_WRITE_MULTIPLE_COILS, (void *)mbs_fn_write_multi_coils},
#endif
#if MB_FUNC_READ_DISCRETE_INPUTS_ENABLED
        {MB_FUNC_READ_DISCRETE_INPUTS, (void *)mbs_fn_read_discrete_inp},
#endif
};

mb_err_enum_t mbs_delete(mb_base_t *inst);
mb_err_enum_t mbs_enable(mb_base_t *inst);
mb_err_enum_t mbs_disable(mb_base_t *inst);
mb_err_enum_t mbs_poll(mb_base_t *inst);

#if (MB_SLAVE_RTU_ENABLED)

mb_err_enum_t mbs_rtu_create(mb_serial_opts_t *ser_opts, void **in_out_obj)
{
    mb_err_enum_t ret = MB_ENOERR;
    MB_RETURN_ON_FALSE(ser_opts, MB_EINVAL, TAG, "invalid options for the instance.");
    MB_RETURN_ON_FALSE((ser_opts->mode == MB_RTU), MB_EILLSTATE, TAG, "incorrect mode != RTU.");
    mbs_object_t *mbs_obj = NULL;
    mbs_obj = (mbs_object_t*)calloc(1, sizeof(mbs_object_t));
    MB_GOTO_ON_FALSE((mbs_obj), MB_EILLSTATE, error, TAG, "no mem for mb slave instance.");
    CRITICAL_SECTION_INIT(mbs_obj->base.lock);
    mbs_obj->cur_state = STATE_NOT_INITIALIZED;
    mbs_obj->base.delete = mbs_delete;
    mbs_obj->base.enable = mbs_enable;
    mbs_obj->base.disable = mbs_disable;
    mbs_obj->base.poll = mbs_poll;
    mbs_obj->base.descr.parent = *in_out_obj;
    mbs_obj->base.descr.is_master = false;
    mbs_obj->base.descr.obj_name = (char *)TAG;
    mbs_obj->base.descr.inst_index = mb_port_get_inst_counter_inc();
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
    mbs_obj->base.pobj_id = NULL;
    mbs_obj->base.obj_id_len = 0;
    mbs_obj->base.obj_id_chunks = 0;
#endif
    int res = asprintf(&mbs_obj->base.descr.parent_name, "mbs_rtu@%p", *in_out_obj);
    MB_GOTO_ON_FALSE((res), MB_EILLSTATE, error,
                     TAG, "name alloc fail, err: %d", (int)res);
    mb_trans_base_t *transp_obj = (mb_trans_base_t *)mbs_obj;
    ret = mbs_rtu_transp_create(ser_opts, (void **)&transp_obj);
    MB_GOTO_ON_FALSE((transp_obj && (ret == MB_ENOERR)), MB_EILLSTATE, error, 
                                TAG, "transport creation, err: %d", (int)ret);
    mbs_obj->func_handlers = slave_handlers;
    mbs_obj->cur_mode = ser_opts->mode;
    mbs_obj->mb_address = ser_opts->uid;
    mbs_obj->cur_state = STATE_DISABLED;
    transp_obj->get_tx_frm(transp_obj, (uint8_t **)&mbs_obj->frame);
    mbs_obj->base.port_obj = transp_obj->port_obj;
    mbs_obj->base.transp_obj = transp_obj;
    *in_out_obj = (void *)&(mbs_obj->base);
    ESP_LOGD(TAG, "created object %s", mbs_obj->base.descr.parent_name);
    return MB_ENOERR;
    
error:
    if (transp_obj) {
        mbs_rtu_transp_delete(transp_obj);
    }
    free(mbs_obj->base.descr.parent_name);
    CRITICAL_SECTION_CLOSE(mbs_obj->base.lock);
    free(mbs_obj);
    mb_port_get_inst_counter_dec();
    return ret;
}

#endif /* MB_SLAVE_RTU_ENABLED */

#if (MB_SLAVE_ASCII_ENABLED)

mb_err_enum_t mbs_ascii_create(mb_serial_opts_t *ser_opts, void **in_out_obj)
{
    mb_err_enum_t ret = MB_ENOERR;
    MB_RETURN_ON_FALSE(ser_opts, MB_EINVAL, TAG, "invalid options for %s instance.", TAG);
    MB_RETURN_ON_FALSE((ser_opts->mode == MB_ASCII), MB_EILLSTATE, TAG, "incorrect mode != ASCII.");
    mbs_object_t *mbs_obj = NULL;
    mbs_obj = (mbs_object_t*)calloc(1, sizeof(mbs_object_t));
    MB_GOTO_ON_FALSE((mbs_obj), MB_EILLSTATE, error, TAG, "no mem for mb slave instance.");
    CRITICAL_SECTION_INIT(mbs_obj->base.lock);
    mbs_obj->base.delete = mbs_delete;
    mbs_obj->base.enable = mbs_enable;
    mbs_obj->base.disable = mbs_disable;
    mbs_obj->base.poll = mbs_poll;
    mbs_obj->base.descr.parent = *in_out_obj;
    mbs_obj->base.descr.is_master = false;
    mbs_obj->base.descr.obj_name = (char *)TAG;
    mbs_obj->base.descr.inst_index = mb_port_get_inst_counter_inc();
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
    mbs_obj->base.pobj_id = NULL;
    mbs_obj->base.obj_id_len = 0;
    mbs_obj->base.obj_id_chunks = 0;
#endif
    int res = asprintf(&mbs_obj->base.descr.parent_name, "mbs_ascii@%p", *in_out_obj);
    MB_GOTO_ON_FALSE((res), MB_EILLSTATE, error,
                     TAG, "name alloc fail, err: %d", (int)res);
    mb_trans_base_t *transp_obj = (mb_trans_base_t *)mbs_obj;
    ret = mbs_ascii_transp_create(ser_opts, (void **)&transp_obj);
    MB_GOTO_ON_FALSE((transp_obj && (ret == MB_ENOERR)), MB_EILLSTATE, error, 
                        TAG, "transport creation, err: %d", (int)ret);
    mbs_obj->func_handlers = slave_handlers;
    mbs_obj->cur_mode = ser_opts->mode;
    mbs_obj->mb_address = ser_opts->uid;
    mbs_obj->cur_state = STATE_DISABLED;
    transp_obj->get_tx_frm(transp_obj, (uint8_t **)&mbs_obj->frame);
    mbs_obj->base.port_obj = transp_obj->port_obj;
    mbs_obj->base.transp_obj = transp_obj;
    *in_out_obj = (void *)&(mbs_obj->base);
    ESP_LOGD(TAG, "created object %s", mbs_obj->base.descr.parent_name);
    return MB_ENOERR;
    
error:
    if (transp_obj) {
        mbs_ascii_transp_delete(transp_obj);
    }
    free(mbs_obj->base.descr.parent_name);
    CRITICAL_SECTION_CLOSE(mbs_obj->base.lock);
    free(mbs_obj);
    mb_port_get_inst_counter_dec();
    return ret;
}

#endif /* MB_SLAVE_ASCII_ENABLED */

#if (MB_TCP_ENABLED)

mb_err_enum_t mbs_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj)
{
    mb_err_enum_t ret = MB_ENOERR;
    MB_RETURN_ON_FALSE(tcp_opts, MB_EINVAL, TAG, "invalid options for the instance.");
    MB_RETURN_ON_FALSE((tcp_opts->mode == MB_TCP), MB_EILLSTATE, TAG, "incorrect mode != TCP.");
    mbs_object_t *mbs_obj = NULL;
    mbs_obj = (mbs_object_t*)calloc(1, sizeof(mbs_object_t));
    MB_GOTO_ON_FALSE((mbs_obj), MB_EILLSTATE, error, TAG, "no mem for mb slave instance.");
    CRITICAL_SECTION_INIT(mbs_obj->base.lock);
    mbs_obj->cur_state = STATE_NOT_INITIALIZED;
    mbs_obj->base.delete = mbs_delete;
    mbs_obj->base.enable = mbs_enable;
    mbs_obj->base.disable = mbs_disable;
    mbs_obj->base.poll = mbs_poll;
    mbs_obj->base.descr.parent = *in_out_obj;
    mbs_obj->base.descr.is_master = false;
    mbs_obj->base.descr.obj_name = (char *)TAG;
    mbs_obj->base.descr.inst_index = mb_port_get_inst_counter_inc();
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
    mbs_obj->base.pobj_id = NULL;
    mbs_obj->base.obj_id_len = 0;
    mbs_obj->base.obj_id_chunks = 0;
#endif
    int res = asprintf(&mbs_obj->base.descr.parent_name, "mbs_tcp@%p", *in_out_obj);
    MB_GOTO_ON_FALSE((res), MB_EILLSTATE, error,
                     TAG, "name alloc fail, err: %d", (int)res);
    mb_trans_base_t *transp_obj = (mb_trans_base_t *)mbs_obj;
    ret = mbs_tcp_transp_create(tcp_opts, (void **)&transp_obj);
    MB_GOTO_ON_FALSE((transp_obj && (ret == MB_ENOERR)), MB_EILLSTATE, error, 
                                TAG, "transport creation, err: %d", (int)ret);
    mbs_obj->func_handlers = slave_handlers;
    mbs_obj->cur_mode = tcp_opts->mode;
    mbs_obj->mb_address = tcp_opts->uid;
    mbs_obj->cur_state = STATE_DISABLED;
    transp_obj->get_tx_frm(transp_obj, (uint8_t **)&mbs_obj->frame);
    mbs_obj->base.port_obj = transp_obj->port_obj;
    mbs_obj->base.transp_obj = transp_obj;
    *in_out_obj = (void *)&(mbs_obj->base);
    ESP_LOGD(TAG, "created object %s", mbs_obj->base.descr.parent_name);
    return MB_ENOERR;
    
error:
    if (transp_obj) {
        mbs_tcp_transp_delete(transp_obj);
    }
    free(mbs_obj->base.descr.parent_name);
    CRITICAL_SECTION_CLOSE(mbs_obj->base.lock);
    free(mbs_obj);
    mb_port_get_inst_counter_dec();
    return ret;
}

#endif

mb_err_enum_t mbs_delete(mb_base_t *inst)
{
    mbs_object_t *mbs_obj = MB_GET_OBJ_CTX(inst, mbs_object_t, base);
    mb_err_enum_t status = MB_ENOERR;
    if (mbs_obj->cur_state == STATE_DISABLED) {
        if (MB_OBJ(mbs_obj->base.transp_obj)->frm_delete) {
            // call destructor of the transport object
            MB_OBJ(mbs_obj->base.transp_obj)->frm_delete(inst->transp_obj);
        }
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
        // delete allocated slave ID
        if (mbs_obj->base.pobj_id) {
            free(mbs_obj->base.pobj_id);
            mbs_obj->base.pobj_id = NULL;
            mbs_obj->base.obj_id_len = 0;
            mbs_obj->base.obj_id_chunks = 0;
        }
#endif
        // delete the modbus instance
        free(mbs_obj->base.descr.parent_name);
        CRITICAL_SECTION_CLOSE(inst->lock);
        free(inst);
        status = MB_ENOERR;
    } else {
        ESP_LOGD(TAG, " need to disable %p object first.", (void *)mbs_obj);
        status = MB_EILLSTATE;
    }
    mb_port_get_inst_counter_dec();
    return status;
}

mb_err_enum_t mbs_enable(mb_base_t *inst)
{
    mbs_object_t *mbs_obj = MB_GET_OBJ_CTX(inst, mbs_object_t, base);
    mb_err_enum_t status = MB_ENOERR;
    CRITICAL_SECTION(inst->lock) {
        if (mbs_obj->cur_state == STATE_DISABLED) {
            /* Activate the protocol stack. */
            MB_OBJ(mbs_obj->base.transp_obj)->frm_start(mbs_obj->base.transp_obj);
            mbs_obj->cur_state = STATE_ENABLED;
            status = MB_ENOERR;
        } else {
            status = MB_EILLSTATE;
        }
    }
    if (!mbs_obj->mb_address) {
        ESP_LOGD(TAG, "incorrect slave address in %p object.", (void *)mbs_obj);
        status = MB_EINVAL;
    }
    return status;
}

mb_err_enum_t mbs_disable(mb_base_t *inst)
{
    mb_err_enum_t status = MB_ENOERR;
    mbs_object_t *mbs_obj = MB_GET_OBJ_CTX(inst, mbs_object_t, base);;
    CRITICAL_SECTION(inst->lock) {
        if (mbs_obj->cur_state == STATE_ENABLED) {
            MB_OBJ(mbs_obj->base.transp_obj)->frm_stop(mbs_obj->base.transp_obj);
            mbs_obj->cur_state = STATE_DISABLED;
            status = MB_ENOERR;
        } else if (mbs_obj->cur_state == STATE_DISABLED) {
            status = MB_ENOERR;
        } else {
            status = MB_EILLSTATE;
        }
    }
    return status;
}

mb_err_enum_t mbs_poll(mb_base_t *inst)
{
    mbs_object_t *mbs_obj = MB_GET_OBJ_CTX(inst, mbs_object_t, base);;

    mb_exception_t exception;
    mb_err_enum_t status = MB_ENOERR;
    mb_event_t event;

    /* Check if the protocol stack is ready. */
    if (mbs_obj->cur_state != STATE_ENABLED) {
        return MB_EILLSTATE;
    }

    /* Check if there is a event available. If not, return control to caller. Otherwise we will handle the event. */
    if (mb_port_event_get(MB_OBJ(mbs_obj->base.port_obj), &event)) {
        switch(event.event) {
            case EV_READY:
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_READY", MB_OBJ_PARENT(inst));
                mb_port_event_res_release(MB_OBJ(inst->port_obj));
                break;
                
            case EV_FRAME_RECEIVED:
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_FRAME_RECEIVED", MB_OBJ_PARENT(inst));
                mbs_obj->length = event.length;
                status = MB_OBJ(inst->transp_obj)->frm_rcv(inst->transp_obj, &mbs_obj->rcv_addr, &mbs_obj->frame, &mbs_obj->length);
                // Check if the frame is for us. If not ,send an error process event.
                if (status == MB_ENOERR) {
                    // Check if the frame is for us. If not ignore the frame.
                    if((mbs_obj->rcv_addr == mbs_obj->mb_address) || (mbs_obj->rcv_addr == MB_ADDRESS_BROADCAST) 
                            || (mbs_obj->rcv_addr == MB_TCP_PSEUDO_ADDRESS)) {
                        mbs_obj->curr_trans_id = event.get_ts;
                        (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_EXECUTE | EV_TRANS_START));
                        ESP_LOG_BUFFER_HEX_LEVEL(MB_STR_CAT(inst->descr.parent_name, ":MB_RECV"), &mbs_obj->frame[MB_PDU_FUNC_OFF], 
                                                    (uint16_t)mbs_obj->length, ESP_LOG_DEBUG);
                    }
                }
                break;

            case EV_EXECUTE:
                MB_RETURN_ON_FALSE(mbs_obj->frame, MB_EILLSTATE, TAG, "receive buffer fail.");
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_EXECUTE", MB_OBJ_PARENT(inst));
                mbs_obj->func_code = mbs_obj->frame[MB_PDU_FUNC_OFF];
                exception = MB_EX_ILLEGAL_FUNCTION;
                // If receive frame has exception. The receive function code highest bit is 1.
                for (int i = 0; (i < MB_FUNC_HANDLERS_MAX); i++) {
                    // No more function handlers registered. Abort.
                    if (mbs_obj->func_handlers[i].func_code == 0) {
                        ESP_LOGD(TAG, MB_OBJ_FMT": function (0x%x), handler is not found.", MB_OBJ_PARENT(inst), (int)mbs_obj->func_code);
                        break;
                    }
                    if ((mbs_obj->func_handlers[i].func_code) == mbs_obj->func_code) {
                        ESP_LOGD(TAG, MB_OBJ_FMT": function (0x%x), start handler.", MB_OBJ_PARENT(inst), (int)mbs_obj->func_code);
                        exception = mbs_obj->func_handlers[i].handler(inst, mbs_obj->frame, &mbs_obj->length);
                        break;
                    }
                }
                // If the request was not sent to the broadcast address, return a reply.
                if ((mbs_obj->rcv_addr != MB_ADDRESS_BROADCAST) || (mbs_obj->cur_mode == MB_TCP)) {
                    if (exception != MB_EX_NONE) {
                        // An exception occurred. Build an error frame.
                        mbs_obj->length = 0;
                        mbs_obj->frame[mbs_obj->length++] = (uint8_t)(mbs_obj->func_code | MB_FUNC_ERROR);
                        mbs_obj->frame[mbs_obj->length++] = exception;
                    }
                    if ((mbs_obj->cur_mode == MB_ASCII) && MB_ASCII_TIMEOUT_WAIT_BEFORE_SEND_MS) {
                        mb_port_timer_delay(MB_OBJ(inst->port_obj), MB_ASCII_TIMEOUT_WAIT_BEFORE_SEND_MS);
                    }
                    ESP_LOG_BUFFER_HEX_LEVEL(MB_STR_CAT(inst->descr.parent_name, ":MB_SEND"), (void *)mbs_obj->frame, mbs_obj->length, ESP_LOG_DEBUG);
                    status = MB_OBJ(inst->transp_obj)->frm_send(inst->transp_obj, mbs_obj->rcv_addr, mbs_obj->frame, mbs_obj->length);
                    if (status != MB_ENOERR) {
                        ESP_LOGE(TAG, MB_OBJ_FMT":frame send error. %d", MB_OBJ_PARENT(inst), (int)status);
                    }
                }
                break;

            case EV_FRAME_TRANSMIT:
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_FRAME_TRANSMIT", MB_OBJ_PARENT(inst));
                break;

            case EV_FRAME_SENT:
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_MASTER_FRAME_SENT", MB_OBJ_PARENT(inst));
                uint64_t time_div_us = mbs_obj->curr_trans_id ? (event.get_ts - mbs_obj->curr_trans_id) : 0;
                mbs_obj->curr_trans_id = 0;
                ESP_LOGD(TAG, MB_OBJ_FMT", transaction processing time(us) = %" PRId64, MB_OBJ_PARENT(inst), time_div_us);
                break;

            default:
                ESP_LOGD(TAG, MB_OBJ_FMT": Unexpected event 0x%02x or timeout.", MB_OBJ_PARENT(inst), (int)event.event);
                break;
        }
    } else {
        // Something went wrong and task unblocked but there are no any correct events set
        ESP_LOGD(TAG, MB_OBJ_FMT": Unexpected event 0x%02x or timeout?", MB_OBJ_PARENT(inst), (int)event.event);
        status = MB_EILLSTATE;
    }
    return status;
}

#endif /* (MB_SLAVE_ASCII_ENABLED || MB_SLAVE_RTU_ENABLED || MB_TCP_ENABLED) */