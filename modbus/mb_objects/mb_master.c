/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "mb_config.h"
#include "mb_common.h"
#include "mb_proto.h"
#include "mb_func.h"
#include "mb_master.h"
#include "transport_common.h"
#include "port_common.h"
#include "ascii_transport.h"
#include "rtu_transport.h"
#include "tcp_transport.h"

static const char *TAG = "mb_object.master";

#if (MB_MASTER_ASCII_ENABLED || MB_MASTER_RTU_ENABLED) 

typedef struct port_serial_opts_s mb_serial_opts_t;

#endif

#if (MB_MASTER_ASCII_ENABLED || MB_MASTER_RTU_ENABLED || MB_MASTER_TCP_ENABLED)

typedef struct
{
    mb_base_t base;

    mb_comm_mode_t cur_mode;
    mb_state_enum_t cur_state;
    uint8_t *rcv_frame;
    uint8_t *snd_frame;
    uint16_t pdu_snd_len;
    uint8_t rcv_addr;
    uint16_t pdu_rcv_len;
    uint8_t func_code;
    mb_exception_t exception;
    uint8_t master_dst_addr;
    uint64_t curr_trans_id;
    handler_descriptor_t handler_descriptor;
} mbm_object_t;

mb_err_enum_t mbm_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);

mb_err_enum_t mbm_delete(mb_base_t *inst);
mb_err_enum_t mbm_enable(mb_base_t *inst);
mb_err_enum_t mbm_disable(mb_base_t *inst);
mb_err_enum_t mbm_poll(mb_base_t *inst);

static void mbm_set_pdu_send_length(mb_base_t *inst, uint16_t length);
static uint16_t mbm_get_pdu_send_length(mb_base_t *inst);
static void mbm_set_dest_addr(mb_base_t *inst, uint8_t dest_addr);
static uint8_t mbm_get_dest_addr(mb_base_t *inst);
static void mbm_get_pdu_send_buf(mb_base_t *inst, uint8_t **pbuf);

mb_err_enum_t mbm_set_handler(mb_base_t *inst, uint8_t func_code, mb_fn_handler_fp phandler)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    mb_err_enum_t status = MB_EILLSTATE;
    SEMA_SECTION(mbm_obj->handler_descriptor.sema, MB_HANDLER_UNLOCK_TICKS) {
        status = mb_set_handler(&mbm_obj->handler_descriptor, func_code, phandler);
    }
    return status;
}

// The helper function to register custom function handler for master
mb_err_enum_t mbm_get_handler(mb_base_t *inst, uint8_t func_code, mb_fn_handler_fp *phandler)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    mb_err_enum_t status = MB_EILLSTATE;
    if (phandler) {
        SEMA_SECTION(mbm_obj->handler_descriptor.sema, MB_HANDLER_UNLOCK_TICKS) {
            status = mb_get_handler(&mbm_obj->handler_descriptor, func_code, phandler);
        }
    }
    return status;
}

mb_err_enum_t mbm_delete_handler(mb_base_t *inst, uint8_t func_code)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    mb_err_enum_t status = MB_EILLSTATE;
    SEMA_SECTION(mbm_obj->handler_descriptor.sema, MB_HANDLER_UNLOCK_TICKS) {
        status = mb_delete_handler(&mbm_obj->handler_descriptor, func_code);
    }
    return status;
}

mb_err_enum_t mbm_get_handler_count(mb_base_t *inst, uint16_t *pcount)
{
    MB_RETURN_ON_FALSE((pcount && inst), MB_EINVAL, TAG, "get handler count wrong arguments.");
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    SEMA_SECTION(mbm_obj->handler_descriptor.sema, MB_HANDLER_UNLOCK_TICKS) {
        *pcount = mbm_obj->handler_descriptor.count;
    }
    return MB_ENOERR;
}

static mb_err_enum_t mbm_check_invoke_handler(mb_base_t *inst, uint8_t func_code, uint8_t *pbuf, uint16_t *plen)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    mb_exception_t exception = MB_EX_ILLEGAL_FUNCTION;
    if (!func_code || !pbuf) {
        return MB_EX_ILLEGAL_FUNCTION;
    }
    if (func_code & MB_FUNC_ERROR) {
        exception = (mb_exception_t)pbuf[MB_PDU_DATA_OFF];
        return exception;
    }
    SEMA_SECTION(mbm_obj->handler_descriptor.sema, MB_HANDLER_UNLOCK_TICKS) {
        mb_fn_handler_fp phandler = NULL;
        mb_err_enum_t status = mb_get_handler(&mbm_obj->handler_descriptor, func_code, &phandler);
        if ((status == MB_ENOERR) && phandler) {
            exception = phandler(inst, pbuf, plen);
        }
    }
    return exception;
}

static mb_err_enum_t mbm_register_default_handlers(mb_base_t *inst)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    mb_err_enum_t err = MB_EILLSTATE;
    LIST_INIT(&mbm_obj->handler_descriptor.head);
    mbm_obj->handler_descriptor.sema = xSemaphoreCreateBinary();
    (void)xSemaphoreGive(mbm_obj->handler_descriptor.sema);
    mbm_obj->handler_descriptor.instance = (void *)inst->descr.parent;
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_OTHER_REPORT_SLAVEID, (void *)mbm_fn_report_slave_id);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_READ_INPUT_ENABLED
        err =  mbm_set_handler(inst, MB_FUNC_READ_INPUT_REGISTER, (void *)mbm_fn_read_inp_reg);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_READ_HOLDING_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_READ_HOLDING_REGISTER, (void *)mbm_fn_read_holding_reg);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_WRITE_MULTIPLE_HOLDING_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_WRITE_MULTIPLE_REGISTERS, (void *)mbm_fn_write_multi_holding_reg);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_WRITE_HOLDING_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_WRITE_REGISTER, (void *)mbm_fn_write_holding_reg);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_READWRITE_HOLDING_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_READWRITE_MULTIPLE_REGISTERS, (void *)mbm_fn_rw_multi_holding_regs);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_READ_COILS_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_READ_COILS, (void *)mbm_fn_read_coils);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_WRITE_COIL_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_WRITE_SINGLE_COIL, (void *)mbm_fn_write_coil);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_WRITE_MULTIPLE_COILS_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_WRITE_MULTIPLE_COILS, (void *)mbm_fn_write_multi_coils);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
#if MB_FUNC_READ_DISCRETE_INPUTS_ENABLED
        err = mbm_set_handler(inst, MB_FUNC_READ_DISCRETE_INPUTS, (void *)mbm_fn_read_discrete_inputs);
        MB_RETURN_ON_FALSE((err == MB_ENOERR), err, TAG, "handler registration error = (0x%x).", (int)err);
#endif
    return MB_ENOERR;
}

static mb_err_enum_t mbm_unregister_handlers(mb_base_t *inst)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    (void)xSemaphoreTake(mbm_obj->handler_descriptor.sema, MB_HANDLER_UNLOCK_TICKS);
    ESP_LOGD(TAG, "Close %s command handlers.", mbm_obj->base.descr.parent_name);
    (void)mb_delete_command_handlers(&mbm_obj->handler_descriptor);
    mbm_obj->handler_descriptor.instance = NULL;
    (void)xSemaphoreGive(mbm_obj->handler_descriptor.sema);
    vSemaphoreDelete(mbm_obj->handler_descriptor.sema);
    return MB_ENOERR;
}

#if (MB_MASTER_RTU_ENABLED)

mb_err_enum_t mbm_rtu_create(mb_serial_opts_t *ser_opts, void **in_out_obj)
{
    MB_RETURN_ON_FALSE((ser_opts && in_out_obj), MB_EINVAL, TAG, "invalid options for the instance.");
    MB_RETURN_ON_FALSE((ser_opts->mode == MB_RTU), MB_EILLSTATE, TAG, "incorrect mode != RTU.");
    mb_err_enum_t ret = MB_ENOERR;
    mbm_object_t *mbm_obj = NULL;
    mbm_obj = (mbm_object_t *)calloc(1, sizeof(mbm_object_t));
    MB_GOTO_ON_FALSE((mbm_obj), MB_EILLSTATE, error, TAG, "no mem for mb master instance.");
    CRITICAL_SECTION_INIT(mbm_obj->base.lock);
    mbm_obj->cur_state = STATE_NOT_INITIALIZED;
    mbm_obj->base.delete = mbm_delete;
    mbm_obj->base.enable = mbm_enable;
    mbm_obj->base.disable = mbm_disable;
    mbm_obj->base.poll = mbm_poll;
    mbm_obj->base.set_dest_addr = mbm_set_dest_addr;
    mbm_obj->base.get_dest_addr = mbm_get_dest_addr;
    mbm_obj->base.set_send_len = mbm_set_pdu_send_length;
    mbm_obj->base.get_send_len = mbm_get_pdu_send_length;
    mbm_obj->base.get_send_buf = mbm_get_pdu_send_buf;
    mbm_obj->base.descr.parent = *in_out_obj;
    mbm_obj->base.descr.is_master = true;
    mbm_obj->base.descr.obj_name = (char *)TAG;
    mbm_obj->base.descr.inst_index = mb_port_get_inst_counter_inc();
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
    mbm_obj->base.pobj_id = NULL;
    mbm_obj->base.obj_id_len = 0;
    mbm_obj->base.obj_id_chunks = 0;
#endif
    int res = asprintf(&mbm_obj->base.descr.parent_name, "mbm_rtu@%p", mbm_obj->base.descr.parent);
    MB_GOTO_ON_FALSE((res), MB_EILLSTATE, error,
                     TAG, "name alloc fail, err: %d", (int)res);
    mb_trans_base_t *transp_obj = (mb_trans_base_t *)mbm_obj;
    ret = mbm_rtu_transp_create(ser_opts, (void **)&transp_obj);
    MB_GOTO_ON_FALSE((transp_obj && (ret == MB_ENOERR)), MB_EILLSTATE, error,
                     TAG, "transport creation, err: %d", (int)ret);
    mbm_obj->cur_mode = ser_opts->mode;
    mbm_obj->cur_state = STATE_DISABLED;
    transp_obj->get_tx_frm(transp_obj, (uint8_t **)&mbm_obj->snd_frame);
    transp_obj->get_rx_frm(transp_obj, (uint8_t **)&mbm_obj->rcv_frame);
    mbm_obj->curr_trans_id = 0;
    mbm_obj->base.port_obj = transp_obj->port_obj;
    mbm_obj->base.transp_obj = transp_obj;
    ret = mbm_register_default_handlers(&mbm_obj->base);
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EILLSTATE, error,
                        TAG, "default handlers registration fail, err: %d", (int)ret);
    *in_out_obj = (void *)&(mbm_obj->base);
    ESP_LOGD(TAG, "created object %s", mbm_obj->base.descr.parent_name);
    return MB_ENOERR;

error:
    if (transp_obj) {
        mbm_rtu_transp_delete(transp_obj);
    }
    (void)mbm_unregister_handlers(&mbm_obj->base);
    free(mbm_obj->base.descr.parent_name);
    CRITICAL_SECTION_CLOSE(mbm_obj->base.lock);
    free(mbm_obj);
    mb_port_get_inst_counter_dec();
    return ret;
}

#endif /* MB_MASTER_RTU_ENABLED */

#if (MB_MASTER_ASCII_ENABLED)

mb_err_enum_t mbm_ascii_create(mb_serial_opts_t *ser_opts, void **in_out_obj)
{
    MB_RETURN_ON_FALSE((ser_opts && in_out_obj), MB_EINVAL, TAG, "invalid options for the instance.");
    MB_RETURN_ON_FALSE((ser_opts->mode == MB_ASCII), MB_EILLSTATE, TAG, "incorrect option mode != ASCII.");
    mb_err_enum_t ret = MB_ENOERR;
    mbm_object_t *mbm_obj = NULL;
    mbm_obj = (mbm_object_t *)calloc(1, sizeof(mbm_object_t));
    MB_GOTO_ON_FALSE((mbm_obj), MB_EILLSTATE, error, TAG, "no mem for mb master instance.");
    CRITICAL_SECTION_INIT(mbm_obj->base.lock);
    mbm_obj->cur_state = STATE_NOT_INITIALIZED;
    mbm_obj->base.delete = mbm_delete;
    mbm_obj->base.enable = mbm_enable;
    mbm_obj->base.disable = mbm_disable;
    mbm_obj->base.poll = mbm_poll;
    mbm_obj->base.set_dest_addr = mbm_set_dest_addr;
    mbm_obj->base.get_dest_addr = mbm_get_dest_addr;
    mbm_obj->base.set_send_len = mbm_set_pdu_send_length;
    mbm_obj->base.get_send_len = mbm_get_pdu_send_length;
    mbm_obj->base.get_send_buf = mbm_get_pdu_send_buf;
    mbm_obj->base.descr.parent = *in_out_obj;
    mbm_obj->base.descr.is_master = true;
    mbm_obj->base.descr.obj_name = (char *)TAG;
    mbm_obj->base.descr.inst_index = mb_port_get_inst_counter_inc();
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
    mbm_obj->base.pobj_id = NULL;
    mbm_obj->base.obj_id_len = 0;
    mbm_obj->base.obj_id_chunks = 0;
#endif
    int res = asprintf(&mbm_obj->base.descr.parent_name, "mbm_ascii@%p", mbm_obj->base.descr.parent);
    MB_GOTO_ON_FALSE((res), MB_EILLSTATE, error,
                     TAG, "name alloc fail, err: %d", (int)res);
    mb_trans_base_t *transp_obj = (mb_trans_base_t *)mbm_obj;
    ret = mbm_ascii_transp_create(ser_opts, (void **)&transp_obj);
    MB_GOTO_ON_FALSE((transp_obj && (ret == MB_ENOERR)), MB_EILLSTATE, error,
                     TAG, "transport creation, err: %d", (int)ret);
    ret = mbm_register_default_handlers(&mbm_obj->base);
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EILLSTATE, error,
                        TAG, "default handlers registration fail, err: %d", (int)ret);
    mbm_obj->cur_mode = ser_opts->mode;
    mbm_obj->cur_state = STATE_DISABLED;
    transp_obj->get_tx_frm(transp_obj, (uint8_t **)&mbm_obj->snd_frame);
    transp_obj->get_rx_frm(transp_obj, (uint8_t **)&mbm_obj->rcv_frame);
    mbm_obj->base.port_obj = transp_obj->port_obj; // binding of the modbus object with port object
    mbm_obj->base.transp_obj = transp_obj;
    *in_out_obj = (void *)&(mbm_obj->base);
    ESP_LOGD(TAG, "created object %s", mbm_obj->base.descr.parent_name);
    return MB_ENOERR;

error:
    if (transp_obj)
    {
        mbm_ascii_transp_delete(transp_obj);
    }
    (void)mbm_unregister_handlers(&mbm_obj->base);
    free(mbm_obj->base.descr.parent_name);
    CRITICAL_SECTION_CLOSE(mbm_obj->base.lock);
    free(mbm_obj);
    mb_port_get_inst_counter_dec();
    return ret;
}

#endif /* MB_MASTER_ASCII_ENABLED */

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

mb_err_enum_t mbm_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj)
{
    MB_RETURN_ON_FALSE((tcp_opts && in_out_obj), MB_EINVAL, TAG, "invalid options for the instance.");
    MB_RETURN_ON_FALSE((tcp_opts->mode == MB_TCP), MB_EILLSTATE, TAG, "incorrect option mode != TCP.");
    mb_err_enum_t ret = MB_ENOERR;
    mbm_object_t *mbm_obj = NULL;
    mbm_obj = (mbm_object_t *)calloc(1, sizeof(mbm_object_t));
    MB_RETURN_ON_FALSE(mbm_obj, MB_EILLSTATE, TAG, "no mem for mb master instance.");
    CRITICAL_SECTION_INIT(mbm_obj->base.lock);
    mbm_obj->cur_state = STATE_NOT_INITIALIZED;
    mbm_obj->base.delete = mbm_delete;
    mbm_obj->base.enable = mbm_enable;
    mbm_obj->base.disable = mbm_disable;
    mbm_obj->base.poll = mbm_poll;
    mbm_obj->base.set_dest_addr = mbm_set_dest_addr;
    mbm_obj->base.get_dest_addr = mbm_get_dest_addr;
    mbm_obj->base.set_send_len = mbm_set_pdu_send_length;
    mbm_obj->base.get_send_len = mbm_get_pdu_send_length;
    mbm_obj->base.get_send_buf = mbm_get_pdu_send_buf;
    mbm_obj->base.descr.parent = *in_out_obj;
    mbm_obj->base.descr.is_master = true;
    mbm_obj->base.descr.obj_name = (char *)TAG;
    mbm_obj->base.descr.inst_index = mb_port_get_inst_counter_inc();
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
    mbm_obj->base.pobj_id = NULL;
    mbm_obj->base.obj_id_len = 0;
    mbm_obj->base.obj_id_chunks = 0;
#endif
    int res = asprintf(&mbm_obj->base.descr.parent_name, "mbm_tcp#%p", mbm_obj->base.descr.parent);
    MB_GOTO_ON_FALSE((res), MB_EILLSTATE, error,
                        TAG, "name alloc fail, err: %d", (int)res);
    mb_trans_base_t *transp_obj = (mb_trans_base_t *)mbm_obj;
    ret = mbm_tcp_transp_create(tcp_opts, (void **)&transp_obj);
    MB_GOTO_ON_FALSE((transp_obj && (ret == MB_ENOERR)), MB_EILLSTATE, error,
                     TAG, "transport creation, err: %d", (int)ret);
    ret = mbm_register_default_handlers(&mbm_obj->base);
    MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EILLSTATE, error,
                        TAG, "default handlers registration fail, err: %d", (int)ret);
    mbm_obj->cur_mode = tcp_opts->mode;
    mbm_obj->cur_state = STATE_DISABLED;
    transp_obj->get_tx_frm(transp_obj, (uint8_t **)&mbm_obj->snd_frame);
    transp_obj->get_rx_frm(transp_obj, (uint8_t **)&mbm_obj->rcv_frame);
    mbm_obj->base.port_obj = transp_obj->port_obj; // binding of the modbus object with port object
    mbm_obj->base.transp_obj = transp_obj;
    *in_out_obj = (void *)&(mbm_obj->base);
    ESP_LOGD(TAG, "created object %s", mbm_obj->base.descr.parent_name);
    return MB_ENOERR;

error:
    if (transp_obj) {
        mbm_tcp_transp_delete(transp_obj);
    }
    (void)mbm_unregister_handlers(&mbm_obj->base);
    free(mbm_obj->base.descr.parent_name);
    CRITICAL_SECTION_CLOSE(mbm_obj->base.lock);
    free(mbm_obj);
    mb_port_get_inst_counter_dec();
    return ret;
}

#endif

mb_err_enum_t mbm_delete(mb_base_t *inst)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    mb_err_enum_t status = MB_ENOERR;
    if (mbm_obj->cur_state == STATE_DISABLED) {
        if (MB_OBJ(mbm_obj->base.transp_obj)->frm_delete) {
            // call destructor of the transport object
            mbm_obj->base.transp_obj->frm_delete(inst->transp_obj);
        }
#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
        // check object ID
        if (mbm_obj->base.pobj_id) {
            free(mbm_obj->base.pobj_id);
            mbm_obj->base.pobj_id = NULL;
            mbm_obj->base.obj_id_len = 0;
            mbm_obj->base.obj_id_chunks = 0;
            ESP_LOGW(TAG, "%p, Master object ID is not supported!", mbm_obj);
        }
#endif
        (void)mbm_unregister_handlers(&mbm_obj->base);
        // delete the modbus instance
        free(mbm_obj->base.descr.parent_name);
        CRITICAL_SECTION_CLOSE(inst->lock);
        status = MB_ENOERR;
        free(inst);
    } else {
        ESP_LOGD(TAG, "disable the instance %p first.", mbm_obj);
        status = MB_EILLSTATE;
    }
    mb_port_get_inst_counter_dec();
    return status;
}

mb_err_enum_t mbm_enable(mb_base_t *inst)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    mb_err_enum_t status = MB_ENOERR;
    CRITICAL_SECTION(inst->lock)
    {
        if (mbm_obj->cur_state == STATE_DISABLED) {
            /* Activate the protocol stack. */
            MB_OBJ(mbm_obj->base.transp_obj)->frm_start(mbm_obj->base.transp_obj);
            mbm_obj->cur_state = STATE_ENABLED;
            status = MB_ENOERR;
        } else {
            status = MB_EILLSTATE;
        }
    }
    return status;
}

mb_err_enum_t mbm_disable(mb_base_t *inst)
{
    mb_err_enum_t status = MB_ENOERR;
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    // Wait for function handler to be unlocked before disable the object
    (void)xSemaphoreTake(mbm_obj->handler_descriptor.sema, MB_HANDLER_UNLOCK_TICKS);
    (void)xSemaphoreGive(mbm_obj->handler_descriptor.sema);
    CRITICAL_SECTION(inst->lock)
    {
        if (mbm_obj->cur_state == STATE_ENABLED) {
            MB_OBJ(mbm_obj->base.transp_obj)->frm_stop(mbm_obj->base.transp_obj);
            mbm_obj->cur_state = STATE_DISABLED;
            status = MB_ENOERR;
        } else if (mbm_obj->cur_state == STATE_DISABLED) {
            status = MB_ENOERR;
        } else {
            status = MB_EILLSTATE;
        }
    }
    return status;
}

static void mbm_get_pdu_send_buf(mb_base_t *inst, uint8_t **pbuf)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    MB_OBJ(mbm_obj->base.transp_obj)->get_tx_frm(mbm_obj->base.transp_obj, pbuf);
}

__attribute__((unused))
static void mbm_get_pdu_recv_buf(mb_base_t *inst, uint8_t **pbuf)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);;
    MB_OBJ(mbm_obj->base.transp_obj)->get_rx_frm(mbm_obj->base.transp_obj, pbuf);
}

static void mbm_set_pdu_send_length(mb_base_t *inst, uint16_t length)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    CRITICAL_SECTION(inst->lock)
    {
        mbm_obj->pdu_snd_len = length;
    }
}

static uint16_t mbm_get_pdu_send_length(mb_base_t *inst)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    return mbm_obj->pdu_snd_len;
}

static void mbm_set_dest_addr(mb_base_t *inst, uint8_t dest_addr)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    CRITICAL_SECTION(inst->lock)
    {
        mbm_obj->master_dst_addr = dest_addr;
    }
}

static uint8_t mbm_get_dest_addr(mb_base_t *inst)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);
    return mbm_obj->master_dst_addr;
}

void mbm_error_cb_respond_timeout(mb_base_t *inst, uint8_t dest_addr, const uint8_t *pdu_data, uint16_t pdu_length)
{
    mb_port_event_set_resp_flag(MB_BASE2PORT(inst), EV_MASTER_ERROR_RESPOND_TIMEOUT);
    ESP_LOG_BUFFER_HEX_LEVEL(__func__, (void *)pdu_data, pdu_length, ESP_LOG_DEBUG);
}

void mbm_error_cb_receive_data(mb_base_t *inst, uint8_t dest_addr, const uint8_t *pdu_data, uint16_t pdu_length)
{
    mb_port_event_set_resp_flag(MB_BASE2PORT(inst), EV_MASTER_ERROR_RECEIVE_DATA);
    ESP_LOG_BUFFER_HEX_LEVEL(__func__, (void *)pdu_data, pdu_length, ESP_LOG_DEBUG);
}

void mbm_error_cb_execute_function(mb_base_t *inst, uint8_t dest_address, const uint8_t *pdu_data, uint16_t pdu_length)
{
    mb_port_event_set_resp_flag(MB_BASE2PORT(inst), EV_MASTER_ERROR_EXECUTE_FUNCTION);
    ESP_LOG_BUFFER_HEX_LEVEL(__func__, (void *)pdu_data, pdu_length, ESP_LOG_DEBUG);
}

void mbm_error_cb_request_success(mb_base_t *inst, uint8_t dest_address, const uint8_t *pdu_data, uint16_t pdu_length)
{
    mb_port_event_set_resp_flag(MB_BASE2PORT(inst), EV_MASTER_PROCESS_SUCCESS);
    ESP_LOG_BUFFER_HEX_LEVEL(__func__, (void *)pdu_data, pdu_length, ESP_LOG_DEBUG);
}

mb_err_enum_t mbm_poll(mb_base_t *inst)
{
    mbm_object_t *mbm_obj = MB_GET_OBJ_CTX(inst, mbm_object_t, base);;

    uint16_t length;
    mb_exception_t exception;
    mb_err_enum_t status = MB_ENOERR;
    mb_event_t event;
    mb_err_event_t error_type;

    /* Check if the protocol stack is ready. */
    if (mbm_obj->cur_state != STATE_ENABLED) {
        return MB_EILLSTATE;
    }

    /* Check if there is a event available. If not return control to caller.
     * Otherwise we will handle the event. */
    if (mb_port_event_get(MB_OBJ(mbm_obj->base.port_obj), &event)) {
        switch (event.event) {
            case EV_READY:
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_READY", MB_OBJ_PARENT(inst));
                mb_port_event_res_release(MB_OBJ(inst->port_obj));
                break;

            case EV_FRAME_TRANSMIT:
                mbm_get_pdu_send_buf(inst, &mbm_obj->snd_frame);
                ESP_LOG_BUFFER_HEX_LEVEL(MB_STR_CAT(inst->descr.parent_name, ":MB_TRANSMIT"), 
                                            (void *)mbm_obj->snd_frame, mbm_obj->pdu_snd_len, ESP_LOG_DEBUG);
                status = MB_OBJ(inst->transp_obj)->frm_send(inst->transp_obj, mbm_obj->master_dst_addr, 
                                                                mbm_obj->snd_frame, mbm_obj->pdu_snd_len);
                if (status != MB_ENOERR) {
                    mb_port_event_set_err_type(MB_OBJ(inst->port_obj), EV_ERROR_RESPOND_TIMEOUT);
                    (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_ERROR_PROCESS));
                    ESP_LOGE(TAG, MB_OBJ_FMT", frame send error. %d", MB_OBJ_PARENT(inst), (int)status);
                }
                // Initialize modbus transaction
                mbm_obj->curr_trans_id = event.trans_id;
                break;

            case EV_FRAME_SENT:
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_FRAME_SENT", MB_OBJ_PARENT(inst));
                break;

            case EV_FRAME_RECEIVED:
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_FRAME_RECEIVED", MB_OBJ_PARENT(inst));
                mbm_obj->pdu_rcv_len = event.length;
                status = MB_OBJ(inst->transp_obj)->frm_rcv(inst->transp_obj, &mbm_obj->rcv_addr,
                                                            &mbm_obj->rcv_frame, &mbm_obj->pdu_rcv_len);
                MB_RETURN_ON_FALSE(mbm_obj->snd_frame, MB_EILLSTATE, TAG, "Send buffer initialization fail.");
                if (event.trans_id == mbm_obj->curr_trans_id) {
                    // Check if the frame is for us. If not ,send an error process event.
                    if ((status == MB_ENOERR) && ((mbm_obj->rcv_addr == mbm_obj->master_dst_addr)
                            || (mbm_obj->rcv_addr == MB_TCP_PSEUDO_ADDRESS))) {
                        if ((mbm_obj->rcv_frame[MB_PDU_FUNC_OFF] & ~MB_FUNC_ERROR) == (mbm_obj->snd_frame[MB_PDU_FUNC_OFF])) {
                            ESP_LOGD(TAG, MB_OBJ_FMT", frame data received successfully, (%d).", MB_OBJ_PARENT(inst), (int)status);
                            ESP_LOG_BUFFER_HEX_LEVEL(MB_STR_CAT(inst->descr.parent_name, ":MB_RECV"), (void *)mbm_obj->rcv_frame, 
                                                        (uint16_t)mbm_obj->pdu_rcv_len, ESP_LOG_DEBUG);
                            (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_EXECUTE));
                        } else {
                            ESP_LOGE(TAG, MB_OBJ_FMT", drop incorrect frame, receive_func(%u) != send_func(%u)",
                                        MB_OBJ_PARENT(inst), (mbm_obj->rcv_frame[MB_PDU_FUNC_OFF] & ~MB_FUNC_ERROR), 
                                        mbm_obj->snd_frame[MB_PDU_FUNC_OFF]);
                            mb_port_event_set_err_type(MB_OBJ(inst->port_obj), EV_ERROR_RECEIVE_DATA);
                            (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_ERROR_PROCESS));
                        }
                    } else {
                        mb_port_event_set_err_type(MB_OBJ(inst->port_obj), EV_ERROR_RECEIVE_DATA);
                        (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_ERROR_PROCESS));
                        ESP_LOGD(TAG, MB_OBJ_FMT", packet data receive failed (addr=%u)(%u).",
                                    MB_OBJ_PARENT(inst), (unsigned)mbm_obj->rcv_addr, (unsigned)status);
                    }
                } else {
                    // Ignore the `EV_FRAME_RECEIVED` event because the respond timeout occurred
                    // and this is likely respond to previous transaction
                    ESP_LOGE(TAG, MB_OBJ_FMT", drop data received outside of transaction.", MB_OBJ_PARENT(inst));
                    mb_port_event_set_err_type(MB_OBJ(inst->port_obj), EV_ERROR_RESPOND_TIMEOUT);
                    (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_ERROR_PROCESS));
                }
                break;

            case EV_EXECUTE:
                if (event.trans_id == mbm_obj->curr_trans_id) {
                    if (MB_OBJ(inst->transp_obj)->frm_is_bcast(inst->transp_obj)
                        && ((mbm_obj->cur_mode == MB_RTU) || (mbm_obj->cur_mode == MB_ASCII))) {
                        mbm_obj->rcv_frame = mbm_obj->snd_frame;
                    }
                    MB_RETURN_ON_FALSE(mbm_obj->rcv_frame, MB_EILLSTATE, TAG,
                                        MB_OBJ_FMT", receive buffer initialization fail.", MB_OBJ_PARENT(inst));
                    ESP_LOGD(TAG, MB_OBJ_FMT":EV_EXECUTE", MB_OBJ_PARENT(inst));
                    mbm_obj->func_code = mbm_obj->rcv_frame[MB_PDU_FUNC_OFF];
                    exception = MB_EX_ILLEGAL_FUNCTION;
                    /* If master request is broadcast,
                     * the master needs to execute function for all slaves.
                     */
                    if (MB_OBJ(inst->transp_obj)->frm_is_bcast(inst->transp_obj)) {
                        length = mbm_obj->pdu_snd_len;
                        for (int j = 1; j <= MB_MASTER_TOTAL_SLAVE_NUM; j++) {
                            mbm_set_dest_addr(inst, j);
                            exception = mbm_check_invoke_handler(inst, mbm_obj->func_code, mbm_obj->rcv_frame, &length);
                        }
                    } else {
                        ESP_LOGD(TAG, MB_OBJ_FMT": function (0x%x), invoke handler.", MB_OBJ_PARENT(inst), (int)mbm_obj->func_code);
                        exception = mbm_check_invoke_handler(inst, mbm_obj->func_code, mbm_obj->rcv_frame, &mbm_obj->pdu_rcv_len);
                    }
                    /* If master has exception, will send error process event. Otherwise the master is idle.*/
                    if (exception != MB_EX_NONE) {
                        mb_port_event_set_err_type(MB_OBJ(inst->port_obj), EV_ERROR_EXECUTE_FUNCTION);
                        (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_ERROR_PROCESS));
                    } else {
                        error_type = mb_port_event_get_err_type(MB_OBJ(inst->port_obj));
                        if (error_type == EV_ERROR_INIT) {
                            ESP_LOGD(TAG, MB_OBJ_FMT", set event EV_ERROR_OK", MB_OBJ_PARENT(inst));
                            mb_port_event_set_err_type(MB_OBJ(inst->port_obj), EV_ERROR_OK);
                            (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_ERROR_PROCESS));
                        }
                    }
                } else {
                    mb_port_event_set_err_type(MB_OBJ(inst->port_obj), EV_ERROR_EXECUTE_FUNCTION);
                    (void)mb_port_event_post(MB_OBJ(inst->port_obj), EVENT(EV_ERROR_PROCESS));
                    ESP_LOGE(TAG, MB_OBJ_FMT", execution is expired.", MB_OBJ_PARENT(inst));
                }
                break;

            case EV_ERROR_PROCESS:
                ESP_LOGD(TAG, MB_OBJ_FMT":EV_ERROR_PROCESS", MB_OBJ_PARENT(inst));
                // stop timer and execute specified error process callback function.
                mb_port_timer_disable(MB_OBJ(inst->port_obj));
                error_type = mb_port_event_get_err_type(MB_OBJ(inst->port_obj));
                mbm_get_pdu_send_buf(inst, &mbm_obj->snd_frame);
                switch (error_type)
                {
                    case EV_ERROR_RESPOND_TIMEOUT:
                        mbm_error_cb_respond_timeout(inst, mbm_obj->master_dst_addr,
                                                    mbm_obj->snd_frame, mbm_obj->pdu_snd_len);
                        break;
                    case EV_ERROR_RECEIVE_DATA:
                        mbm_error_cb_receive_data(inst, mbm_obj->master_dst_addr,
                                                    mbm_obj->snd_frame, mbm_obj->pdu_snd_len);
                        break;
                    case EV_ERROR_EXECUTE_FUNCTION:
                        mbm_error_cb_execute_function(inst, mbm_obj->master_dst_addr,
                                                    mbm_obj->snd_frame, mbm_obj->pdu_snd_len);
                        break;
                    case EV_ERROR_OK:
                        mbm_error_cb_request_success(inst, mbm_obj->master_dst_addr,
                                                    mbm_obj->snd_frame, mbm_obj->pdu_snd_len);
                        break;
                    default:
                        ESP_LOGE(TAG, MB_OBJ_FMT", incorrect error type = %d.", MB_OBJ_PARENT(inst), (int)error_type);
                        break;
                }
                mb_port_event_set_err_type(MB_OBJ(inst->port_obj), EV_ERROR_INIT);
                uint64_t time_div_us = mbm_obj->curr_trans_id ? (event.get_ts - mbm_obj->curr_trans_id) : 0;
                mbm_obj->curr_trans_id = 0;
                ESP_LOGD(TAG, MB_OBJ_FMT", transaction processing time(us) = %" PRId64, MB_OBJ_PARENT(inst), time_div_us);
                mb_port_event_res_release(MB_OBJ(inst->port_obj));
                break;

            default:
                ESP_LOGD(TAG, MB_OBJ_FMT": Unexpected event 0x%02x or timeout?", MB_OBJ_PARENT(inst), (int)event.event);
                break;
        }
    } else {
        // Something went wrong and task unblocked but there are no any correct events set
        ESP_LOGD(TAG, MB_OBJ_FMT": Unexpected event 0x%02x or timeout?", MB_OBJ_PARENT(inst), (int)event.event);
        status = MB_EILLSTATE;
    }
    return status;
}

#endif
