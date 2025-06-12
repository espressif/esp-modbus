/*
 * FreeModbus Libary: A portable Modbus implementation for Modbus ASCII/RTU.
 * Copyright (c) 2016, 2017 Nucleron R&D LLC <main@nucleron.ru>
 * Copyright (c) 2006 Christian Walter <wolti@sil.at>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * File: $Id: mbfuncother.c, v 1.8 2006/12/07 22:10:34 wolti Exp $
 */
#include <sys/param.h>
#include "mb_common.h"
#include "mb_proto.h"
#include "mb_slave.h"
#include "mb_master.h"

#define MB_PDU_BYTECNT_OFF              (MB_PDU_DATA_OFF + 0)
#define MB_PDU_FUNC_DATA_OFF            (MB_PDU_DATA_OFF + 1)
#define MB_CMD_SL_ID_LEN                (1)
#define MB_SLAVE_ID_CHUNK_SIZE          (MIN(MB_FUNC_OTHER_REP_SLAVEID_BUF, 32))

/* ----------------------- Start implementation -----------------------------*/
mb_exception_t mb_error_to_exception(mb_err_enum_t error_code);

/**
 * This helper function performs the custom request.
 *
 * @param uid slave address
 * @param fc custom function code
 * @param buf additional data to send
 * @param buf_size size of data to send
 * @param timeout timeout
 *
 * @return error code (mb_err_enum_t)
 */
mb_err_enum_t mbm_rq_custom(mb_base_t *inst, uint8_t uid, uint8_t fc, uint8_t *buf, uint16_t buf_size, uint32_t tout)
{
    uint8_t *mb_frame_ptr;
    if (!buf || (uid > MB_ADDRESS_MAX) || (buf_size >= (MB_BUFFER_SIZE - 2))) {
        return MB_EINVAL;
    }
    if (!mb_port_event_res_take(inst->port_obj, tout)) {
        return MB_EBUSY;
    }
    inst->get_send_buf(inst, &mb_frame_ptr);
    inst->set_dest_addr(inst, uid);

    mb_frame_ptr[MB_PDU_FUNC_OFF] = fc;

    memcpy(&mb_frame_ptr[MB_PDU_DATA_OFF], buf, buf_size);

    inst->set_send_len(inst, MB_PDU_SIZE_MIN + buf_size);

    (void)mb_port_event_post(inst->port_obj, EVENT(EV_FRAME_TRANSMIT | EV_TRANS_START));
    return mb_port_event_wait_req_finish(inst->port_obj);
}

#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED && MB_FUNC_OTHER_REP_SLAVEID_BUF

mb_err_enum_t mbm_rq_report_slave_id(mb_base_t *inst, uint8_t slave_addr, uint32_t timeout)
{
    uint8_t *mb_frame_ptr = NULL;
    mb_err_enum_t err = MB_ENOERR;
    if (!inst || !inst->port_obj || (slave_addr > MB_ADDRESS_MAX)) {
        err = MB_EINVAL;
    } else if (!mb_port_event_res_take(inst->port_obj, timeout)) {
        err = MB_EBUSY;
    } else {
        inst->get_send_buf(inst, &mb_frame_ptr);
        inst->set_dest_addr(inst, slave_addr);
        mb_frame_ptr[MB_PDU_FUNC_OFF] = MB_FUNC_OTHER_REPORT_SLAVEID;
        inst->set_send_len(inst, MB_CMD_SL_ID_LEN);
        (void)mb_port_event_post(inst->port_obj, EVENT(EV_FRAME_TRANSMIT | EV_TRANS_START));
        err = mb_port_event_wait_req_finish(inst->port_obj);
    }
    return err;
}

mb_exception_t mbm_fn_report_slave_id(mb_base_t *inst, uint8_t *pframe, uint16_t *plen)
{
    uint8_t byte_count = 0;
    mb_exception_t status = MB_EX_NONE;
    mb_err_enum_t err;

    if (!inst || !plen || !pframe) {
        status = MB_EX_SLAVE_DEVICE_FAILURE;
    } else if (*plen <= MB_BUFFER_SIZE - 2) {
        byte_count = pframe[MB_PDU_BYTECNT_OFF];
        // Transfer data from command buffer.
        err = mbc_reg_common_cb(inst, &pframe[MB_PDU_FUNC_DATA_OFF], 0, byte_count);
        // If an err occured convert it into a Modbus exception.
        if (err != MB_ENOERR) {
            status = mb_error_to_exception(err);
        }
    } else {
        // Can't be a valid request because the length is incorrect.
        status = MB_EX_ILLEGAL_DATA_VALUE;
    }
    return status;
}

mb_exception_t mbs_fn_report_slave_id(mb_base_t *inst, uint8_t *pframe, uint16_t *plen_buf)
{
    mb_exception_t status = MB_EX_NONE;
    if (!inst || !pframe || !plen_buf || !inst->pobj_id || !inst->obj_id_len) {
        status = MB_EX_SLAVE_DEVICE_FAILURE;
    } else if ((inst->obj_id_len <= MB_BUFFER_SIZE - 2)
                && (*plen_buf == MB_CMD_SL_ID_LEN)) {
        CRITICAL_SECTION(inst->lock) {
            pframe[MB_PDU_FUNC_OFF] = MB_FUNC_OTHER_REPORT_SLAVEID; // rewrite the FC
            *plen_buf = (uint16_t)(inst->obj_id_len);
            pframe[MB_PDU_BYTECNT_OFF] = *plen_buf;
            memcpy(&pframe[MB_PDU_FUNC_DATA_OFF], inst->pobj_id, (size_t)inst->obj_id_len);
            *plen_buf += 2; // count function code + length in frame length
        }
    } else {
        status = MB_EX_ILLEGAL_DATA_VALUE;
    }
    return status;
}

mb_err_enum_t mbs_set_slave_id(mb_base_t *inst, uint8_t slave_id, bool is_running, uint8_t const *pdata, uint8_t data_len)
{
    mb_err_enum_t status = MB_ENOERR;
    // the first byte and second byte in the buffer is reserved for
    // the parameter slave_id and the running flag. The rest of
    // the buffer is available for additional data.
    if (inst && inst->lock && (data_len + 2 <= MB_FUNC_OTHER_REP_SLAVEID_BUF)) {
        uint8_t chunk_num = ((data_len + 2) / MB_SLAVE_ID_CHUNK_SIZE) + 1;
        if (!inst->pobj_id || inst->obj_id_chunks != chunk_num) {
            CRITICAL_SECTION(inst->lock) {
                inst->pobj_id = realloc(inst->pobj_id, (chunk_num * MB_SLAVE_ID_CHUNK_SIZE));
            }
        }
        if (!inst->pobj_id) {
            return MB_ENORES;
        }
        CRITICAL_SECTION(inst->lock) {
            inst->obj_id_len = 0;
            inst->pobj_id[inst->obj_id_len++] = slave_id;
            inst->pobj_id[inst->obj_id_len++] = (uint8_t)(is_running ? 0xFF : 0x00);
            if (data_len > 0) {
                memcpy(&inst->pobj_id[inst->obj_id_len], pdata, (size_t)data_len);
                inst->obj_id_len += data_len;
                inst->obj_id_chunks = chunk_num;
            }
        }
    } else {
        status = MB_ENORES;
    }
    return status;
}

mb_err_enum_t mbs_get_slave_id(mb_base_t *inst, uint8_t *pdata, uint8_t *pdata_len)
{
    mb_err_enum_t status = MB_ENOERR;
    if (inst && inst->lock && pdata_len) {
        if (!inst->pobj_id) {
            return MB_ENOREG;
        }
        if (pdata && (*pdata_len >= inst->obj_id_len)) {
            CRITICAL_SECTION(inst->lock) {
                memcpy(pdata, &inst->pobj_id[0],(size_t)inst->obj_id_len);
            }
        } else {
            status = MB_ENORES;
        }
        *pdata_len = inst->obj_id_len;
    } else {
        status = MB_EINVAL;
    }
    return status;
}

#endif
