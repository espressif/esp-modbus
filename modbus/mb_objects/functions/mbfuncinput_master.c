/*
 * FreeModbus Libary: A portable Modbus implementation for Modbus ASCII/RTU.
 * Copyright (c) 2016, 2017 Nucleron R&D LLC <main@nucleron.ru>
 * Copyright (C) 2013 Armink <armink.ztl@gmail.com>
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
 * File: $Id: mbfuncinput_m.c, v 1.60 2013/10/12 14:23:40 Armink Add Master Functions  Exp $
 */
#include "mb_common.h"
#include "mb_proto.h"
#include "transport_common.h"
#include "mb_master.h"
/* ----------------------- Defines ------------------------------------------*/
#define MB_PDU_REQ_READ_ADDR_OFF            (MB_PDU_DATA_OFF + 0)
#define MB_PDU_REQ_READ_REGCNT_OFF          (MB_PDU_DATA_OFF + 2)
#define MB_PDU_REQ_READ_SIZE                (4)
#define MB_PDU_FUNC_READ_BYTECNT_OFF        (MB_PDU_DATA_OFF + 0)
#define MB_PDU_FUNC_READ_VALUES_OFF         (MB_PDU_DATA_OFF + 1)
#define MB_PDU_FUNC_READ_SIZE_MIN           (1)

#define MB_PDU_FUNC_READ_RSP_BYTECNT_OFF    (MB_PDU_DATA_OFF)

/* ----------------------- Static functions ---------------------------------*/
mb_exception_t mb_error_to_exception(mb_err_enum_t error_code);

/* ----------------------- Start implementation -----------------------------*/
#if MB_MASTER_RTU_ENABLED || MB_MASTER_ASCII_ENABLED || MB_MASTER_TCP_ENABLED

#if MB_FUNC_WRITE_HOLDING_ENABLED

/**
 * This function will request read input register.
 *
 * @param snd_addr salve address
 * @param reg_addr register start address
 * @param reg_num register total number
 * @param timeout timeout (-1 will waiting forever)
 *
 * @return error code
 */
mb_err_enum_t mbm_rq_read_inp_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_num, uint32_t tout)
{
    uint8_t *mb_frame_ptr;

    if (!inst || (snd_addr > MB_ADDRESS_MAX)) {
        return MB_EINVAL;
    }
    if (!mb_port_event_res_take(inst->port_obj, tout)) {
        return MB_EBUSY;
    }
    inst->get_send_buf(inst, &mb_frame_ptr);
    inst->set_dest_addr(inst, snd_addr);

    mb_frame_ptr[MB_PDU_FUNC_OFF]                = MB_FUNC_READ_INPUT_REGISTER;

    mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF]       = reg_addr >> 8;
    mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF + 1]   = reg_addr;
    
    mb_frame_ptr[MB_PDU_REQ_READ_REGCNT_OFF]     = reg_num >> 8;
    mb_frame_ptr[MB_PDU_REQ_READ_REGCNT_OFF + 1] = reg_num;

    inst->set_send_len(inst, MB_PDU_SIZE_MIN + MB_PDU_REQ_READ_SIZE);

    (void)mb_port_event_post(inst->port_obj, EVENT(EV_FRAME_TRANSMIT | EV_TRANS_START) );
    return mb_port_event_wait_req_finish(inst->port_obj);
}

mb_exception_t mbm_fn_read_inp_reg(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf)
{
    mb_exception_t status = MB_EX_NONE;
    mb_err_enum_t reg_status = MB_EILLFUNC;
    uint16_t reg_cnt;
    uint16_t reg_address;
    uint8_t *mb_frame_ptr;    

    /* If this request is broadcast, and it's read mode. This request don't need execute. */
    if (inst->transp_obj->frm_is_bcast(inst->transp_obj)) {
        status = MB_EX_NONE;
    } else if (*len_buf >= MB_PDU_SIZE_MIN + MB_PDU_FUNC_READ_SIZE_MIN) {
        inst->get_send_buf(inst, &mb_frame_ptr);

        reg_address = (uint16_t)( mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF] << 8 );
        reg_address |= (uint16_t)( mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF + 1] );
        reg_address++;

        reg_cnt = (uint16_t)( mb_frame_ptr[MB_PDU_REQ_READ_REGCNT_OFF] << 8 );
        reg_cnt |= (uint16_t)( mb_frame_ptr[MB_PDU_REQ_READ_REGCNT_OFF + 1] );

        /* Check if the number of registers to read is valid. If not
         * return Modbus illegal data value exception.
         */
        if ((reg_cnt >= 1) && (2 * reg_cnt == frame_ptr[MB_PDU_FUNC_READ_BYTECNT_OFF])) {
            /* Make callback to fill the buffer. */
            if (inst->rw_cbs.reg_input_cb) {
                reg_status = inst->rw_cbs.reg_input_cb(inst, &frame_ptr[MB_PDU_FUNC_READ_VALUES_OFF], reg_address, reg_cnt);
            }
            /* If an error occured convert it into a Modbus exception. */
            if (reg_status != MB_ENOERR) {
                status = mb_error_to_exception(reg_status);
            }
        } else {
            status = MB_EX_ILLEGAL_DATA_VALUE;
        }
    } else {
        /* Can't be a valid request because the length is incorrect. */
        status = MB_EX_ILLEGAL_DATA_VALUE;
    }
    return status;
}

#endif
#endif // #if MB_MASTER_RTU_ENABLED || MB_MASTER_ASCII_ENABLED || MB_MASTER_TCP_ENABLED
