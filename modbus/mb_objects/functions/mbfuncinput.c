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
 * File: $Id: mbfuncinput.c, v 1.10 2007/09/12 10:15:56 wolti Exp $
 */
#include <mb_common.h>
#include <mb_proto.h>
#include "mb_slave.h"
/* ----------------------- Defines ------------------------------------------*/
#define MB_PDU_FUNC_READ_ADDR_OFF           (MB_PDU_DATA_OFF)
#define MB_PDU_FUNC_READ_REGCNT_OFF         (MB_PDU_DATA_OFF + 2)
#define MB_PDU_FUNC_READ_SIZE               (4)
#define MB_PDU_FUNC_READ_REGCNT_MAX         (0x007D)

#define MB_PDU_FUNC_READ_RSP_BYTECNT_OFF    (MB_PDU_DATA_OFF)

/* ----------------------- Static functions ---------------------------------*/
mb_exception_t mb_error_to_exception(mb_err_enum_t error_code);

/* ----------------------- Start implementation -----------------------------*/
#if MB_FUNC_READ_INPUT_ENABLED > 0
mb_exception_t mbs_fn_read_input_reg(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf)
{
    uint16_t reg_addr;
    uint16_t reg_cnt;
    uint8_t *frame_cur;

    mb_exception_t status = MB_EX_NONE;
    mb_err_enum_t reg_status = MB_EILLFUNC;

    if (*len_buf == (MB_PDU_FUNC_READ_SIZE + MB_PDU_SIZE_MIN)) {
        reg_addr = (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_ADDR_OFF] << 8);
        reg_addr |= (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_ADDR_OFF + 1]);
        reg_addr++;

        reg_cnt = (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_REGCNT_OFF] << 8);
        reg_cnt |= (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_REGCNT_OFF + 1]);

        /* Check if the number of registers to read is valid. If not
         * return Modbus illegal data value exception.
         */
        if ((reg_cnt >= 1)
            && (reg_cnt <= MB_PDU_FUNC_READ_REGCNT_MAX)) {
            /* Set the current PDU data pointer to the beginning. */
            frame_cur = &frame_ptr[MB_PDU_FUNC_OFF];
            *len_buf = MB_PDU_FUNC_OFF;

            /* First byte contains the function code. */
            *frame_cur++ = MB_FUNC_READ_INPUT_REGISTER;
            *len_buf += 1;

            /* Second byte in the response contain the number of bytes. */
            *frame_cur++ = (uint8_t)(reg_cnt * 2);
            *len_buf += 1;
            if (inst->rw_cbs.reg_input_cb) {
                reg_status = inst->rw_cbs.reg_input_cb(inst, frame_cur, reg_addr, reg_cnt);
            }

            /* If an error occured convert it into a Modbus exception. */
            if (reg_status != MB_ENOERR) {
                status = mb_error_to_exception(reg_status);
            } else {
                *len_buf += reg_cnt * 2;
            }
        } else {
            status = MB_EX_ILLEGAL_DATA_VALUE;
        }
    } else {
        /* Can't be a valid read input register request because the length
         * is incorrect. */
        status = MB_EX_ILLEGAL_DATA_VALUE;
    }
    return status;
}
#endif
