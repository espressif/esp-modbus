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
 * File: $Id: mbfunccoils.c, v 1.8 2007/02/18 23:47:16 wolti Exp $
 */
#include <mb_common.h>
#include <mb_proto.h>
#include "mb_slave.h"
/* ----------------------- Defines ------------------------------------------*/
#define MB_PDU_FUNC_READ_ADDR_OFF           (MB_PDU_DATA_OFF)
#define MB_PDU_FUNC_READ_COILCNT_OFF        (MB_PDU_DATA_OFF + 2)
#define MB_PDU_FUNC_READ_SIZE               (4)
#define MB_PDU_FUNC_READ_COILCNT_MAX        (0x07D0)

#define MB_PDU_FUNC_WRITE_ADDR_OFF          (MB_PDU_DATA_OFF)
#define MB_PDU_FUNC_WRITE_VALUE_OFF         (MB_PDU_DATA_OFF + 2)
#define MB_PDU_FUNC_WRITE_SIZE              (4)

#define MB_PDU_FUNC_WRITE_MUL_ADDR_OFF      (MB_PDU_DATA_OFF)
#define MB_PDU_FUNC_WRITE_MUL_COILCNT_OFF   (MB_PDU_DATA_OFF + 2)
#define MB_PDU_FUNC_WRITE_MUL_BYTECNT_OFF   (MB_PDU_DATA_OFF + 4)
#define MB_PDU_FUNC_WRITE_MUL_VALUES_OFF    (MB_PDU_DATA_OFF + 5)
#define MB_PDU_FUNC_WRITE_MUL_SIZE_MIN      (5)
#define MB_PDU_FUNC_WRITE_MUL_COILCNT_MAX   (0x07B0)

/* ----------------------- Static functions ---------------------------------*/
mb_exception_t  mb_error_to_exception(mb_err_enum_t error_code);

/* ----------------------- Start implementation -----------------------------*/

#if MB_FUNC_READ_COILS_ENABLED > 0

mb_exception_t mbs_fn_read_coils(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf)
{
    uint16_t reg_addr;
    uint16_t coil_cnt;
    uint8_t byte_num;
    uint8_t *frame_cur;

    mb_exception_t status = MB_EX_NONE;
    mb_err_enum_t reg_status = MB_EILLFUNC;

    if (*len_buf == (MB_PDU_FUNC_READ_SIZE + MB_PDU_SIZE_MIN)) {
        reg_addr = (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_ADDR_OFF] << 8);
        reg_addr |= (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_ADDR_OFF + 1]);
        reg_addr++;

        coil_cnt = (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_COILCNT_OFF] << 8);
        coil_cnt |= (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_COILCNT_OFF + 1]);

        /* Check if the number of registers to read is valid. If not
         * return Modbus illegal data value exception.
         */
        if ((coil_cnt >= 1) &&
            (coil_cnt < MB_PDU_FUNC_READ_COILCNT_MAX)) {
            /* Set the current PDU data pointer to the beginning. */
            frame_cur = &frame_ptr[MB_PDU_FUNC_OFF];
            *len_buf = MB_PDU_FUNC_OFF;

            /* First byte contains the function code. */
            *frame_cur++ = MB_FUNC_READ_COILS;
            *len_buf += 1;

            /* Test if the quantity of coils is a multiple of 8. If not last
             * byte is only partially field with unused coils set to zero. */
            if ((coil_cnt & 0x0007) != 0) {
                byte_num = (uint8_t)(coil_cnt / 8 + 1);
            } else {
                byte_num = (uint8_t)(coil_cnt / 8);
            }
            
            *frame_cur++ = byte_num;
            *len_buf += 1;

            if (inst->rw_cbs.reg_coils_cb) {
                reg_status = inst->rw_cbs.reg_coils_cb(inst, frame_cur, reg_addr, coil_cnt, MB_REG_READ);
            }

            /* If an error occured convert it into a Modbus exception. */
            if (reg_status != MB_ENOERR) {
                status = mb_error_to_exception(reg_status);
            } else {
                /* The response contains the function code, the starting address
                 * and the quantity of registers. We reuse the old values in the
                 * buffer because they are still valid. */
                *len_buf += byte_num;;
            }
        } else {
            status = MB_EX_ILLEGAL_DATA_VALUE;
        }
    } else {
        /* Can't be a valid read coil register request because the length
         * is incorrect. */
        status = MB_EX_ILLEGAL_DATA_VALUE;
    }
    return status;
}

#if MB_FUNC_WRITE_COIL_ENABLED > 0
mb_exception_t mbs_fn_write_coil(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf)
{
    uint16_t          reg_addr;
    uint8_t           buf[2];

    mb_exception_t    status = MB_EX_NONE;
    mb_err_enum_t reg_status = MB_EILLFUNC;

    if (*len_buf == (MB_PDU_FUNC_WRITE_SIZE + MB_PDU_SIZE_MIN)) {
        reg_addr = (uint16_t)(frame_ptr[MB_PDU_FUNC_WRITE_ADDR_OFF] << 8);
        reg_addr |= (uint16_t)(frame_ptr[MB_PDU_FUNC_WRITE_ADDR_OFF + 1]);
        reg_addr++;

        if ((frame_ptr[MB_PDU_FUNC_WRITE_VALUE_OFF + 1] == 0x00) &&
            ((frame_ptr[MB_PDU_FUNC_WRITE_VALUE_OFF] == 0xFF) ||
              (frame_ptr[MB_PDU_FUNC_WRITE_VALUE_OFF] == 0x00))) {
            buf[1] = 0;
            if (frame_ptr[MB_PDU_FUNC_WRITE_VALUE_OFF] == 0xFF) {
                buf[0] = 1;
            } else {
                buf[0] = 0;
            }

            if (inst->rw_cbs.reg_coils_cb) {
                reg_status = inst->rw_cbs.reg_coils_cb(inst, &buf[0], reg_addr, 1, MB_REG_WRITE);
            }

            /* If an error occured convert it into a Modbus exception. */
            if (reg_status != MB_ENOERR) {
                status = mb_error_to_exception(reg_status);
            }
        } else {
            status = MB_EX_ILLEGAL_DATA_VALUE;
        }
    } else {
        /* Can't be a valid write coil register request because the length
         * is incorrect. */
        status = MB_EX_ILLEGAL_DATA_VALUE;
    }
    return status;
}

#endif

#if MB_FUNC_WRITE_MULTIPLE_COILS_ENABLED > 0
mb_exception_t mbs_fn_write_multi_coils(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf)
{
    uint16_t          reg_addr;
    uint16_t          coil_cnt;
    uint8_t           byte_cnt;
    uint8_t           byte_cnt_verify;

    mb_exception_t    status = MB_EX_NONE;
    mb_err_enum_t reg_status = MB_EILLFUNC;

    if (*len_buf > (MB_PDU_FUNC_WRITE_SIZE + MB_PDU_SIZE_MIN)) {
        reg_addr = (uint16_t)(frame_ptr[MB_PDU_FUNC_WRITE_MUL_ADDR_OFF] << 8);
        reg_addr |= (uint16_t)(frame_ptr[MB_PDU_FUNC_WRITE_MUL_ADDR_OFF + 1]);
        reg_addr++;

        coil_cnt = (uint16_t)(frame_ptr[MB_PDU_FUNC_WRITE_MUL_COILCNT_OFF] << 8);
        coil_cnt |= (uint16_t)(frame_ptr[MB_PDU_FUNC_WRITE_MUL_COILCNT_OFF + 1]);

        byte_cnt = frame_ptr[MB_PDU_FUNC_WRITE_MUL_BYTECNT_OFF];

        /* Compute the number of expected bytes in the request. */
        if ((coil_cnt & 0x0007) != 0) {
            byte_cnt_verify = (uint8_t)(coil_cnt / 8 + 1);
        } else {
            byte_cnt_verify = (uint8_t)(coil_cnt / 8);
        }

        if ((coil_cnt >= 1) &&
            (coil_cnt <= MB_PDU_FUNC_WRITE_MUL_COILCNT_MAX) &&
            (byte_cnt_verify == byte_cnt)) {
            if (inst->rw_cbs.reg_coils_cb) {
                reg_status = inst->rw_cbs.reg_coils_cb(inst, &frame_ptr[MB_PDU_FUNC_WRITE_MUL_VALUES_OFF], reg_addr, coil_cnt, MB_REG_WRITE);
            }

            /* If an error occured convert it into a Modbus exception. */
            if (reg_status != MB_ENOERR) {
                status = mb_error_to_exception(reg_status);
            } else {
                /* The response contains the function code, the starting address
                 * and the quantity of registers. We reuse the old values in the
                 * buffer because they are still valid. */
                *len_buf = MB_PDU_FUNC_WRITE_MUL_BYTECNT_OFF;
            }
        } else {
            status = MB_EX_ILLEGAL_DATA_VALUE;
        }
    } else {
        /* Can't be a valid write coil register request because the length
         * is incorrect. */
        status = MB_EX_ILLEGAL_DATA_VALUE;
    }
    return status;
}
#endif
#endif
