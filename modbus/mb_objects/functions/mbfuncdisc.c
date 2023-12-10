 /*
  * FreeRTOS Modbus Libary: A Modbus serial implementation for FreeRTOS
  * Copyright (c) 2016, 2017 Nucleron R&D LLC <main@nucleron.ru>
  * Copyright (C) 2006 Christian Walter <wolti@sil.at>
  *
  * This library is free software; you can redistribute it and/or
  * modify it under the terms of the GNU Lesser General Public
  * License as published by the Free Software Foundation; either
  * version 2.1 of the License, or (at your option) any later version.
  *
  * This library is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this library; if not, write to the Free Software
  * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
  */
#include <mb_common.h>
#include <mb_proto.h>
#include "mb_slave.h"
/* ----------------------- Defines ------------------------------------------*/
#define MB_PDU_FUNC_READ_ADDR_OFF           (MB_PDU_DATA_OFF)
#define MB_PDU_FUNC_READ_DISCCNT_OFF        (MB_PDU_DATA_OFF + 2)
#define MB_PDU_FUNC_READ_SIZE               (4)
#define MB_PDU_FUNC_READ_DISCCNT_MAX        (0x07D0)

/* ----------------------- Static functions ---------------------------------*/
mb_exception_t mb_error_to_exception(mb_err_enum_t error_code);

/* ----------------------- Start implementation -----------------------------*/

#if MB_FUNC_READ_COILS_ENABLED > 0

mb_exception_t
mbs_fn_read_discrete_inp(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf)
{
    uint16_t reg_addr;
    uint16_t discrete_cnt;
    uint8_t byte_num;
    uint8_t *frame_cur;

    mb_exception_t status = MB_EX_NONE;
    mb_err_enum_t reg_status = MB_EILLFUNC;

    (void)inst;

    if (*len_buf == (MB_PDU_FUNC_READ_SIZE + MB_PDU_SIZE_MIN)) {
        reg_addr = (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_ADDR_OFF] << 8);
        reg_addr |= (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_ADDR_OFF + 1]);
        reg_addr++;

        discrete_cnt = (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_DISCCNT_OFF] << 8);
        discrete_cnt |= (uint16_t)(frame_ptr[MB_PDU_FUNC_READ_DISCCNT_OFF + 1]);

        /* Check if the number of registers to read is valid. If not
         * return Modbus illegal data value exception.
         */
        if ((discrete_cnt >= 1) &&
            (discrete_cnt < MB_PDU_FUNC_READ_DISCCNT_MAX)) {
            /* Set the current PDU data pointer to the beginning. */
            frame_cur = &frame_ptr[MB_PDU_FUNC_OFF];
            *len_buf = MB_PDU_FUNC_OFF;

            /* First byte contains the function code. */
            *frame_cur++ = MB_FUNC_READ_DISCRETE_INPUTS;
            *len_buf += 1;

            /* Test if the quantity of coils is a multiple of 8. If not last
             * byte is only partially field with unused coils set to zero. */
            if ((discrete_cnt & 0x0007) != 0) {
                byte_num = (uint8_t) (discrete_cnt / 8 + 1);
            } else {
                byte_num = (uint8_t) (discrete_cnt / 8);
            }
            *frame_cur++ = byte_num;
            *len_buf += 1;

            /* Call r/w function if defined*/
            if (inst->rw_cbs.reg_discrete_cb) {
                reg_status = inst->rw_cbs.reg_discrete_cb(inst, frame_cur, reg_addr, discrete_cnt);
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

#endif
