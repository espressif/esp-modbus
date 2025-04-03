/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stddef.h>
#include "mb_config.h"
#include "mb_common.h"
#include "mb_types.h"
#include "mb_frame.h"
#include "mb_proto.h"
#include "mbcrc.h"
#include "transport_common.h"
#include "port_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (CONFIG_FMB_COMM_MODE_RTU_EN)

/* If baudrate > 19200 then we should use the fixed timer values
 * t35 = 1750us. Otherwise t35 must be 3.5 times the character time.
 * The timer reload value for a character is given by:
 *
 * ChTimeValue = Ticks_per_1s / (Baudrate / 11)
 *             = 11 * Ticks_per_1s / Baudrate
 *             = 220000 / Baudrate
 * The reload for t3.5 is 1.5 times this value and similary
 * for t3.5.
 */
#define MB_RTU_GET_T35_VAL(baudrate) (__extension__(            \
{                                                               \
    uint16_t tmr_35_50us = (baudrate > 19200) ?                 \
                    35 : ((7UL * 220000UL) / (2UL * baudrate)); \
    tmr_35_50us;                                                \
}                                                               \
))

/* ----------------------- Defines ------------------------------------------*/
#define MB_RTU_SER_PDU_SIZE_MIN     4                       /*!< Minimum size of a Modbus RTU frame. */
#define MB_RTU_SER_PDU_SIZE_MAX     MB_BUFFER_SIZE          /*!< Maximum size of a Modbus RTU frame. */
#define MB_RTU_SER_PDU_SIZE_CRC     2                       /*!< Size of CRC field in PDU. */
#define MB_RTU_SER_PDU_ADDR_OFF     0                       /*!< Offset of slave address in Ser-PDU. */
#define MB_RTU_SER_PDU_PDU_OFF      1                       /*!< Offset of Modbus-PDU in Ser-PDU. */

typedef enum
{
    MB_RTU_STATE_INIT,              /*!< Receiver is in initial state. */
    MB_RTU_STATE_ACTIVE,            /*!< Receiver is in active state. */
    MB_RTU_STATE_ERROR              /*!< If the frame is invalid. */
} mb_rtu_state_enum_t;

typedef struct port_serial_opts_s mb_serial_opts_t;
typedef struct mb_trans_base_t mb_trans_base_t;

mb_err_enum_t mbm_rtu_transp_create(mb_serial_opts_t *ser_opts, void **in_out_inst);
mb_err_enum_t mbs_rtu_transp_create(mb_serial_opts_t *ser_opts, void **in_out_inst);
bool mbm_rtu_transp_delete(mb_trans_base_t *inst);
bool mbs_rtu_transp_delete(mb_trans_base_t *inst);

#endif

#ifdef __cplusplus
}
#endif