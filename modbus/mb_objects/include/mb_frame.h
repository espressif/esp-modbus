/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "mb_config.h"

#ifdef __cplusplus
extern "C" {
#endif
/*!
 * Constants which defines the format of a modbus frame. The example is
 * shown for a Modbus RTU/ASCII frame. Note that the Modbus PDU is not
 * dependent on the underlying transport.
 *
 * <code>
 * <------------------------ MODBUS SERIAL LINE PDU (1) ------------------->
 *              <----------- MODBUS PDU (1') ---------------->
 *  +-----------+---------------+----------------------------+-------------+
 *  | Address   | Function Code | Data                       | CRC/LRC     |
 *  +-----------+---------------+----------------------------+-------------+
 *  |           |               |                                   |
 * (2)        (3/2')           (3')                                (4)
 *
 * (1)  ... MB_SER_PDU_SIZE_MAX = 256
 * (2)  ... MB_SER_PDU_ADDR_OFF = 0
 * (3)  ... MB_SER_PDU_PDU_OFF  = 1
 * (4)  ... MB_SER_PDU_SIZE_CRC = 2
 *
 * (1') ... MB_PDU_SIZE_MAX     = 253
 * (2') ... MB_PDU_FUNC_OFF     = 0
 * (3') ... MB_PDU_DATA_OFF     = 1
 * </code>
 */

/* ----------------------- Defines ------------------------------------------*/
#define MB_PDU_SIZE_MAX             253 /*!< Maximum size of a PDU. */
#define MB_PDU_SIZE_MIN             1   /*!< Function Code */
#define MB_PDU_FUNC_OFF             0   /*!< Offset of function code in PDU. */
#define MB_PDU_DATA_OFF             1   /*!< Offset for response data in PDU. */

#define MB_SER_PDU_SIZE_MAX         MB_BUFFER_SIZE /*!< Maximum size of a Modbus frame. */
#define MB_SER_PDU_SIZE_LRC         1   /*!< Size of LRC field in PDU. */
#define MB_SER_PDU_ADDR_OFF         0   /*!< Offset of slave address in Ser-PDU. */
#define MB_SER_PDU_PDU_OFF          1   /*!< Offset of Modbus-PDU in Ser-PDU. */
#define MB_SER_PDU_SIZE_CRC         2   /*!< Size of CRC field in PDU. */

#define MB_TCP_TID                  0
#define MB_TCP_PID                  2
#define MB_TCP_LEN                  4
#define MB_TCP_UID                  6
#define MB_TCP_FUNC                 7

#if MB_MASTER_TCP_ENABLED
#define MB_SEND_BUF_PDU_OFF     MB_TCP_FUNC
#else
#define MB_SEND_BUF_PDU_OFF     MB_SER_PDU_PDU_OFF
#endif

#define MB_TCP_BUFF_MAX_SIZE    MB_TCP_FUNC + MB_PDU_SIZE_MAX

#define MB_TCP_PSEUDO_ADDRESS   (255)
#define MB_TCP_PROTOCOL_ID      (0)   /* 0 = Modbus Protocol */

#ifdef __cplusplus
}
#endif
