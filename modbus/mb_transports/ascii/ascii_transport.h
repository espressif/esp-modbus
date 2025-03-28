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
#include "transport_common.h"
#include "port_common.h"
#include "ascii_lrc.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (CONFIG_FMB_COMM_MODE_ASCII_EN)

/* ----------------------- Defines ------------------------------------------*/
#define MB_ASCII_SER_PDU_SIZE_MIN   3                             /*!< Minimum size of a Modbus ASCII frame. */
#define MB_ASCII_SER_PDU_SIZE_MAX   MB_SER_PDU_SIZE_MAX * 2       /*!< Maximum size of a Modbus ASCII frame. */
#define MB_ASCII_SER_PDU_SIZE_LRC   1                             /*!< Size of LRC field in PDU. */
#define MB_ASCII_SER_PDU_ADDR_OFF   0                             /*!< Offset of slave address in Ser-PDU. */
#define MB_ASCII_SER_PDU_PDU_OFF    1                             /*!< Offset of Modbus-PDU in Ser-PDU. */

typedef struct port_serial_opts_s mb_serial_opts_t;
typedef struct mb_trans_base_t mb_trans_base_t;

mb_err_enum_t mbm_ascii_transp_create(mb_serial_opts_t *ser_opts, void **in_out_inst);
mb_err_enum_t mbs_ascii_transp_create(mb_serial_opts_t *ser_opts, void **in_out_inst);
bool mbs_ascii_transp_delete(mb_trans_base_t *inst);
bool mbm_ascii_transp_delete(mb_trans_base_t *inst);

#endif

#ifdef __cplusplus
}
#endif