/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stddef.h>
#include "sdkconfig.h"
#include "mb_common.h"
#include "mb_types.h"
#include "transport_common.h"
#include "port_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

/* ----------------------- Defines ------------------------------------------*/

// Common definitions for TCP port
#define MB_TCP_BUF_SIZE         (256 + 7) // Must hold a complete Modbus TCP frame.

#define MB_TCP_TIMEOUT_MS       (1000)

typedef enum
{
    MB_TCP_STATE_INIT,              /*!< Receiver is in initial state. */
    MB_TCP_STATE_ACTIVE,            /*!< Receiver is in active state. */
    MB_TCP_STATE_ERROR              /*!< If the frame is invalid. */
} mb_tcp_state_enum_t;

typedef struct mb_trans_base_t mb_trans_base_t;

mb_err_enum_t mbm_tcp_transp_create(mb_tcp_opts_t *tcp_opts, void **in_out_inst);
mb_err_enum_t mbs_tcp_transp_create(mb_tcp_opts_t *tcp_opts, void **in_out_inst);
bool mbs_tcp_transp_delete(mb_trans_base_t *inst);
bool mbm_tcp_transp_delete(mb_trans_base_t *inst);

#endif

#ifdef __cplusplus
}
#endif