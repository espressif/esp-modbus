/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "mb_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
mb_exception_t mbs_fn_report_slave_id(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *plen_buf);
#endif

#ifdef __cplusplus
}
#endif