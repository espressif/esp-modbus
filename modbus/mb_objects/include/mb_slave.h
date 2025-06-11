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
mb_exception_t mbs_fn_report_slave_id(mb_base_t *inst, uint8_t *frame, uint16_t *len_buf);
#endif

// The helper function to register custom function handler for slave
mb_err_enum_t mbs_set_handler(mb_base_t *inst, uint8_t func_code, mb_fn_handler_fp handler);

// The helper function to get custom function handler for slave
mb_err_enum_t mbs_get_handler(mb_base_t *inst, uint8_t func_code, mb_fn_handler_fp *handler);

// The helper function to delete custom function handler for slave
mb_err_enum_t mbs_delete_handler(mb_base_t *inst, uint8_t func_code);

// The helper function to get count of handlers for slave
mb_err_enum_t mbs_get_handler_count(mb_base_t *inst, uint16_t *count);

#ifdef __cplusplus
}
#endif