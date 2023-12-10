/*
 * SPDX-FileCopyrightText: 2016-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Stack callback functions prototypes

#pragma once

#include "mb_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef mb_err_enum_t (*reg_input_cb)(mb_base_t*, uint8_t *, uint16_t, uint16_t);
typedef mb_err_enum_t (*reg_holding_cb)(mb_base_t*, uint8_t *, uint16_t, uint16_t, mb_reg_mode_enum_t);
typedef mb_err_enum_t (*reg_coils_cb)(mb_base_t*, uint8_t *, uint16_t, uint16_t, mb_reg_mode_enum_t);
typedef mb_err_enum_t (*reg_discrete_cb)(mb_base_t*, uint8_t *, uint16_t, uint16_t);

#ifdef __cplusplus
}
#endif
