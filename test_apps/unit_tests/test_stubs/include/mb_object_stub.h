/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <sdkconfig.h>
#include "esp_log.h"
#include "mb_common.h"
#include "mb_port_types.h"

#if (CONFIG_FMB_COMM_MODE_TCP_EN)
mb_err_enum_t mb_stub_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);
#endif

#if (MB_MASTER_ASCII_ENABLED || MB_MASTER_RTU_ENABLED) 
mb_err_enum_t mb_stub_serial_create(mb_serial_opts_t *ser_opts, void **in_out_obj);
#endif
