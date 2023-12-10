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

mb_err_enum_t mb_stub_create(mb_serial_opts_t *ser_opts, void **in_out_obj);
