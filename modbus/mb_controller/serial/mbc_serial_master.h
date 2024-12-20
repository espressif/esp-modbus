/*
 * SPDX-FileCopyrightText: 2016-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//  mbc_serial_master.h Modbus controller serial master implementation header file

#pragma once

#include <stdint.h>                 // for standard int types definition
#include <stddef.h>                 // for NULL and std defines
#include "soc/soc.h"                // for BITN definitions
#include "esp_err.h"                // for esp_err_t
#include "esp_modbus_common.h"      // for common defines
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

/**
 * @brief Initialize Modbus controller and stack
 *
 * @param[out] ctx - pointer to pointer of interface structure
 * @param[in] config - pointer to configuration structure
 * @return
 *     - ESP_OK   Success
 *     - ESP_ERR_NO_MEM Parameter error
 */
esp_err_t mbc_serial_master_create(mb_communication_info_t *config, void **ctx);

#endif

#ifdef __cplusplus
}
#endif
