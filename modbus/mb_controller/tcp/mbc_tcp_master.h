/*
 * SPDX-FileCopyrightText: 2016-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//  mbc_tcp_master.h Modbus controller TCP master implementation header file

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>                 // for standard int types definition
#include <stddef.h>                 // for NULL and std defines
#include "esp_modbus_common.h"      // for common defines

/* ----------------------- Defines ------------------------------------------*/

/**
 * @brief Create Modbus Master controller and stack for TCP port
 *
 * @param[out] ctx - pointer to pointer of interface structure
 * @param[in] config - pointer to configuration structure
 * @return
 *     - ESP_OK   Success
 *     - ESP_ERR_NO_MEM Parameter error
 */
esp_err_t mbc_tcp_master_create(mb_communication_info_t *config, void **ctx);

#ifdef __cplusplus
}
#endif
