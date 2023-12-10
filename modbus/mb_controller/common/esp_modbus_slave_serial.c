/*
 * SPDX-FileCopyrightText: 2016-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"                    // for esp_err_t
#include "sdkconfig.h"                  // for KConfig defines
#include "mbc_slave.h"                  // for slave interface define
#include "esp_modbus_slave.h"           // for public slave defines
#include "mbc_serial_slave.h"           // for public interface defines

#include "mb_port_types.h"

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

/**
 * Initialization of Modbus Serial slave controller
 */
esp_err_t mbc_slave_create_serial(mb_communication_info_t *config, void **handler)
{
    void *ctx = NULL;
    esp_err_t error = ESP_ERR_NOT_SUPPORTED;
    switch(config->mode)
{
        case MB_RTU:
        case MB_ASCII:
            // Call constructor function of actual port implementation
            error = mbc_serial_slave_create(config, &ctx);
            break;
        default:
            return ESP_ERR_NOT_SUPPORTED;
    }
    if ((ctx) && (error == ESP_OK)) {
        mbc_slave_init_iface(ctx);
        *handler = ctx;
    }
    return error;
}

#endif