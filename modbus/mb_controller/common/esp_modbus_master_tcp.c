/*
 * SPDX-FileCopyrightText: 2016-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"                // for esp_err_t
#include "esp_modbus_master.h"      // for public interface defines
#include "mbc_tcp_master.h"         // for public interface defines
#include "sdkconfig.h"

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

/**
 * Initialization of Modbus TCP Master controller interface
 */
esp_err_t mbc_master_create_tcp(mb_communication_info_t *config, void **handler)
{
    void *ctx = NULL;
    esp_err_t error = mbc_tcp_master_create(config, &ctx);

    if ((ctx) && (error == ESP_OK)) {
        *handler = ctx;
    }
    return  error;
}

#endif