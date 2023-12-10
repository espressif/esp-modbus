/*
 * SPDX-FileCopyrightText: 2016-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"                // for esp_err_t
#include "esp_modbus_slave.h"       // for public slave defines
#include "mbc_tcp_slave.h"          // for public interface defines

#include "sdkconfig.h"

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

/**
 * Initialization of Modbus TCP Slave controller
 */
esp_err_t mbc_slave_create_tcp(mb_communication_info_t *config, void **handler)
{
    void *ctx = NULL;
    esp_err_t error = mbc_tcp_slave_create(config, &ctx);

    if ((ctx) && (error == ESP_OK)) {
        mbc_slave_init_iface(ctx);
        *handler = ctx;
    }
    return  error;
}

#endif
