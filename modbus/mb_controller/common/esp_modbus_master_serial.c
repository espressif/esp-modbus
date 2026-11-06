/*
 * SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"                // for esp_err_t
#include "mbc_master.h"             // for master interface define
#include "esp_modbus_master.h"      // for public slave defines
#include "mbc_serial_master.h"      // for public interface defines

#include "sdkconfig.h"              // for KConfig defines

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

/**
 * Initialization of Modbus master serial
 */
esp_err_t mbc_master_create_serial_with_transport(mb_communication_info_t *config,
        mbc_master_transport_factory_t factory,
        void *user_ctx,
        void **ctx)
{
    void *obj = NULL;
    esp_err_t error = ESP_ERR_NOT_SUPPORTED;
    switch (config->mode) {
    case MB_RTU:
    case MB_ASCII:
        error = mbc_serial_master_create_with_transport(config, factory, user_ctx, &obj);
        break;
    default:
        return ESP_ERR_NOT_SUPPORTED;
    }
    if ((obj) && (error == ESP_OK)) {
        *ctx = obj;
    }
    return error;
}

esp_err_t mbc_master_create_serial(mb_communication_info_t *config, void **ctx)
{
    return mbc_master_create_serial_with_transport(config, NULL, NULL, ctx);
}

#endif
