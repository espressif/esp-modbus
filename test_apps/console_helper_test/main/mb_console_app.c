/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_console.h"

#include "mb_console.h"

const char *TAG = "console_helper_test";

#if !CONFIG_MB_CONSOLE_HELPER_ENABLED
#error "The MB_CONSOLE_HELPER_ENABLED option must be enabled for this test app."
#endif

// Simple config table: one entry waiting from stdin, NULL-terminated
#define APP_CFG_COUNT 3
#define APP_CFG_TIMEOUT_MS 500
char *app_config_table[APP_CFG_COUNT + 1] = { NULL };

void app_main(void)
{
    ESP_LOGI(TAG, "Console helper test app starting.");

    // Prepare the config table entries; "FROM_STDIN" will be replaced by the helper on configuration.
    for (int i = 0; i < APP_CFG_COUNT; ++i) {
        app_config_table[i] = "FROM_STDIN";
    }
    app_config_table[APP_CFG_COUNT] = NULL; // terminator of the table

    // Init console helper and register config table.
    esp_err_t err = mb_console_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mb_console_init failed: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "mb_console_init OK");
    }

    err = mb_console_register_configs(app_config_table);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mb_console_register_configs failed: %s", esp_err_to_name(err));
    }

    for (;;) {
        int ev = mb_console_event_check(MB_CMD_CONFIG_END | MB_CMD_START | MB_CMD_STOP, APP_CFG_TIMEOUT_MS);
        if (ev & MB_CMD_CONFIG_END) {
            /* print out configured addresses */
            for (int i = 0; i < APP_CFG_COUNT; ++i) {
                if (app_config_table[i]) {
                    ESP_LOGI(TAG, "Config[%d] set to %s\n", i, app_config_table[i]);
                } else {
                    ESP_LOGI(TAG, "ConfigTable[%d]=NULL", i);
                }
            }
        }
        if (ev & MB_CMD_START) {
            ESP_LOGI(TAG, "Start modbus instances.");
        }
        if (ev & MB_CMD_STOP) {
            ESP_LOGI(TAG, "Stop modbus instances.");
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(APP_CFG_TIMEOUT_MS));
    }

    err = mb_console_destroy();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Console helper destroyed.");
    } else {
        ESP_LOGE(TAG, "Console helper destroy failed.");
    }
}
