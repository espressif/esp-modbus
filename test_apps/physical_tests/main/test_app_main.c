/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include "unity.h"
#include "test_common.h"

void app_main(void)
{
#if !CONFIG_LOG_DEFAULT_LEVEL_DEBUG
    esp_log_level_set("mbc_tcp.slave",ESP_LOG_DEBUG);
    esp_log_level_set("mbc_serial.slave",ESP_LOG_DEBUG);
    esp_log_level_set("mb_object.slave",ESP_LOG_DEBUG);
#else
    // Disable VFS logs as they are too verbose
    esp_log_level_set("vfs_calls", ESP_LOG_NONE);
#endif
    printf("Modbus RS485 multi-device test cases/n");
    unity_run_menu();
}
