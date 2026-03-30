/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdint.h>
#include "esp_err.h"
#include "sdkconfig.h"

#define MB_CMD_NO_EVENTS        0
#define MB_CMD_START            BIT0
#define MB_CMD_STOP             BIT1
#define MB_CMD_CONFIG_END       BIT2
#define MB_CMD_MAX_CFG_COUNT    50

#if __cplusplus
extern "C" {
#endif

    /* This structure describes the plugin to the rest of the application */
    typedef struct {
        /* A pointer to the name of the command */
        const char *name;

        /* A function which performs auto-registration of console commands */
        esp_err_t (*plugin_regd_fn)(void);
    } console_cmd_plugin_desc_t;

    /**
     * @brief Initialize the console helper component
     *
     * @param callback Function to call when a command is processed
     * @return
     *          - ESP_OK - initialization is completed, otherwise reports the error code.
     */
    esp_err_t mb_console_init();

    /**
     * @brief Check for console input message during timeout
     *
     * @param event console event corresponded to command
     * @param tout_ms timeout in milliseconds to wait for the event
     *
     * @return event bits that were set, or MB_CMD_NO_EVENTS if timeout occurred without receiving the event
     */
    int mb_console_event_check(int event, uint32_t tout_ms);

#if CONFIG_MB_CONSOLE_HELPER_ENABLED
    /**
     * @brief Registers the mb command.
     *
     * @return
     *          - ESP_OK - command registration is completed, otherwise reports the error code.
     */
    esp_err_t mb_console_cmd_mb_register(void);

    /**
     * @brief Add legacy configuration registration function
     * @param config_table - pointer to the configuration table, which is an array of strings with NULL terminator.
     *                   The console helper will update the entries in this table with the values received from the console.
     * @return
     *          - ESP_OK - command registration is completed, otherwise reports the error code.
     */
    esp_err_t mb_console_register_configs(char **config_table);

    /**
     * @brief Destroy modbus console
     *
     * @return
     *          - ESP_OK - destroy is completed successfully, , otherwise reports the error code.
     */
    esp_err_t mb_console_destroy(void);

#else
#error "Console helper is disabled."
#endif

#if __cplusplus
}
#endif
