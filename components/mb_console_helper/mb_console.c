/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_console.h"
#include "esp_log.h"
#include "argtable3/argtable3.h"

#include "mb_console.h"

#if CONFIG_MB_CONSOLE_HELPER_ENABLED

static const char *TAG = "mb_console";

/* FreeRTOS event group to command received */
static EventGroupHandle_t s_mb_event_group;
// Mutex to protect configuration table updates
static SemaphoreHandle_t s_config_table_lock;

#if CONFIG_MB_CONSOLE_CMD_AUTO_REGISTRATION

static char **s_config_table = NULL;
static esp_console_repl_t *repl = NULL;

static struct {
    struct arg_str *config_str;
    struct arg_end *end;
} add_config_args;

// Supports simple Modbus command arguments for now
static struct {
    struct arg_str *command;
    struct arg_str *instance;
    struct arg_end *end;
} mb_args;

esp_err_t mb_console_cmd_mb_register(void);

/**
 * Static registration of this plugin is achieved by defining the plugin description
 * structure and placing it into .console_cmd_desc section.
 * The name of the section and its placement is determined by linker.lf file in 'plugins' component.
 */
static const console_cmd_plugin_desc_t __attribute__((section(".console_cmd_desc"), used)) PLUGIN = {
    .name = "console_cmd_mb",
    .plugin_regd_fn = &mb_console_cmd_mb_register
};
#endif

static int do_mb_cmd(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&mb_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, mb_args.end, argv[0]);
        return 1;
    }
    const char *inst = mb_args.instance->sval[0];
    if (strcmp(inst, "instances") == 0 ||
            strcmp(inst, "masters") == 0 ||
            strcmp(inst, "slaves") == 0) {
        if (strcmp(mb_args.command->sval[0], "start") == 0) {
            ESP_LOGI(TAG, "Start modbus %s.", mb_args.instance->sval[0]);
            xEventGroupSetBits(s_mb_event_group, MB_CMD_START);
            return 0;
        } else if (strcmp(mb_args.command->sval[0], "stop") == 0) {
            ESP_LOGI(TAG, "Stop modbus %s.", mb_args.instance->sval[0]);
            xEventGroupSetBits(s_mb_event_group, MB_CMD_STOP);
            return 0;
        }
    }

    return 1;
}

static char *console_cmd_scan_config(int *index, uint16_t *port_ptr, const char *buffer)
{
    if (!buffer || !index) {
        return NULL;
    }
    char *ip_str = NULL;
    int a[8] = {0};
    int buf_cnt = 0;
    uint16_t port_val = 0;
#if !CONFIG_EXAMPLE_CONNECT_IPV6
    buf_cnt = sscanf(buffer, "%d=%d.%d.%d.%d;%" PRIu16, index, &a[0], &a[1], &a[2], &a[3], &port_val);
    if (buf_cnt == 6) {
        if (-1 == asprintf(&ip_str, "%02x;%d.%d.%d.%d;%" PRIu16, (int)(*index + 1), a[0], a[1], a[2], a[3], port_val)) {
            abort();
        }
    } else if (buf_cnt == 5) {
        if (-1 == asprintf(&ip_str, "%02x;%d.%d.%d.%d", (int)(*index + 1), a[0], a[1], a[2], a[3])) {
            abort();
        }
    } else {
        return NULL;
    }
#else
    buf_cnt = sscanf(buffer, "%d=%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x;%" PRIu16, index, &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7], &port_val);
    if (buf_cnt == 9) {
        if (-1 == asprintf(&ip_str, "%02x;%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x;%" PRIu16, (int)(*index + 1), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], port_val)) {
            abort();
        }
    } else if (buf_cnt == 8) {
        if (-1 == asprintf(&ip_str, "%02x;%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", (int)(*index + 1), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])) {
            abort();
        }
    } else {
        return NULL;
    }
#endif
    if (port_ptr) {
        *port_ptr = port_val;
    }
    printf("IP string: %s\r\n", ip_str);
    return ip_str;
}

static int console_cmd_check_table(char **config_table, int *free_slot_cnt_ptr, int *first_free_slot_ptr)
{
    if (!config_table || !config_table[0]) {
        ESP_LOGE(TAG, "Configuration table is not correctly initialized.");
        return -1;
    }

    int cnt = 0;
    int free_slot_cnt = 0;
    int first_free_slot = -1;

    for (cnt = 0; cnt < MB_CMD_MAX_CFG_COUNT && config_table[cnt]; ++cnt) {
        if (strcmp("FROM_STDIN", config_table[cnt]) == 0) {
            free_slot_cnt++;
            first_free_slot = first_free_slot < 0 ? cnt : first_free_slot;
        }
    }
    if (cnt == MB_CMD_MAX_CFG_COUNT && config_table[cnt]) {
        ESP_LOGE(TAG, "Configuration table is not terminated correctly: %d", cnt);
        return -1;
    }
    if (free_slot_cnt_ptr) {
        *free_slot_cnt_ptr = free_slot_cnt;
    }
    if (first_free_slot_ptr) {
        *first_free_slot_ptr = first_free_slot;
    }
    ESP_LOGI(TAG, "Configuration table length: %d, free slots: %d", cnt, free_slot_cnt);
    return cnt;
}

static int do_add_config(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&add_config_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, add_config_args.end, argv[0]);
        return 1;
    }

    if (!s_config_table) {
        ESP_LOGE(TAG, "Configuration table is not set.");
        return 1;
    }

    if (!s_config_table_lock) {
        ESP_LOGE(TAG, "Configuration table mutex is not initialized.");
        return 1;
    }

    int cnt = 0;
    int free_slot_cnt = 0;
    int first_free_slot = -1;
    int ret = 1; // default to error

    if (xSemaphoreTake(s_config_table_lock, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to lock configuration table mutex.");
        return 1;
    }

    do {
        cnt = console_cmd_check_table(s_config_table, &free_slot_cnt, &first_free_slot);
        if (cnt <= 0) {
            ESP_LOGE(TAG, "Configuration table is not valid.");
            break;
        }

        int index = 0;
        char *config_str = console_cmd_scan_config(&index, NULL, add_config_args.config_str->sval[0]);

        if (!config_str) {
            ESP_LOGE(TAG, "Incorrect config string: %s", add_config_args.config_str->sval[0]);
            break;
        }

        ESP_LOGI(TAG, "Config table index %d(%s), free slot: %d, cnt: %d, free_slots_cnt: %d", index, config_str, first_free_slot, cnt, free_slot_cnt);

        if (index >= cnt) {
            ESP_LOGE(TAG, "Incorrect config IP index: %d > %d", index, cnt);
            free (config_str);
            break;
        }

        // Allocate and store the IP string
        if (s_config_table[index] &&
                (strcmp("FROM_STDIN", s_config_table[index]) == 0) &&
                (index < MB_CMD_MAX_CFG_COUNT) &&
                (index < cnt)
           ) {
            s_config_table[index] = config_str;
        } else {
            ESP_LOGI(TAG, "Leave IP(%d) = [%s] set manually.", index, s_config_table[index]);
            free (config_str);
            break;
        }

        ESP_LOGI(TAG, "Config[%d] set to %s", index, s_config_table[index]);
        if (first_free_slot + 1 == cnt) {
            ESP_LOGI(TAG, "All %d configs are set.", cnt);
            xEventGroupSetBits(s_mb_event_group, MB_CMD_CONFIG_END);
        } else {
            ESP_LOGI(TAG, "Waiting IP(%d) from stdin:", first_free_slot + 1);
        }
        ret = 0;
    } while (0);

    xSemaphoreGive(s_config_table_lock);
    return ret;
}

// Registers the basic modbus command for start and stop events
esp_err_t mb_console_cmd_mb_register(void)
{
    esp_err_t ret;

    // Support for just simple commands for now
    mb_args.command = arg_str1(NULL, NULL, "<Command>", "Command (start, stop).");
    mb_args.instance = arg_str1(NULL, NULL, "<Instances>", "Instance types (instances, slaves, masters, id)");
    mb_args.end = arg_end(2);

    const esp_console_cmd_t mb_cmd = {
        .command = "mb",
        .help = "Send simple modbus action command",
        .hint = NULL,
        .func = &do_mb_cmd,
        .argtable = &mb_args
    };

    ret = esp_console_cmd_register(&mb_cmd);
    if (ret) {
        ESP_LOGE(TAG, "Unable to register modbus command");
    }

    return ret;
}

esp_err_t mb_console_register_configs(char **config_table)
{
    if (!config_table) {
        ESP_LOGE(TAG, "Incorrect configuration table.");
        return ESP_ERR_INVALID_ARG;
    }

    if (!s_config_table_lock) {
        ESP_LOGE(TAG, "Configuration table mutex is not initialized.");
        return ESP_ERR_INVALID_STATE;
    }

    int free_slot_cnt = 0;
    int first_free_slot = -1;

    if (xSemaphoreTake(s_config_table_lock, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to lock configuration table mutex.");
        return ESP_ERR_INVALID_STATE;
    }

    int cnt = console_cmd_check_table(config_table, &free_slot_cnt, &first_free_slot);
    if (cnt <= 0 || first_free_slot < 0) {
        ESP_LOGE(TAG, "Configuration table is not valid.");
        xSemaphoreGive(s_config_table_lock);
        return ESP_ERR_INVALID_ARG;
    }

    s_config_table = config_table;
    xSemaphoreGive(s_config_table_lock);
    add_config_args.config_str = arg_str1(NULL, NULL, "<config>", "IP config (e.g. \"01=192.168.1.5;1502)\"");
    add_config_args.end = arg_end(1);

    // Use the command similar to legacy string
    const esp_console_cmd_t cmd = {
        .command = "IP",
        .help = "Register configuration",
        .hint = NULL,
        .func = &do_add_config,
        .argtable = &add_config_args
    };

    esp_err_t ret = esp_console_cmd_register(&cmd);
    if (ret) {
        ESP_LOGE(TAG, "Unable to register %s", cmd.command);
        return ret;
    }
    ESP_LOGI(TAG, "Waiting IP(%d) from stdin:", first_free_slot);
    return ESP_OK;
}

esp_err_t mb_console_init()
{
#if CONFIG_MB_CONSOLE_HELPER_ENABLED
    ESP_LOGI(TAG, "Initialize console helper.");

    if (s_config_table_lock) {
        ESP_LOGE(TAG, "Failed to init command console. Already installed?");
        return ESP_ERR_INVALID_STATE;
    }

    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    esp_err_t ret = ESP_FAIL;

    // install console REPL environment
#if defined(CONFIG_ESP_CONSOLE_UART_DEFAULT) || defined(CONFIG_ESP_CONSOLE_UART_CUSTOM)
    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ret = esp_console_new_repl_uart(&hw_config, &repl_config, &repl);

#elif defined(CONFIG_ESP_CONSOLE_USB_CDC)
    esp_console_dev_usb_cdc_config_t hw_config = ESP_CONSOLE_DEV_CDC_CONFIG_DEFAULT();
    ret = esp_console_new_repl_usb_cdc(&hw_config, &repl_config, &repl);

#elif defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG)
    esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ret = esp_console_new_repl_usb_serial_jtag(&hw_config, &repl_config, &repl);

#else
#error Unsupported console type
#endif

    if (ret) {
        ESP_LOGE(TAG, "Failed to init repl: %s", esp_err_to_name(ret));
        return ret;
    }

    extern const console_cmd_plugin_desc_t _console_cmd_array_start;
    extern const console_cmd_plugin_desc_t _console_cmd_array_end;

    ESP_LOGI(TAG, "List of Console commands:\n");
    for (const console_cmd_plugin_desc_t *it = &_console_cmd_array_start; it != &_console_cmd_array_end; ++it) {
        ESP_LOGI(TAG, "- Command '%s', function plugin_regd_fn=%p\n", it->name, it->plugin_regd_fn);
        if (it->plugin_regd_fn != NULL) {
            ret = (it->plugin_regd_fn)();
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "Failed to register console commands: %s", esp_err_to_name(ret));
            }
        }
    }

    s_mb_event_group = xEventGroupCreate();
    if (!s_mb_event_group) {
        ESP_LOGE(TAG, "Failed to create event group.");
        return ESP_ERR_NO_MEM;
    }

    s_config_table_lock = xSemaphoreCreateMutex();
    if (!s_config_table_lock) {
        ESP_LOGE(TAG, "Failed to create configuration table mutex.");
        vEventGroupDelete(s_mb_event_group);
        return ESP_ERR_NO_MEM;
    }

    ret = esp_console_start_repl(repl);
    if (ret) {
        ESP_LOGE(TAG, "Failed to start console commands: %s", esp_err_to_name(ret));
        return ret;
    }


    ESP_LOGI(TAG, "Console helper initialized with config table protection.");
#endif
    return ESP_OK;
}

int mb_console_event_check(int event, uint32_t tout_ms)
{
    if (!event || !tout_ms) {
        return MB_CMD_NO_EVENTS;
    }

    if (!s_mb_event_group) {
        ESP_LOGW(TAG, "Console helper is not initialized, cannot check for commands.");
        return MB_CMD_NO_EVENTS;
    }

    EventBits_t event_mask = event;
    EventBits_t event_bits = MB_CMD_NO_EVENTS;
#if CONFIG_MB_CONSOLE_HELPER_ENABLED
    event_bits = xEventGroupWaitBits(s_mb_event_group,
                                     event_mask ? event_mask : MB_CMD_STOP | MB_CMD_START,
                                     pdTRUE, // Clear bits before returning
                                     pdFALSE,
                                     pdMS_TO_TICKS(tout_ms));
#endif
    return (int) event_bits;
}

esp_err_t mb_console_destroy(void)
{
    esp_err_t err = ESP_ERR_NOT_SUPPORTED;
#if CONFIG_MB_CONSOLE_HELPER_ENABLED
    ESP_LOGI(TAG, "Destroying console helper...");

    if (xSemaphoreTake(s_config_table_lock, pdMS_TO_TICKS(1000)) == pdTRUE) {
        xSemaphoreGive(s_config_table_lock);
    }

    if (s_config_table) {
        for (int i = 0; s_config_table[i]; ++i) {
            if (strcmp("FROM_STDIN", s_config_table[i]) != 0) {
                free(s_config_table[i]);
            }
            s_config_table[i] = NULL;
        }
    }

    if (s_config_table_lock) {
        vSemaphoreDelete(s_config_table_lock);
        s_config_table_lock = NULL;
    }
    if (s_mb_event_group) {
        vEventGroupDelete(s_mb_event_group);
        s_mb_event_group = NULL;
    }

    // It is enough to call repl destructor, esp_console_deinit() call is performed from there
    if (repl && repl->del) {
        err = repl->del(repl);
        if (err) {
            ESP_LOGE(TAG, "Failed to stop repl: %s", esp_err_to_name(err));
        }
    }
    repl = NULL;

    ESP_LOGI(TAG, "Console helper destroyed.");
#endif
    return err;
}

#endif
