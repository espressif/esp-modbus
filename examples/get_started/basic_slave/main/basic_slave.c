/*
 * SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mbcontroller.h"
#include "esp_log.h"
#include "sdkconfig.h"

#if CONFIG_FMB_COMM_MODE_TCP_EN
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "mdns.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#endif

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN) && CONFIG_FMB_COMM_MODE_TCP_EN
#error "Only one from the communication options can be selected  (FMB_COMM_MODE_RTU_EN or FMB_COMM_MODE_ASCII_EN) or FMB_COMM_MODE_TCP_EN"
#endif

#define MB_PAR_INFO_GET_TOUT                (10) // Timeout for get parameter info

static const char *TAG = "BASIC_MODBUS_SLAVE";

static void *slave_handle = NULL;

// Slave holding register Area, the descriptor will associate this structure as the holding registers available for reading or writing.
struct holding_params {
    uint16_t holding_1;
};

#if CONFIG_FMB_COMM_MODE_TCP_EN

static esp_err_t init_services(void)
{
    esp_err_t result = nvs_flash_init();
    if (result == ESP_ERR_NVS_NO_FREE_PAGES || result == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        result = nvs_flash_init();
    }
    ESP_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                        TAG,
                        "nvs_flash_init fail, returns(0x%x).",
                        (int)result);
    result = esp_netif_init();
    ESP_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                        TAG,
                        "esp_netif_init fail, returns(0x%x).",
                        (int)result);
    result = esp_event_loop_create_default();
    ESP_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                        TAG,
                        "esp_event_loop_create_default fail, returns(0x%x).",
                        (int)result);
    // This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
    // Read "Establishing Wi-Fi or Ethernet Connection" section in
    // examples/protocols/README.md for more information about this function.
    result = example_connect();
    ESP_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                        TAG,
                        "example_connect fail, returns(0x%x).",
                        (int)result);
#if CONFIG_EXAMPLE_CONNECT_WIFI
    result = esp_wifi_set_ps(WIFI_PS_NONE); // Disables power save on WIFI to decrease transmit delays
    ESP_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                        TAG,
                        "esp_wifi_set_ps fail, returns(0x%x).",
                        (int)result);
#endif
    return ESP_OK;
}

static esp_err_t destroy_services(void)
{
    esp_err_t err = ESP_OK;

    err = example_disconnect();
    ESP_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                        TAG,
                        "example_disconnect fail, returns(0x%x).",
                        (int)err);
    err = esp_event_loop_delete_default();
    ESP_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                        TAG,
                        "esp_event_loop_delete_default fail, returns(0x%x).",
                        (int)err);
    err = esp_netif_deinit();
    ESP_RETURN_ON_FALSE((err == ESP_OK || err == ESP_ERR_NOT_SUPPORTED), ESP_ERR_INVALID_STATE,
                        TAG,
                        "esp_netif_deinit fail, returns(0x%x).",
                        (int)err);
    err = nvs_flash_deinit();
    ESP_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                        TAG,
                        "nvs_flash_deinit fail, returns(0x%x).",
                        (int)err);
    return err;
}

#elif CONFIG_FMB_COMM_MODE_ASCII_EN  || CONFIG_FMB_COMM_MODE_RTU_EN

static void uart_initialization(void)
{
    // Set UART pin numbers
    ESP_ERROR_CHECK(uart_set_pin(CONFIG_MB_UART_PORT_NUM, CONFIG_MB_UART_TXD, CONFIG_MB_UART_RXD,
                                 CONFIG_MB_UART_RTS, UART_PIN_NO_CHANGE));

#if CONFIG_MB_USE_RS485_HALF_DUPLEX_EN
    ESP_ERROR_CHECK(uart_set_mode(CONFIG_MB_UART_PORT_NUM, UART_MODE_RS485_HALF_DUPLEX));
#else
    ESP_ERROR_CHECK(uart_set_mode(CONFIG_MB_UART_PORT_NUM, UART_MODE_UART));
#endif

}
#endif

#if CONFIG_FMB_COMM_MODE_TCP_EN

static esp_err_t slave_init_tcp(void)
{
    esp_err_t err = ESP_OK;

    ESP_ERROR_CHECK(init_services());

    mb_communication_info_t comm_config = {
        .tcp_opts.port = CONFIG_FMB_TCP_PORT_DEFAULT,
        .tcp_opts.mode = MB_TCP,

#if CONFIG_EXAMPLE_CONNECT_IPV4
        .tcp_opts.addr_type = MB_IPV4,
#else
        .tcp_opts.addr_type = MB_IPV6,
#endif

        .tcp_opts.ip_addr_table = NULL, // Bind to any address
        .tcp_opts.ip_netif_ptr = (void *)get_example_netif(),
        .tcp_opts.uid = CONFIG_MB_SLAVE_ADDR
    };

    ESP_ERROR_CHECK(mbc_slave_create_tcp(&comm_config, &slave_handle));

    ESP_RETURN_ON_FALSE((slave_handle != NULL), ESP_ERR_INVALID_STATE, TAG, "mb controller initialization fail.");
    ESP_ERROR_CHECK(mbc_slave_start(slave_handle));
    ESP_LOGI(TAG, "Modbus slave stack initialized...");

    return err;
}
#endif


#if CONFIG_FMB_COMM_MODE_ASCII_EN  || CONFIG_FMB_COMM_MODE_RTU_EN

static esp_err_t slave_init_serial(void)
{
    esp_err_t err = ESP_OK;

    mb_communication_info_t comm_config = {
        .ser_opts.port = CONFIG_MB_UART_PORT_NUM,

#if CONFIG_FMB_COMM_MODE_ASCII_EN
        .ser_opts.mode = MB_ASCII,
#elif CONFIG_FMB_COMM_MODE_RTU_EN
        .ser_opts.mode = MB_RTU,
#endif

        .ser_opts.baudrate = CONFIG_MB_UART_BAUD_RATE,
        .ser_opts.parity = MB_PARITY_NONE,
        .ser_opts.uid = CONFIG_MB_SLAVE_ADDR,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1
    };

    ESP_ERROR_CHECK(mbc_slave_create_serial(&comm_config, &slave_handle));

    uart_initialization();

    ESP_RETURN_ON_FALSE((slave_handle != NULL), ESP_ERR_INVALID_STATE, TAG, "mb controller initialization fail.");
    ESP_ERROR_CHECK(mbc_slave_start(slave_handle));
    ESP_LOGI(TAG, "Modbus slave stack initialized...");

    return err;
}
#endif

static void register_init(struct holding_params *holding_register)
{
    mb_register_area_descriptor_t reg_area = {0};

    // Initialization of Holding area
    reg_area.type = MB_PARAM_HOLDING;
    reg_area.address = (void *)&holding_register->holding_1;
    reg_area.start_offset = holding_register->holding_1;
    reg_area.size = sizeof(*holding_register);
    reg_area.access = MB_ACCESS_RW;
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(slave_handle, reg_area));

    holding_register->holding_1 = 10;
}

static void slave_operation_func(void)
{
    ESP_LOGI(TAG, "Start Modbus basic slave example...");

    const uint8_t master_max_request = 20; // Defines the slave loop based on master basic example writing and reading 10 times each.

    // Bit masks for different types of master request events
    const mb_event_group_t mb_read_mask = (MB_EVENT_INPUT_REG_RD | MB_EVENT_HOLDING_REG_RD | MB_EVENT_DISCRETE_RD | MB_EVENT_COILS_RD);
    const mb_event_group_t mb_write_mask = (MB_EVENT_HOLDING_REG_WR | MB_EVENT_COILS_WR);
    const mb_event_group_t mb_read_write_mask = (mb_read_mask | mb_write_mask);

    mb_param_info_t reg_info = {0}; // Modbus master request structure

    for (uint8_t request = 0; request < master_max_request; request++) {

        mbc_slave_check_event(slave_handle, mb_read_write_mask);

        ESP_ERROR_CHECK(mbc_slave_get_param_info(slave_handle, &reg_info, MB_PAR_INFO_GET_TOUT));

        const char *rw_str = (reg_info.type & mb_read_mask) ? "READ" : "WRITE";

        if ((reg_info.type & MB_EVENT_HOLDING_REG_WR) || (reg_info.type & MB_EVENT_HOLDING_REG_RD)) {

            ESP_LOGI(TAG, "Slave ID:%p - HOLDING REG %s REG_AREA_ADDR:%p OFFSET:%u NUMBER_REG:%u",
                     slave_handle,
                     rw_str,
                     reg_info.address,
                     reg_info.mb_offset,
                     reg_info.size);
        } else {
            ESP_LOGE(TAG, "Slave ID:%p - UNSUPPORTED REG %s REG_AREA_ADDR:%p OFFSET:%u NUMBER_REG:%u",
                     slave_handle,
                     rw_str,
                     reg_info.address,
                     reg_info.mb_offset,
                     reg_info.size);
        }

    }
}

void app_main(void)
{

    esp_log_level_set("mbc_serial.slave", ESP_LOG_DEBUG);
    esp_log_level_set("mbc_tcp.slave", ESP_LOG_DEBUG);
    esp_log_level_set("mb_object.slave", ESP_LOG_DEBUG);

    struct holding_params example_holding_params = { 0 }; // Register saving structure

#if CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN
    ESP_ERROR_CHECK(slave_init_serial());
#elif CONFIG_FMB_COMM_MODE_TCP_EN
    ESP_ERROR_CHECK(slave_init_tcp());
#endif

    register_init(&example_holding_params);
    slave_operation_func();
    ESP_LOGI(TAG, "Destroy slave...");
    ESP_ERROR_CHECK(mbc_slave_delete(slave_handle));

#if CONFIG_FMB_COMM_MODE_TCP_EN
    ESP_ERROR_CHECK(destroy_services());
#endif
}
