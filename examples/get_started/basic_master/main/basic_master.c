/*
 * SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_log.h"
#include "esp_system.h"
#include "mbcontroller.h"
#include "sdkconfig.h"

#if CONFIG_FMB_COMM_MODE_TCP_EN
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "mdns.h"
#include "protocol_examples_common.h"
#include "mb_console.h" // for CONFIG_MB_SLAVE_IP_FROM_STDIN
#endif

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN) && CONFIG_FMB_COMM_MODE_TCP_EN
#error "Only one from the communication options can be selected together (FMB_COMM_MODE_RTU_EN or FMB_COMM_MODE_ASCII_EN) or FMB_COMM_MODE_TCP_EN"
#endif

// The number of retries in master loop
#define MASTER_MAX_RETRY                (10)

#define UPDATE_CIDS_TIMEOUT_TICS        (500 / portTICK_PERIOD_MS)

#define MB_CMD_CONFIGURATION_TOUT_MS 120000 // for CONFIG_MB_SLAVE_IP_FROM_STDIN

// Options can be used as bit masks or parameter limits
#define OPTS(min_val, max_val, step_val) { .opt1 = min_val, .opt2 = max_val, .opt3 = step_val }

static const char *TAG = "BASIC_MODBUS_MASTER";

static void *master_handle = NULL;

// All the slave devices being accessed by master.
enum {
    MB_SLAVE_ADDR1 = 1,  // Add other slave addresses here.
    MB_DEVICE_COUNT = 2  // Equals to the number of registered slaves - 1
};

#if CONFIG_FMB_COMM_MODE_TCP_EN

// This table represents slave IP addresses that correspond to the short address field of the slave in device_parameters structure
// Modbus TCP stack shall use these addresses to be able to connect and read parameters from slave
char *slave_ip_address_table[MB_DEVICE_COUNT + 1] = {
#if CONFIG_MB_SLAVE_IP_FROM_STDIN
    "FROM_STDIN",     // Address corresponds to MB_SLAVE_ADDR1 and set to predefined value by user
    NULL              // End of table condition (must be included)
#elif CONFIG_MB_MDNS_IP_RESOLVER
    "01;mb_slave_tcp_01;1502",
    NULL              // End of table condition (must be included)
#endif
};

const size_t ip_table_sz = (size_t)(sizeof(slave_ip_address_table) / sizeof(slave_ip_address_table[0]));

static void master_destroy_slave_list(char **table, size_t ip_table_size)
{
    for (int i = 0; ((i < ip_table_size) && table[i] != NULL); i++) {
        if (table[i]) {
#if CONFIG_MB_SLAVE_IP_FROM_STDIN
            free(table[i]);
            table[i] = "FROM_STDIN";
#elif CONFIG_MB_MDNS_IP_RESOLVER
            table[i] = NULL;
#endif
        }
    }
}

static esp_err_t init_services(mb_tcp_addr_type_t ip_addr_type)
{
    esp_err_t result = nvs_flash_init();
    if (result == ESP_ERR_NVS_NO_FREE_PAGES || result == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        result = nvs_flash_init();
    }
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                       TAG,
                       "nvs_flash_init fail, returns(0x%x).",
                       (int)result);
    result = esp_netif_init();
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                       TAG,
                       "esp_netif_init fail, returns(0x%x).",
                       (int)result);
    result = esp_event_loop_create_default();
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                       TAG,
                       "esp_event_loop_create_default fail, returns(0x%x).",
                       (int)result);
    // This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
    // Read "Establishing Wi-Fi or Ethernet Connection" section in
    // examples/protocols/README.md for more information about this function.
    result = example_connect();
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                       TAG,
                       "example_connect fail, returns(0x%x).",
                       (int)result);
#if CONFIG_EXAMPLE_CONNECT_WIFI
    result = esp_wifi_set_ps(WIFI_PS_NONE);
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                       TAG,
                       "esp_wifi_set_ps fail, returns(0x%x).",
                       (int)result);
#endif

#if CONFIG_MB_SLAVE_IP_FROM_STDIN
#if CONFIG_MB_CONSOLE_HELPER_ENABLED
    mb_console_init();
    result = mb_console_register_configs(slave_ip_address_table);
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                       TAG,
                       "Could not init CONFIG mode, returns(0x%x).",
                       (int)result);
    ESP_LOGI(TAG, "System initialized in CONFIG mode.");
    ESP_LOGI(TAG, "Usage example: IP 0=192.168.1.5;1502 -> then: mb start instances");
    if (!mb_console_event_check(MB_CMD_CONFIG_END, MB_CMD_CONFIGURATION_TOUT_MS)) {
        ESP_LOGE(TAG, "Configuration timeout reached.");
        return ESP_ERR_NOT_FOUND;
    }
#else
#error "The MB_CONSOLE_HELPER_ENABLED is required for setting configs from STDIN."
#endif
#endif
    return ESP_OK;
}


static esp_err_t destroy_services(void)
{
    esp_err_t err = ESP_OK;
    master_destroy_slave_list(slave_ip_address_table, ip_table_sz);

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

#elif CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN

static void uart_initialization(void)
{
    ESP_ERROR_CHECK(uart_set_pin(CONFIG_MB_UART_PORT_NUM, CONFIG_MB_UART_TXD, CONFIG_MB_UART_RXD,
                                 CONFIG_MB_UART_RTS, UART_PIN_NO_CHANGE));

#if CONFIG_MB_USE_RS485_HALF_DUPLEX_EN
    ESP_ERROR_CHECK(uart_set_mode(CONFIG_MB_UART_PORT_NUM, UART_MODE_RS485_HALF_DUPLEX));
#else
    ESP_ERROR_CHECK(uart_set_mode(CONFIG_MB_UART_PORT_NUM, UART_MODE_UART));
#endif
}

#endif

static uint16_t register_example_value = 15;

void read_modbus_parameter(uint16_t cid, uint16_t *parameter_value)
{
    esp_err_t err = ESP_OK;
    const mb_parameter_descriptor_t *param_descriptor = NULL;  // Struct to hold Data Dictionary entry
    uint8_t type = 0;  // Parameter type based on name returned from request (keep it zero)

    ESP_ERROR_CHECK(mbc_master_get_cid_info(master_handle, cid, &param_descriptor));

    err = mbc_master_get_parameter(master_handle, cid, (uint8_t *)parameter_value, &type);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Master Id:%p Characteristic ID #%u %s value = %u read successful.",
                 master_handle,
                 param_descriptor->cid,
                 param_descriptor->param_key,
                 *parameter_value);
    } else {
        ESP_LOGE(TAG, "Master Id:%p Characteristic ID #%u %s read fail, err = %s.",
                 master_handle,
                 param_descriptor->cid,
                 param_descriptor->param_key,
                 esp_err_to_name(err));
    }
}

void write_modbus_parameter(uint16_t cid, uint16_t *parameter_value)
{
    esp_err_t err = ESP_OK;
    const mb_parameter_descriptor_t *param_descriptor = NULL;  // Struct to hold Data Dictionary entry
    uint8_t type = 0;  // Parameter type based on name returned from request (keep it zero)

    ESP_ERROR_CHECK(mbc_master_get_cid_info(master_handle, cid, &param_descriptor));

    err = mbc_master_set_parameter(master_handle, cid, (uint8_t *)parameter_value, &type);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Master Id:%p Characteristic ID #%u %s write fail, err = %s.",
                 master_handle,
                 param_descriptor->cid,
                 param_descriptor->param_key,
                 esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Master Id:%p Characteristic ID #%u %s value = %u write successful.",
                 master_handle,
                 param_descriptor->cid,
                 param_descriptor->param_key,
                 *parameter_value);
    }
}

// Number of each accessed Characteristic Identifier (CID) for Data Dictionary reference.
// CID and Data Dictionary order must match.
enum {
    CID_EX_0 = 0,
    CID_COUNT
};

//                  DATA DICTIONARY
//
// Each entry in the Data Dictionary must have the fields:
//     cid - CID number (must be unique in the table)
//     param_key - Description of the characteristic (must be unique in the table)
//     param_units - Description of units being measured
//     mb_slave_addr - Slave device address (unit identifier (UID) or short address) where the parameter is stored.
//
//     #### Fields regarding register area in slave where the parameter is stored, used by master to populate the read/write request
//     mb_param_type - Type of Modbus register area in slave (Input, Holding, Coil, Discrete)
//     mb_reg_start - Parameter start offset address in slave register area
//     mb_size - Size in registers (two bytes for INPUT and HOLDING, 1 bit for COIL and DISCRETE) of parameter in slave register area
//
//     #### Fields regarding where data from slave will be saved in master
//     param_offset - Offset start address
//     param_type - Data type of parameter (Float, U8, U16, U32, ASCII, etc.)
//     param_size - Number of bytes to be saved
//
//     param_opts - Extra options to define limits or alarm state for user application.
//     access - Define the access permission of characteristics for user application (readable, writable, triggerable, etc.)

const mb_parameter_descriptor_t device_parameters[] = {
    {
        CID_EX_0, "Example_register", "-", MB_SLAVE_ADDR1,
        MB_PARAM_HOLDING, 0, 1,
        0, PARAM_TYPE_U16, PARAM_SIZE_U16,
        OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER
    }
};

// Calculate number of parameters in the Data Dictionary table
const uint16_t num_device_parameters = (sizeof(device_parameters) / sizeof(device_parameters[0]));

static void master_operation_func(void)
{
    ESP_LOGI(TAG, "Start Modbus basic example...");

    for (uint8_t retry = 0; retry < MASTER_MAX_RETRY; retry++) {

        write_modbus_parameter(CID_EX_0, &register_example_value);

        read_modbus_parameter(CID_EX_0, &register_example_value);

        register_example_value += 1;

        vTaskDelay(UPDATE_CIDS_TIMEOUT_TICS);
    }
}

#if CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN

static esp_err_t master_init_serial(void)
{
    esp_err_t err = ESP_OK;

    mb_communication_info_t comm = {
        .ser_opts.port = CONFIG_MB_UART_PORT_NUM,

#if CONFIG_FMB_COMM_MODE_ASCII_EN
        .ser_opts.mode = MB_ASCII,
#elif CONFIG_FMB_COMM_MODE_RTU_EN
        .ser_opts.mode = MB_RTU,
#endif
        .ser_opts.baudrate = CONFIG_MB_UART_BAUD_RATE,
        .ser_opts.parity = MB_PARITY_NONE,
        .ser_opts.uid = 0,
        .ser_opts.response_tout_ms = CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1
    };

    ESP_ERROR_CHECK(mbc_master_create_serial(&comm, &master_handle));

    ESP_RETURN_ON_FALSE((master_handle != NULL), ESP_ERR_INVALID_STATE, TAG, "mb controller initialization fail.");

    uart_initialization();

    ESP_ERROR_CHECK(mbc_master_set_descriptor(master_handle, &device_parameters[0], num_device_parameters));
    ESP_LOGI(TAG, "Modbus master stack initialized...");
    ESP_ERROR_CHECK(mbc_master_start(master_handle));

    return err;
}
#endif

#if CONFIG_FMB_COMM_MODE_TCP_EN

static esp_err_t master_init_tcp(void)
{
    esp_err_t err = ESP_OK;

    mb_tcp_addr_type_t ip_addr_type;
#if !CONFIG_EXAMPLE_CONNECT_IPV6
    ip_addr_type = MB_IPV4;
#else
    ip_addr_type = MB_IPV6;
#endif

    ESP_ERROR_CHECK(init_services(ip_addr_type));

    mb_communication_info_t tcp_master_config = {
        .tcp_opts.port = CONFIG_FMB_TCP_PORT_DEFAULT,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = ip_addr_type,
        .tcp_opts.ip_addr_table = (void *)slave_ip_address_table,
        .tcp_opts.uid = 0,
        .tcp_opts.start_disconnected = false,
        .tcp_opts.response_tout_ms = CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND,
        .tcp_opts.ip_netif_ptr = (void *)get_example_netif()
    };

    ESP_ERROR_CHECK(mbc_master_create_tcp(&tcp_master_config, &master_handle));
    ESP_RETURN_ON_FALSE((master_handle != NULL), ESP_ERR_INVALID_STATE, TAG, "mb controller initialization fail.");

    ESP_ERROR_CHECK(mbc_master_set_descriptor(master_handle, &device_parameters[0], num_device_parameters));
    ESP_LOGI(TAG, "Modbus master stack initialized...");
    ESP_ERROR_CHECK(mbc_master_start(master_handle));

    return err;
}
#endif

void app_main(void)
{

    esp_log_level_set("mbc_tcp.master", ESP_LOG_DEBUG);
    esp_log_level_set("mbc_serial.master", ESP_LOG_DEBUG);
    esp_log_level_set("mb_object.master", ESP_LOG_DEBUG);


#if CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN
    ESP_ERROR_CHECK(master_init_serial());
#elif CONFIG_FMB_COMM_MODE_TCP_EN
    ESP_ERROR_CHECK(master_init_tcp());
#endif

    master_operation_func();
    ESP_LOGI(TAG, "Destroy master...");
    ESP_ERROR_CHECK(mbc_master_delete(master_handle));

#if CONFIG_FMB_COMM_MODE_TCP_EN
    ESP_ERROR_CHECK(destroy_services());
#endif
}
