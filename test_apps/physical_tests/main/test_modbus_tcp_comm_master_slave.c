/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include "unity.h"

#include "sdkconfig.h"
#include "test_common.h"
#include "test_utils.h"

#include "nvs_flash.h"

#if MB_MDNS_IS_INCLUDED
#include "mdns.h"
#endif

#include "protocol_examples_common.h"
#include "esp_event.h"

#if __has_include("unity_test_utils.h")
// unity test utils are used
#include "unity_test_utils.h"
#else
// Unit_test_app utils from test_utils ("test_utils.h"), v4.4
#define unity_utils_task_delete test_utils_task_delete
#endif

#define TEST_TCP_PORT_NUM1              (1502)
#define TEST_TCP_PORT_NUM2              (502)
#define TEST_TCP_TASK_TIMEOUT_MS        (160000)
#define TEST_TCP_SLAVE_SEND_TOUT_US     (500)
#define TEST_TCP_MASTER_SEND_TOUT_US    (500)

#define TEST_MASTER_RESPOND_TOUT_MS     (CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND)

// The workaround to statically link the whole test library
__attribute__((unused)) bool mb_test_include_phys_impl_tcp = true;

#define TAG "MODBUS_TCP_COMM_TEST"

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

// Example Data (Object) Dictionary for Modbus parameters
static const mb_parameter_descriptor_t descriptors[] = {
    {CID_DEV_REG0, STR("MB_hold_reg-0"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 0, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG1, STR("MB_hold_reg-1"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 1, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG2, STR("MB_hold_reg-2"), STR("Data"), MB_DEVICE_ADDR2, MB_PARAM_HOLDING, 2, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG3, STR("MB_hold_reg-3"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 3, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG_COUNT, STR("CYCLE_COUNTER"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 4, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER}
};

// The number of parameters in the table
const uint16_t num_descriptors = (sizeof(descriptors) / sizeof(descriptors[0]));

const char *slave_tcp_addr_table[] = {
    "01;mb_slave_tcp_01;1502",      // Corresponds to characteristic MB_DEVICE_ADDR1
    "200;mb_slave_tcp_c8;502",     // Corresponds to characteristic MB_DEVICE_ADDR2
    NULL                            // End of table condition (must be included)
};

static esp_err_t test_tcp_services_init(void **pnetif)
{
    esp_err_t result = nvs_flash_init();
    if ((result == ESP_ERR_NVS_NO_FREE_PAGES) || (result == ESP_ERR_NVS_NEW_VERSION_FOUND)) {
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
#if MB_MDNS_IS_INCLUDED
    // Start mdns service and register device
    if (mdns_init() != ESP_OK) {
        ESP_LOGE(TAG, "initialization of mdns fail.");
    };
#endif
    // This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
    // Read "Establishing Wi-Fi or Ethernet Connection" section in
    // examples/protocols/README.md for more information about this function.
    result = example_connect();
    ESP_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                                TAG,
                                "example_connect fail, returns(0x%x).",
                                (int)result);
#if CONFIG_EXAMPLE_CONNECT_WIFI
    // result = esp_wifi_set_ps(WIFI_PS_NONE);
    // ESP_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
    //                                TAG,
    //                                "esp_wifi_set_ps fail, returns(0x%x).",
    //                                (int)result);
#endif
    if (pnetif) {
        *pnetif = get_example_netif();
    }
    return ESP_OK;
}

static esp_err_t test_tcp_services_destroy(void)
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
    ESP_RETURN_ON_FALSE(((err == ESP_OK) || (err == ESP_ERR_NOT_SUPPORTED)), 
                            ESP_ERR_INVALID_STATE,
                            TAG,
                            "esp_netif_deinit fail, returns(0x%x).",
                            (int)err);
    err = nvs_flash_deinit();
    ESP_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                            TAG,
                            "nvs_flash_deinit fail, returns(0x%x).",
                            (int)err);
#if MB_MDNS_IS_INCLUDED
    // Stop mdns service and register device
    mdns_free();
#endif
    return err;
}

static void test_modbus_tcp_slave(void)
{
    void *pnetif = NULL;
    TEST_ASSERT_TRUE(test_tcp_services_init(&pnetif) == ESP_OK);
    TEST_ASSERT_NOT_NULL(pnetif);
    test_common_start();

    mb_communication_info_t tcp_slave_cfg_1 = {
        .tcp_opts.port = TEST_TCP_PORT_NUM1,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = NULL,
        .tcp_opts.uid = MB_DEVICE_ADDR1,
        .tcp_opts.start_disconnected = true,
        .tcp_opts.response_tout_ms = 1,
        .tcp_opts.test_tout_us = TEST_TCP_SLAVE_SEND_TOUT_US,
        .tcp_opts.ip_netif_ptr = pnetif
    };

    TEST_ASSERT_NOT_NULL(test_common_slave_tcp_create(&tcp_slave_cfg_1, 0));

    ESP_LOGI(TAG, "Slave TCP #1 is started. (%s).", __func__);

    mb_communication_info_t tcp_slave_cfg_2 = {
        .tcp_opts.port = TEST_TCP_PORT_NUM2,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = NULL,
        .tcp_opts.uid = MB_DEVICE_ADDR2,
        .tcp_opts.start_disconnected = true,
        .tcp_opts.response_tout_ms = 1,
        .tcp_opts.test_tout_us = TEST_TCP_SLAVE_SEND_TOUT_US,
        .tcp_opts.ip_netif_ptr = pnetif
    };

    TEST_ASSERT_NOT_NULL(test_common_slave_tcp_create(&tcp_slave_cfg_2, 0));

    ESP_LOGI(TAG, "Slave TCP #2 is started. (%s).", __func__);

    unity_send_signal("Slave_ready");
    unity_wait_for_signal("Master_started");

    TEST_ASSERT_EQUAL(test_common_task_start_all(1),
                        test_common_task_wait_done_delete_all(TEST_TCP_TASK_TIMEOUT_MS));

    ESP_LOGI(TAG, "Slave TCP test is complited. (%s).", __func__);

    test_common_stop();

    test_tcp_services_destroy();
}

static void test_modbus_tcp_master(void)
{
    void *pnetif = NULL;
    TEST_ASSERT_TRUE(test_tcp_services_init(&pnetif) == ESP_OK);
    TEST_ASSERT_NOT_NULL(pnetif);

    test_common_start();

    ESP_LOGI(TAG, "Master TCP is started (%s).", __func__);
    unity_wait_for_signal("Slave_ready");


    // Initialize and start Modbus controller
    mb_communication_info_t tcp_master_cfg_1 = {
        .tcp_opts.port = TEST_TCP_PORT_NUM1,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = (void *)slave_tcp_addr_table,
        .tcp_opts.uid = 0,
        .tcp_opts.start_disconnected = false,
        .tcp_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .tcp_opts.test_tout_us = TEST_TCP_MASTER_SEND_TOUT_US,
        .tcp_opts.ip_netif_ptr = pnetif
    };

    TEST_ASSERT_NOT_NULL(test_common_master_tcp_create(&tcp_master_cfg_1, 0, &descriptors[0], num_descriptors));

    unity_send_signal("Master_started");

    TEST_ASSERT_EQUAL(test_common_task_start_all(1),
                        test_common_task_wait_done_delete_all(TEST_TCP_TASK_TIMEOUT_MS));

    test_common_stop();

    test_tcp_services_destroy();
    ESP_LOGI(TAG, "Master TCP is complited. (%s).", __func__);
}

/* 
 * Modbus TCP multi device test case
 */
TEST_CASE_MULTIPLE_DEVICES("Modbus TCP multi device master - slave case.", "[modbus][test_env=multi_dut_modbus_tcp]",
                            test_modbus_tcp_slave, test_modbus_tcp_master);

#endif