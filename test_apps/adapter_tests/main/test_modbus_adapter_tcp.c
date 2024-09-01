/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include "unity_fixture.h"

#include "test_utils.h"

#if __has_include("unity_test_utils.h")
#define UNITY_TEST_UTILS_INCLUDED
// unity test utils are used
#include "unity_test_utils.h"
#include "unity_test_utils_memory.h"
#else
// Unit_test_app utils from test_utils ("test_utils.h"), v4.4
#define unity_utils_task_delete test_utils_task_delete
#endif

#include "sdkconfig.h"
#include "test_common.h"

#define TEST_TCP_PORT_NUM               (1502)
#define TEST_TASK_TIMEOUT_MS            (120000)
#define TEST_LEAK_WARN                  (32)
#define TEST_LEAK_CRITICAL              (64)
#define TEST_SLAVE_SEND_TOUT_US         (50)
#define TEST_MASTER_SEND_TOUT_US        (50)

#define TEST_MASTER_RESPOND_TOUT_MS     (CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND)

#define TAG "MODBUS_TCP_TEST"

// The workaround to statically link whole test library
__attribute__((unused)) bool mb_test_include_adapter_impl_tcp = true;

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

// Example Data (Object) Dictionary for Modbus parameters
static const mb_parameter_descriptor_t descriptors[] = {
    {CID_DEV_REG0, STR("MB_hold_reg-0"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 0, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG1, STR("MB_hold_reg-1"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 1, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG2, STR("MB_hold_reg-2"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 2, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG3, STR("MB_hold_reg-3"), STR("Data"), MB_DEVICE_ADDR2, MB_PARAM_HOLDING, 3, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG_COUNT, STR("CYCLE_COUNTER"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 4, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER}
};

// Calculate number of parameters in the table
const uint16_t num_descriptors = (sizeof(descriptors) / sizeof(descriptors[0]));

TEST_GROUP(modbus_adapter_tcp);

TEST_SETUP(modbus_adapter_tcp)
{
    test_common_start();
}

TEST_TEAR_DOWN(modbus_adapter_tcp)
{
    int task_count = test_common_task_start_all(1);
    TEST_ASSERT_TRUE(task_count > 0);
    TEST_ASSERT_EQUAL(task_count, test_common_task_wait_done_delete_all(TEST_TASK_TIMEOUT_MS));
    test_common_stop();
    ESP_LOGI(TAG, "%s, done successfully.", __func__);
}

const char *slave_tcp_addr_table[] = {
    "01;mb_slave_tcp_01;1502",      // Corresponds to characteristic MB_DEVICE_ADDR1 "mb_slave_tcp_01"
    "200;mb_slave_tcp_c8;1502",     // Corresponds to characteristic MB_DEVICE_ADDR2 "mb_slave_tcp_C8"
    NULL                            // End of table condition (must be included)
};

TEST(modbus_adapter_tcp, test_modbus_adapter_tcp)
{
    mb_communication_info_t tcp_slave_cfg_1 = {
        .tcp_opts.port = TEST_TCP_PORT_NUM,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = NULL,
        .tcp_opts.uid = MB_DEVICE_ADDR1,
        .tcp_opts.start_disconnected = true,
        .tcp_opts.response_tout_ms = 1,
        .tcp_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };

    TEST_ASSERT_NOT_NULL(test_common_slave_tcp_create(&tcp_slave_cfg_1, 0));

    mb_communication_info_t tcp_slave_cfg_2 = {
        .tcp_opts.port = TEST_TCP_PORT_NUM,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = NULL,
        .tcp_opts.uid = MB_DEVICE_ADDR2,
        .tcp_opts.start_disconnected = true,
        .tcp_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .tcp_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };

    TEST_ASSERT_NOT_NULL(test_common_slave_tcp_create(&tcp_slave_cfg_2, 0));

    // Initialize and start Modbus controller
    mb_communication_info_t tcp_master_cfg_1 = {
        .tcp_opts.port = TEST_TCP_PORT_NUM,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = (void *)slave_tcp_addr_table,
        .tcp_opts.uid = 0,
        .tcp_opts.start_disconnected = false,
        .tcp_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .tcp_opts.test_tout_us = TEST_MASTER_SEND_TOUT_US
    };

    TEST_ASSERT_NOT_NULL(test_common_master_tcp_create(&tcp_master_cfg_1, 0, &descriptors[0], num_descriptors));
}

TEST_GROUP_RUNNER(modbus_adapter_tcp)
{
    RUN_TEST_CASE(modbus_adapter_tcp, test_modbus_adapter_tcp);
}

#endif


