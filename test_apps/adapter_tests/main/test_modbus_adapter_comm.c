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

#define TEST_SER_PORT_NUM 1
#define TEST_TCP_PORT_NUM 1502
#define TEST_TASKS_NUM 3
#define TEST_TASK_TIMEOUT_MS 30000
#define TEST_LEAK_WARN 32
#define TEST_LEAK_CRITICAL 64
#define TEST_SLAVE_SEND_TOUT_US 30000
#define TEST_MASTER_SEND_TOUT_US 30000

#define TEST_MASTER_RESPOND_TOUT_MS CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND

#define TAG "MODBUS_SERIAL_TEST"

// The workaround to statically link whole test library
__attribute__((unused)) bool mb_test_include_impl = 1;

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

TaskHandle_t task_handles[TEST_TASKS_NUM] = {};

TEST_GROUP(modbus_adapter_comm_basic);

TEST_SETUP(modbus_adapter_comm_basic)
{
    test_common_start();
}

TEST_TEAR_DOWN(modbus_adapter_comm_basic)
{
    uint32_t test_task = 0;
    uint32_t test_task_count = 0;
    int i = 0;

    // Trigger start of test task intentionally
    for (i = 0; i < TEST_TASKS_NUM; i++) {
        test_common_task_notify_start(task_handles[i], 1);
    }

    for (i = 0; (i < TEST_TASKS_NUM); i++) {
        test_task = test_common_wait_done(pdMS_TO_TICKS(TEST_TASK_TIMEOUT_MS));
        if (test_task) {
            unity_utils_task_delete((TaskHandle_t)test_task);
            ESP_LOGI(TAG, "Task %" PRIx32 " is complited.", test_task);
            test_task_count++;
        }
    }

    vTaskDelay(5); // Let the test tasks with lower priority to suspend or delete itself from test_common

    TEST_ASSERT_EQUAL(TEST_TASKS_NUM, test_task_count);
    ESP_LOGI(TAG, "Test done successfully.");

    test_common_stop();
}

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

TEST(modbus_adapter_comm_basic, test_modbus_adapter_rtu)
{
    mb_communication_info_t slave_config1 = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_RTU,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };
    
    task_handles[0] = test_slave_serial_create(&slave_config1);

    mb_communication_info_t slave_config2 = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_RTU,
        .ser_opts.uid = MB_DEVICE_ADDR2,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };

    task_handles[1] = test_slave_serial_create(&slave_config2);

    // Initialize and start Modbus controller
    mb_communication_info_t master_config = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_RTU,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_MASTER_SEND_TOUT_US
    };

    task_handles[2] = test_master_serial_create(&master_config, &descriptors[0], num_descriptors);
}

TEST(modbus_adapter_comm_basic, test_modbus_adapter_ascii)
{
    mb_communication_info_t slave_config1 = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };
    
    task_handles[0] = test_slave_serial_create(&slave_config1);

    mb_communication_info_t slave_config2 = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.uid = MB_DEVICE_ADDR2,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };

    task_handles[1] = test_slave_serial_create(&slave_config2);

    mb_communication_info_t master_config = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_MASTER_SEND_TOUT_US
    };
    
    task_handles[2] = test_master_serial_create(&master_config, &descriptors[0], num_descriptors);
}

#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

const char *slave_tcp_addr_table[] = {
    "01;mb_slave_tcp_01;1502",      // Corresponds to characteristic MB_DEVICE_ADDR1 "mb_slave_tcp_01"
    "200;mb_slave_tcp_c8;1502",     // Corresponds to characteristic MB_DEVICE_ADDR2 "mb_slave_tcp_C8"
    NULL                            // End of table condition (must be included)
};

TEST(modbus_adapter_comm_basic, test_modbus_adapter_tcp)
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

    task_handles[0] = test_slave_tcp_create(&tcp_slave_cfg_1);

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

    task_handles[1] = test_slave_tcp_create(&tcp_slave_cfg_2);

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

    task_handles[2] = test_master_tcp_create(&tcp_master_cfg_1, &descriptors[0], num_descriptors);
}

#endif

TEST_GROUP_RUNNER(modbus_adapter_comm_basic)
{
#if (CONFIG_FMB_COMM_MODE_RTU_EN && CONFIG_FMB_COMM_MODE_ASCII_EN)
    RUN_TEST_CASE(modbus_adapter_comm_basic, test_modbus_adapter_rtu);
    RUN_TEST_CASE(modbus_adapter_comm_basic, test_modbus_adapter_ascii);
#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)
    RUN_TEST_CASE(modbus_adapter_comm_basic, test_modbus_adapter_tcp);
#endif
}
