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

#define TEST_SER_PORT_NUM1              (1)
#define TEST_SER_PORT_NUM2              (2)
#define TEST_TASK_TIMEOUT_MS            (120000)
#define TEST_LEAK_WARN                  (32)
#define TEST_LEAK_CRITICAL              (64)
#define TEST_SLAVE_SEND_TOUT_US         (5000)
#define TEST_MASTER_SEND_TOUT_US        (5000)

#define TEST_MASTER_RESPOND_TOUT_MS     (CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND)

#define TAG "MODBUS_SERIAL_TEST"

// The workaround to statically link whole test library
__attribute__((unused)) bool mb_test_include_adapter_impl_serial = true;

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

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

TEST_GROUP(modbus_adapter_serial);

TEST_SETUP(modbus_adapter_serial)
{
    test_common_start();
}

TEST_TEAR_DOWN(modbus_adapter_serial)
{
    int task_count = test_common_task_start_all(1);
    TEST_ASSERT_TRUE(task_count > 0);
    TEST_ASSERT_EQUAL(task_count, test_common_task_wait_done_delete_all(TEST_TASK_TIMEOUT_MS));
    test_common_stop();
    ESP_LOGI(TAG, "%s, done successfully.", __func__);
}

TEST(modbus_adapter_serial, test_modbus_adapter_rtu)
{
    mb_communication_info_t slave_config1 = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_RTU,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };
    
    TEST_ASSERT_NOT_NULL(test_common_slave_serial_create(&slave_config1, 0));

    mb_communication_info_t slave_config2 = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_RTU,
        .ser_opts.uid = MB_DEVICE_ADDR2,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };

    TEST_ASSERT_NOT_NULL(test_common_slave_serial_create(&slave_config2, 0));

    // Initialize and start Modbus controller
    mb_communication_info_t master_config = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_RTU,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_MASTER_SEND_TOUT_US
    };

    TEST_ASSERT_NOT_NULL(test_common_master_serial_create(&master_config, 0, &descriptors[0], num_descriptors));
}

TEST(modbus_adapter_serial, test_modbus_adapter_ascii)
{
    mb_communication_info_t slave_config1 = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };
    
    TEST_ASSERT_NOT_NULL(test_common_slave_serial_create(&slave_config1, 0));

    mb_communication_info_t slave_config2 = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.uid = MB_DEVICE_ADDR2,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };

    TEST_ASSERT_NOT_NULL(test_common_slave_serial_create(&slave_config2, 0));

    mb_communication_info_t master_config = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_MASTER_SEND_TOUT_US
    };
    
    TEST_ASSERT_NOT_NULL(test_common_master_serial_create(&master_config, 0, &descriptors[0], num_descriptors));
}

// ignore test for now (temporary workaround for the issue)
IGNORE_TEST(modbus_adapter_serial, test_modbus_adapter_rtu_two_ports)
{
    mb_communication_info_t slave_config1 = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };
    
    TEST_ASSERT_NOT_NULL(test_common_slave_serial_create(&slave_config1, 0));

    mb_communication_info_t slave_config2 = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.uid = MB_DEVICE_ADDR2,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };

    TEST_ASSERT_NOT_NULL(test_common_slave_serial_create(&slave_config2, 0));

    mb_communication_info_t slave_config3 = {
        .ser_opts.port = TEST_SER_PORT_NUM2,
        .ser_opts.mode = MB_RTU,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };
    
    TEST_ASSERT_NOT_NULL(test_common_slave_serial_create(&slave_config3, 0));

    mb_communication_info_t slave_config4 = {
        .ser_opts.port = TEST_SER_PORT_NUM2,
        .ser_opts.mode = MB_RTU,
        .ser_opts.uid = MB_DEVICE_ADDR2,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 1,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };

    TEST_ASSERT_NOT_NULL(test_common_slave_serial_create(&slave_config4, 0));

    mb_communication_info_t master_config1 = {
        .ser_opts.port = TEST_SER_PORT_NUM1,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };
    
    TEST_ASSERT_NOT_NULL(test_common_master_serial_create(&master_config1, 0, &descriptors[0], num_descriptors));

    mb_communication_info_t master_config2 = {
        .ser_opts.port = TEST_SER_PORT_NUM2,
        .ser_opts.mode = MB_RTU,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US
    };
    
    TEST_ASSERT_NOT_NULL(test_common_master_serial_create(&master_config2, 0, &descriptors[0], num_descriptors));
}

TEST_GROUP_RUNNER(modbus_adapter_serial)
{
    RUN_TEST_CASE(modbus_adapter_serial, test_modbus_adapter_rtu);
    RUN_TEST_CASE(modbus_adapter_serial, test_modbus_adapter_ascii);
    RUN_TEST_CASE(modbus_adapter_serial, test_modbus_adapter_rtu_two_ports);
}

#endif


