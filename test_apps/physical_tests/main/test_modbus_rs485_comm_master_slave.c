/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include "unity.h"

#include "sdkconfig.h"
#include "test_common.h"
#include "test_utils.h"

#if __has_include("unity_test_utils.h")
// unity test utils are used
#include "unity_test_utils.h"
#else
// Unit_test_app utils from test_utils ("test_utils.h"), v4.4
#define unity_utils_task_delete test_utils_task_delete
#endif

#define TEST_SER_PORT_NUM       (1)
#define TEST_TASK_TIMEOUT_MS    (30000)
#define TEST_SEND_TOUT_US       (30000)
#define TEST_RESP_TOUT_MS       (1000)

#if CONFIG_IDF_TARGET_ESP32
#define TEST_SER_PIN_RX         (22)
#define TEST_SER_PIN_TX         (23)
// RTS for RS485 Half-Duplex Mode manages DE/~RE
#define TEST_SER_PIN_RTS        (18)
#define TEST_BAUD_RATE          (115200)
#elif CONFIG_IDF_TARGET_ESP32C3
#define TEST_SER_PIN_RX         (4)
#define TEST_SER_PIN_TX         (5)
#define TEST_SER_PIN_RTS        (10)
#define TEST_BAUD_RATE          (115200)
#endif

#define TEST_MASTER_RESPOND_TOUT_MS CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND

// The workaround to statically link the whole test library
 __attribute__((unused)) bool mb_test_include_impl = 1;

#define TAG "MODBUS_SERIAL_COMM_TEST"

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

// Example Data (Object) Dictionary for Modbus parameters
static const mb_parameter_descriptor_t descriptors[] = {
    {CID_DEV_REG0, STR("MB_hold_reg-0"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 0, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG1, STR("MB_hold_reg-1"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 1, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG2, STR("MB_hold_reg-2"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 2, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG3, STR("MB_hold_reg-3"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 3, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG_COUNT, STR("CYCLE_COUNTER"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 4, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER}
};

// The number of parameters in the table
const uint16_t num_descriptors = (sizeof(descriptors) / sizeof(descriptors[0]));

static void test_task_start_wait_done(TaskHandle_t task_handle)
{
    uint32_t test_task = 0;

    // Start test sequence intentionally in the task
    test_common_task_notify_start(task_handle, 1);
    
    for (int i = 0; (i < 2); i++) {
        test_task = test_common_wait_done(pdMS_TO_TICKS(TEST_TASK_TIMEOUT_MS));
        if (test_task == (uint32_t)task_handle) {
            unity_utils_task_delete((TaskHandle_t)test_task);
            break;
        }
    }
    
    vTaskDelay(5); // A small delay to let the test lower priority task delete itself
    if (test_task != (uint32_t)task_handle) {
        ESP_LOGI(TAG, "Could not complete task 0x%" PRIx32" after %d ms, force kill the task.", 
                        (uint32_t)task_handle, TEST_TASK_TIMEOUT_MS);
        unity_utils_task_delete((TaskHandle_t)task_handle);
    }

    TEST_ASSERT_EQUAL(test_task, (uint32_t)task_handle);
    ESP_LOGI(TAG, "Test task 0x%" PRIx32 ", done successfully.", (uint32_t)task_handle);
}

static void test_modbus_rs485_rtu_slave(void)
{
    mb_communication_info_t slave_config1 = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_RTU,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1,
        .ser_opts.baudrate = TEST_BAUD_RATE,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_SEND_TOUT_US
    };
    
    TEST_ESP_OK(uart_set_pin(slave_config1.ser_opts.port, TEST_SER_PIN_TX, 
                                TEST_SER_PIN_RX, TEST_SER_PIN_RTS, UART_PIN_NO_CHANGE));

    TaskHandle_t slave_task_handle = test_slave_serial_create(&slave_config1);

    // Set driver mode to Half Duplex
    TEST_ESP_OK(uart_set_mode(slave_config1.ser_opts.port, UART_MODE_RS485_HALF_DUPLEX));

    ESP_LOGI(TAG, "Slave RTU is started. (%s).", __func__);

    unity_send_signal("Slave_ready");
    unity_wait_for_signal("Master_started");

    test_task_start_wait_done(slave_task_handle);

}

static void test_modbus_rs485_rtu_master(void)
{
    ESP_LOGI(TAG, "Master RTU is started (%s).", __func__);
    unity_wait_for_signal("Slave_ready");
    unity_send_signal("Master_started");

    // Initialize and start Modbus controller
    mb_communication_info_t master_config = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_RTU,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1,
        .ser_opts.baudrate = TEST_BAUD_RATE,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_SEND_TOUT_US
    };

    TaskHandle_t master_task_handle = test_master_serial_create(&master_config, &descriptors[0], num_descriptors);

    // Set driver mode to Half Duplex
    TEST_ESP_OK(uart_set_mode(master_config.ser_opts.port, UART_MODE_RS485_HALF_DUPLEX));
    TEST_ESP_OK(uart_set_pin(master_config.ser_opts.port, TEST_SER_PIN_TX, 
                                TEST_SER_PIN_RX, TEST_SER_PIN_RTS, UART_PIN_NO_CHANGE));

    test_task_start_wait_done(master_task_handle);
}

/* 
 * Modbus RS485 RTU multi device test case
 */
TEST_CASE_MULTIPLE_DEVICES("Modbus RS485 RTU multi device master - slave case.", "[modbus][test_env=multi_dut_modbus_serial]", test_modbus_rs485_rtu_slave, test_modbus_rs485_rtu_master);

static void test_modbus_rs485_ascii_slave(void)
{
    mb_communication_info_t slave_config1 = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1,
        .ser_opts.baudrate = TEST_BAUD_RATE,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_SEND_TOUT_US
    };
    
    TEST_ESP_OK(uart_set_pin(slave_config1.ser_opts.port, TEST_SER_PIN_TX, 
                                TEST_SER_PIN_RX, TEST_SER_PIN_RTS, UART_PIN_NO_CHANGE));

    TaskHandle_t slave_task_handle = test_slave_serial_create(&slave_config1);

    // Set driver mode to Half Duplex
    TEST_ESP_OK(uart_set_mode(slave_config1.ser_opts.port, UART_MODE_RS485_HALF_DUPLEX));

    ESP_LOGI(TAG, "Slave ASCII is started. (%s).", __func__);

    unity_send_signal("Slave_ready");
    unity_wait_for_signal("Master_started");

    test_task_start_wait_done(slave_task_handle);

}

static void test_modbus_rs485_ascii_master(void)
{
    ESP_LOGI(TAG, "Master ASCII is started (%s).", __func__);
    unity_wait_for_signal("Slave_ready");

    // Initialize and start Modbus controller
    mb_communication_info_t master_config = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_ASCII,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1,
        .ser_opts.baudrate = TEST_BAUD_RATE,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_SEND_TOUT_US
    };

    TaskHandle_t master_task_handle = test_master_serial_create(&master_config, &descriptors[0], num_descriptors);

    // Set driver mode to Half Duplex
    TEST_ESP_OK(uart_set_mode(master_config.ser_opts.port, UART_MODE_RS485_HALF_DUPLEX));
    TEST_ESP_OK(uart_set_pin(master_config.ser_opts.port, TEST_SER_PIN_TX, 
                                TEST_SER_PIN_RX, TEST_SER_PIN_RTS, UART_PIN_NO_CHANGE));
    
    unity_send_signal("Master_started");

    test_task_start_wait_done(master_task_handle);
}

/* 
 * Modbus RS485 ASCII multi device test case
 */
TEST_CASE_MULTIPLE_DEVICES("Modbus RS485 ASCII multi device master - slave case.", "[modbus][test_env=multi_dut_modbus_serial]", test_modbus_rs485_ascii_slave, test_modbus_rs485_ascii_master);


#endif