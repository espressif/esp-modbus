/*
 * SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
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

#define TEST_SER_PORT_NUM               (1)
#define TEST_TASK_TIMEOUT_MS            (160000)
#define TEST_SEND_TOUT_US               (30000)
#define TEST_RESP_TOUT_MS               (1000)
#define TEST_BAUD_RATE                  (115200)

#if CONFIG_IDF_TARGET_ESP32
#define TEST_SER_PIN_RX                 (22)
#define TEST_SER_PIN_TX                 (23)
// RTS for RS485 Half-Duplex Mode manages DE/~RE
#define TEST_SER_PIN_RTS                (18)
#else
#define TEST_SER_PIN_RX                 (4)
#define TEST_SER_PIN_TX                 (5)
#define TEST_SER_PIN_RTS                (10)
#endif

#define TEST_MASTER_RESPOND_TOUT_MS     (CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND)

// The workaround to statically link the whole test library
__attribute__((unused)) bool mb_test_include_bcast_serial = true;

#define TAG "MODBUS_SERIAL_BROADCAST_TEST"

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

#define MB_DEVICE_ADDR0 0

// Example Data (Object) Dictionary for Modbus parameters
static const mb_parameter_descriptor_t descriptors[] = {
    {
        CID_DEV_REG0, STR("MB_hold_reg-0"), STR("Data"), MB_DEVICE_ADDR0, MB_PARAM_HOLDING, 0, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_DEV_REG1, STR("MB_hold_reg-1"), STR("Data"), MB_DEVICE_ADDR0, MB_PARAM_HOLDING, 1, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_DEV_REG2, STR("MB_hold_reg-2"), STR("Data"), MB_DEVICE_ADDR0, MB_PARAM_HOLDING, 2, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_DEV_REG3, STR("MB_hold_reg-3"), STR("Data"), MB_DEVICE_ADDR0, MB_PARAM_HOLDING, 3, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_DEV_REG_COUNT, STR("CYCLE_COUNTER"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 4, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER
    }
};

// The number of parameters in the table
const uint16_t num_descriptors = (sizeof(descriptors) / sizeof(descriptors[0]));

/**
 * @brief Helper sends broadcast request through the legacy public master API and checks the mapped error.
 */
static void test_send_broadcast_request(void *handle, uint8_t command, uint16_t reg_start,
                                        uint16_t reg_size, uint16_t wr_reg_start, uint16_t wr_reg_size,
                                        void *data_ptr, esp_err_t expected_err)
{
    mb_param_request_t req = {
        .slave_addr = 0,
        .command = command,
        .reg_start = reg_start,
        .reg_size = reg_size,
        .wr_rd_multi_reg_func = {
            .wr_reg_start = wr_reg_start,
            .wr_reg_size = wr_reg_size,
        }
    };

    ESP_LOGW(TAG, "Send broadcast command 0x%02x: start=%u size=%u wr_start=%u wr_size=%u, expect %s",
             command, (unsigned)reg_start, (unsigned)reg_size,
             (unsigned)wr_reg_start, (unsigned)wr_reg_size, esp_err_to_name(expected_err));

    esp_err_t err = mbc_master_send_request(handle, &req, data_ptr);
    if (err != expected_err) {
        ESP_LOGE(TAG, "Broadcast command 0x%02x returned %s, expected %s",
                 command, esp_err_to_name(err), esp_err_to_name(expected_err));
    }
    TEST_ESP_ERR(expected_err, err);
}

/**
 * @brief Command specific test for broadcast requests
 *
 * Read function codes are rejected in the request builder with MB_ENOREG, which
 * `mbc_master_send_request()` maps to ESP_ERR_NOT_SUPPORTED.
 * Write function codes are accepted for broadcast: the master waits the convert delay and
 * does not expect a slave response, so ESP_OK is the success path.
 * FC 0x17 is a mixed read/write command; the stack still sends it as broadcast
 * but cannot parse a read response, so ESP_ERR_INVALID_RESPONSE is expected.
 */
static void test_check_master_specific_requests(TaskHandle_t master_task_handle)
{
    void *handle = test_common_task_get_instance(master_task_handle);
    uint16_t reg = 0;
    uint8_t type = 0;

    esp_err_t err = mbc_master_get_parameter(handle, CID_DEV_REG0, (uint8_t *)&reg, &type);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Send broadcast read holding request fail, err = 0x%x (expected).", (int)err);
    }
    TEST_ESP_ERR(ESP_ERR_NOT_SUPPORTED, err); // Broadcast read request is not supported

    uint16_t command_data[] = { TEST_REG_VAL1, TEST_REG_VAL2, TEST_REG_VAL3, TEST_REG_VAL4 };
    uint16_t coil_on = 0xFF00;
    const uint16_t reg_count = (uint16_t)(sizeof(command_data) / sizeof(command_data[0]));
    const uint16_t coil_count = (uint16_t)(sizeof(command_data) * 8);

    // Verify standard handlers
    test_send_broadcast_request(handle, MB_FUNC_READ_COILS, 0, coil_count, 0, 0,
                                command_data, ESP_ERR_NOT_SUPPORTED);
    test_send_broadcast_request(handle, MB_FUNC_READ_DISCRETE_INPUTS, 0, coil_count, 0, 0,
                                command_data, ESP_ERR_NOT_SUPPORTED);
    test_send_broadcast_request(handle, MB_FUNC_READ_HOLDING_REGISTER, 0, reg_count, 0, 0,
                                command_data, ESP_ERR_NOT_SUPPORTED);
    test_send_broadcast_request(handle, MB_FUNC_READ_INPUT_REGISTER, 0, reg_count, 0, 0,
                                command_data, ESP_ERR_NOT_SUPPORTED);
    test_send_broadcast_request(handle, MB_FUNC_WRITE_SINGLE_COIL, 0, 1, 0, 0,
                                &coil_on, ESP_OK);
    test_send_broadcast_request(handle, MB_FUNC_WRITE_REGISTER, 0, 1, 0, 0,
                                command_data, ESP_OK);
    test_send_broadcast_request(handle, MB_FUNC_WRITE_MULTIPLE_COILS, 0, coil_count, 0, 0,
                                command_data, ESP_OK);
    test_send_broadcast_request(handle, MB_FUNC_WRITE_MULTIPLE_REGISTERS, 0, reg_count, 0, 0,
                                command_data, ESP_OK);
    test_send_broadcast_request(handle, MB_FUNC_READWRITE_MULTIPLE_REGISTERS, 0, reg_count, 0, reg_count,
                                command_data, ESP_ERR_INVALID_RESPONSE);
#if CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT
    test_send_broadcast_request(handle, MB_FUNC_OTHER_REPORT_SLAVEID, 0, 1, 0, 0,
                                command_data, ESP_ERR_INVALID_RESPONSE);
#endif
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

    TaskHandle_t slave_task_handle = test_common_slave_serial_create(&slave_config1, 0);

    // Set driver mode to Half Duplex
    TEST_ESP_OK(uart_set_mode(slave_config1.ser_opts.port, UART_MODE_RS485_HALF_DUPLEX));
    TEST_ESP_OK(uart_set_pin(slave_config1.ser_opts.port, TEST_SER_PIN_TX,
                             TEST_SER_PIN_RX, TEST_SER_PIN_RTS, UART_PIN_NO_CHANGE));

    ESP_LOGI(TAG, "Slave RTU is started. (%s).", __func__);

    unity_send_signal("Slave_ready");
    unity_wait_for_signal("Master_started");

    test_common_task_start(slave_task_handle, 1);
    TEST_ASSERT_TRUE(test_common_task_wait_done(slave_task_handle, pdMS_TO_TICKS(TEST_TASK_TIMEOUT_MS)));
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

    TaskHandle_t master_task_handle = test_common_master_serial_create(&master_config, 0, &descriptors[0], num_descriptors);

    // Set driver mode to Half Duplex
    TEST_ESP_OK(uart_set_mode(master_config.ser_opts.port, UART_MODE_RS485_HALF_DUPLEX));
    TEST_ESP_OK(uart_set_pin(master_config.ser_opts.port, TEST_SER_PIN_TX,
                             TEST_SER_PIN_RX, TEST_SER_PIN_RTS, UART_PIN_NO_CHANGE));

    /* Command specific test for broadcast requests */
    test_check_master_specific_requests(master_task_handle);

    /* The regular API test for broadcast requests:
     * sends broadcast 0x10 - Write multiple holding registers command,
     * then reads directly from slave with its UID,
     * and verifies the actual values of holding registers with expected ones.
     */
    test_common_task_start(master_task_handle, 1);

    TEST_ASSERT_TRUE(test_common_task_wait_done(master_task_handle, pdMS_TO_TICKS(TEST_TASK_TIMEOUT_MS)));
}

/*
 * Modbus RS485 RTU multi device test case
 */
TEST_CASE_MULTIPLE_DEVICES("Modbus RS485 RTU multi device broadcast case.", "[modbus][test_env=multi_dut_modbus_serial]", test_modbus_rs485_rtu_slave, test_modbus_rs485_rtu_master);

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

    TaskHandle_t slave_task_handle = test_common_slave_serial_create(&slave_config1, 0);

    TEST_ESP_OK(uart_set_pin(slave_config1.ser_opts.port, TEST_SER_PIN_TX,
                             TEST_SER_PIN_RX, TEST_SER_PIN_RTS, UART_PIN_NO_CHANGE));

    // Set driver mode to Half Duplex
    TEST_ESP_OK(uart_set_mode(slave_config1.ser_opts.port, UART_MODE_RS485_HALF_DUPLEX));

    ESP_LOGI(TAG, "Slave ASCII is started. (%s).", __func__);

    unity_send_signal("Slave_ready");
    unity_wait_for_signal("Master_started");

    test_common_task_start(slave_task_handle, 1);
    TEST_ASSERT_TRUE(test_common_task_wait_done(slave_task_handle, pdMS_TO_TICKS(TEST_TASK_TIMEOUT_MS)));
};

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

    TaskHandle_t master_task_handle = test_common_master_serial_create(&master_config, 0, &descriptors[0], num_descriptors);

    // Set driver mode to Half Duplex
    TEST_ESP_OK(uart_set_mode(master_config.ser_opts.port, UART_MODE_RS485_HALF_DUPLEX));
    TEST_ESP_OK(uart_set_pin(master_config.ser_opts.port, TEST_SER_PIN_TX,
                             TEST_SER_PIN_RX, TEST_SER_PIN_RTS, UART_PIN_NO_CHANGE));
    unity_send_signal("Master_started");

    /* Test for specific requests */
    test_check_master_specific_requests(master_task_handle);

    /* Test for regular API requests */
    test_common_task_start(master_task_handle, 1);
    TEST_ASSERT_TRUE(test_common_task_wait_done(master_task_handle, pdMS_TO_TICKS(TEST_TASK_TIMEOUT_MS)));
}

/*
 * Modbus RS485 ASCII multi device test case
 */
TEST_CASE_MULTIPLE_DEVICES("Modbus RS485 ASCII multi device broadcast case.", "[modbus][test_env=multi_dut_modbus_serial]", test_modbus_rs485_ascii_slave, test_modbus_rs485_ascii_master);


#endif
