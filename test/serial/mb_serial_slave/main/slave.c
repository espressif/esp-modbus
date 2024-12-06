/*
 * SPDX-FileCopyrightText: 2016-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// FreeModbus Slave Example ESP32

#include <stdio.h>
#include <stdint.h>
#include "esp_err.h"
#include "mbcontroller.h"       // for mbcontroller defines and api
#include "modbus_params.h"      // for modbus parameters structures
#include "esp_log.h"            // for log_write
#include "sdkconfig.h"

#define MB_PORT_NUM     (CONFIG_MB_UART_PORT_NUM)   // Number of UART port used for Modbus connection
#define MB_SLAVE_ADDR   (CONFIG_MB_SLAVE_ADDR)      // The address of device in Modbus network
#define MB_DEV_SPEED    (CONFIG_MB_UART_BAUD_RATE)  // The communication speed of the UART

// Note: Some pins on target chip cannot be assigned for UART communication.
// Please refer to documentation for selected board and target to configure pins using Kconfig.

// Defines below are used to define register start address for each type of Modbus registers
#define HOLD_OFFSET(field) ((uint16_t)(offsetof(holding_reg_params_t, field) >> 1))
#define INPUT_OFFSET(field) ((uint16_t)(offsetof(input_reg_params_t, field) >> 1))
#define MB_REG_DISCRETE_INPUT_START         (0x0000)
#define MB_REG_COILS_START                  (0x0000)
#define MB_REG_INPUT_START_AREA0            (INPUT_OFFSET(input_data0)) // register offset input area 0
#define MB_REG_INPUT_START_AREA1            (INPUT_OFFSET(input_data4)) // register offset input area 1
#define MB_REG_HOLDING_START_AREA0          (HOLD_OFFSET(holding_data0))
#define MB_REG_HOLDING_START_AREA0_SIZE     ((size_t)((HOLD_OFFSET(holding_data4) - HOLD_OFFSET(holding_data0)) << 1))
#define MB_REG_HOLDING_START_AREA1          (HOLD_OFFSET(holding_data4))
#define MB_REG_HOLDING_START_AREA1_SIZE     ((size_t)((HOLD_OFFSET(holding_area1_end) - HOLD_OFFSET(holding_data4)) << 1))
#define MB_REG_HOLDING_START_AREA2          (HOLD_OFFSET(holding_u8_a))
#define MB_REG_HOLDING_START_AREA2_SIZE     ((size_t)((HOLD_OFFSET(holding_area2_end) - HOLD_OFFSET(holding_u8_a)) << 1))

#define MB_PAR_INFO_GET_TOUT                (10) // Timeout for get parameter info
#define MB_CHAN_DATA_MAX_VAL                (6)
#define MB_CHAN_DATA_OFFSET                 (0.2f)
#define MB_READ_MASK                        (MB_EVENT_INPUT_REG_RD \
                                                | MB_EVENT_HOLDING_REG_RD \
                                                | MB_EVENT_DISCRETE_RD \
                                                | MB_EVENT_COILS_RD)
#define MB_WRITE_MASK                       (MB_EVENT_HOLDING_REG_WR \
                                                | MB_EVENT_COILS_WR)
#define MB_READ_WRITE_MASK                  (MB_READ_MASK | MB_WRITE_MASK)
#define MB_TEST_VALUE 12345.0

static const char *TAG = "SLAVE_TEST";

static portMUX_TYPE param_lock = portMUX_INITIALIZER_UNLOCKED;

// Set register values into known state
static void setup_reg_data(void)
{
    // Define initial state of parameters
    discrete_reg_params.discrete_input0 = 1;
    discrete_reg_params.discrete_input1 = 0;
    discrete_reg_params.discrete_input2 = 1;
    discrete_reg_params.discrete_input3 = 0;
    discrete_reg_params.discrete_input4 = 1;
    discrete_reg_params.discrete_input5 = 0;
    discrete_reg_params.discrete_input6 = 1;
    discrete_reg_params.discrete_input7 = 0;

    holding_reg_params.holding_data0 = 1.34;
    holding_reg_params.holding_data1 = 2.56;
    holding_reg_params.holding_data2 = 3.78;
    holding_reg_params.holding_data3 = 4.90;

    holding_reg_params.holding_data4 = 5.67;
    holding_reg_params.holding_data5 = 6.78;
    holding_reg_params.holding_data6 = 7.79;
    holding_reg_params.holding_data7 = 8.80;

#if CONFIG_FMB_EXT_TYPE_SUPPORT
    mb_set_uint8_a((val_16_arr *)&holding_reg_params.holding_u8_a[0], (uint8_t)0x55);
    mb_set_uint8_a((val_16_arr *)&holding_reg_params.holding_u8_a[1], (uint8_t)0x55);
    mb_set_uint8_b((val_16_arr *)&holding_reg_params.holding_u8_b[0], (uint8_t)0x55);
    mb_set_uint8_b((val_16_arr *)&holding_reg_params.holding_u8_b[1], (uint8_t)0x55);
    mb_set_uint16_ab((val_16_arr *)&holding_reg_params.holding_u16_ab[1], (uint16_t)MB_TEST_VALUE);
    mb_set_uint16_ab((val_16_arr *)&holding_reg_params.holding_u16_ab[0], (uint16_t)MB_TEST_VALUE);
    mb_set_uint16_ba((val_16_arr *)&holding_reg_params.holding_u16_ba[0], (uint16_t)MB_TEST_VALUE);
    mb_set_uint16_ba((val_16_arr *)&holding_reg_params.holding_u16_ba[1], (uint16_t)MB_TEST_VALUE);

    mb_set_float_abcd((val_32_arr *)&holding_reg_params.holding_float_abcd[0], (float)MB_TEST_VALUE);
    mb_set_float_abcd((val_32_arr *)&holding_reg_params.holding_float_abcd[1], (float)MB_TEST_VALUE);
    mb_set_float_cdab((val_32_arr *)&holding_reg_params.holding_float_cdab[0], (float)MB_TEST_VALUE);
    mb_set_float_cdab((val_32_arr *)&holding_reg_params.holding_float_cdab[1], (float)MB_TEST_VALUE);
    mb_set_float_badc((val_32_arr *)&holding_reg_params.holding_float_badc[0], (float)MB_TEST_VALUE);
    mb_set_float_badc((val_32_arr *)&holding_reg_params.holding_float_badc[1], (float)MB_TEST_VALUE);
    mb_set_float_dcba((val_32_arr *)&holding_reg_params.holding_float_dcba[0], (float)MB_TEST_VALUE);
    mb_set_float_dcba((val_32_arr *)&holding_reg_params.holding_float_dcba[1], (float)MB_TEST_VALUE);

    mb_set_uint32_abcd((val_32_arr *)&holding_reg_params.holding_uint32_abcd[0], (uint32_t)MB_TEST_VALUE);
    mb_set_uint32_abcd((val_32_arr *)&holding_reg_params.holding_uint32_abcd[1], (uint32_t)MB_TEST_VALUE);
    mb_set_uint32_cdab((val_32_arr *)&holding_reg_params.holding_uint32_cdab[0], (uint32_t)MB_TEST_VALUE);
    mb_set_uint32_cdab((val_32_arr *)&holding_reg_params.holding_uint32_cdab[1], (uint32_t)MB_TEST_VALUE);
    mb_set_uint32_badc((val_32_arr *)&holding_reg_params.holding_uint32_badc[0], (uint32_t)MB_TEST_VALUE);
    mb_set_uint32_badc((val_32_arr *)&holding_reg_params.holding_uint32_badc[1], (uint32_t)MB_TEST_VALUE);
    mb_set_uint32_dcba((val_32_arr *)&holding_reg_params.holding_uint32_dcba[0], (uint32_t)MB_TEST_VALUE);
    mb_set_uint32_dcba((val_32_arr *)&holding_reg_params.holding_uint32_dcba[1], (uint32_t)MB_TEST_VALUE);

    mb_set_double_abcdefgh((val_64_arr *)&holding_reg_params.holding_double_abcdefgh[0], (double)MB_TEST_VALUE);
    mb_set_double_abcdefgh((val_64_arr *)&holding_reg_params.holding_double_abcdefgh[1], (double)MB_TEST_VALUE);
    mb_set_double_hgfedcba((val_64_arr *)&holding_reg_params.holding_double_hgfedcba[0], (double)MB_TEST_VALUE);
    mb_set_double_hgfedcba((val_64_arr *)&holding_reg_params.holding_double_hgfedcba[1], (double)MB_TEST_VALUE);
    mb_set_double_ghefcdab((val_64_arr *)&holding_reg_params.holding_double_ghefcdab[0], (double)MB_TEST_VALUE);
    mb_set_double_ghefcdab((val_64_arr *)&holding_reg_params.holding_double_ghefcdab[1], (double)MB_TEST_VALUE);
    mb_set_double_badcfehg((val_64_arr *)&holding_reg_params.holding_double_badcfehg[0], (double)MB_TEST_VALUE);
    mb_set_double_badcfehg((val_64_arr *)&holding_reg_params.holding_double_badcfehg[1], (double)MB_TEST_VALUE);
#endif

    coil_reg_params.coils_port0 = 0x55;
    coil_reg_params.coils_port1 = 0xAA;

    input_reg_params.input_data0 = 1.12;
    input_reg_params.input_data1 = 2.34;
    input_reg_params.input_data2 = 3.56;
    input_reg_params.input_data3 = 4.78;

    input_reg_params.input_data4 = 1.12;
    input_reg_params.input_data5 = 2.34;
    input_reg_params.input_data6 = 3.56;
    input_reg_params.input_data7 = 4.78;
}

// This is the way to expose the funcion to set slave ID .
// The related function is vendor specific and stack by default hides this functionality from user.
extern int eMBSetSlaveID(uint8_t slave_id, bool is_running, uint8_t const *pdata, uint16_t data_len);

// An example application of Modbus slave. It is based on freemodbus stack.
// See deviceparams.h file for more information about assigned Modbus parameters.
// These parameters can be accessed from main application and also can be changed
// by external Modbus master host.
void app_main(void)
{
    mb_param_info_t reg_info; // keeps the Modbus registers access information
    mb_communication_info_t comm_info; // Modbus communication parameters
    mb_register_area_descriptor_t reg_area; // Modbus register area descriptor structure

    // Set UART log level
    esp_log_level_set(TAG, ESP_LOG_INFO);
    void* mbc_slave_handler = NULL;

    ESP_ERROR_CHECK(mbc_slave_init(MB_PORT_SERIAL_SLAVE, &mbc_slave_handler)); // Initialization of Modbus controller

    // Setup communication parameters and start stack
#if CONFIG_MB_COMM_MODE_ASCII
    comm_info.mode = MB_MODE_ASCII;
#elif CONFIG_MB_COMM_MODE_RTU
    comm_info.mode = MB_MODE_RTU;
#endif
    comm_info.slave_addr = MB_SLAVE_ADDR;
    comm_info.port = MB_PORT_NUM;
    comm_info.baudrate = MB_DEV_SPEED;
    comm_info.parity = MB_PARITY_NONE;
    ESP_ERROR_CHECK(mbc_slave_setup((void*)&comm_info));

    // The code below initializes Modbus register area descriptors
    // for Modbus Holding Registers, Input Registers, Coils and Discrete Inputs
    // Initialization should be done for each supported Modbus register area according to register map.
    // When external master trying to access the register in the area that is not initialized
    // by mbc_slave_set_descriptor() API call then Modbus stack
    // will send exception response for this register area.
    reg_area.type = MB_PARAM_HOLDING; // Set type of register area
    reg_area.start_offset = MB_REG_HOLDING_START_AREA0; // Offset of register area in Modbus protocol
    reg_area.address = (void*)&holding_reg_params.holding_data0; // Set pointer to storage instance
    // Set the size of register storage instance in bytes
    reg_area.size = MB_REG_HOLDING_START_AREA0_SIZE;
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(reg_area));
    
    // The second register area
    reg_area.type = MB_PARAM_HOLDING; // Set type of register area
    reg_area.start_offset = MB_REG_HOLDING_START_AREA1;
    reg_area.address = (void*)&holding_reg_params.holding_data4;
    reg_area.size = MB_REG_HOLDING_START_AREA1_SIZE;
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(reg_area));

#if CONFIG_FMB_EXT_TYPE_SUPPORT
    // The extended parameters register area
    reg_area.type = MB_PARAM_HOLDING;
    reg_area.start_offset = MB_REG_HOLDING_START_AREA2;
    reg_area.address = (void*)&holding_reg_params.holding_u8_a;
    reg_area.size = MB_REG_HOLDING_START_AREA2_SIZE;
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(reg_area));
#endif

    // Initialization of Input Registers area
    reg_area.type = MB_PARAM_INPUT;
    reg_area.start_offset = MB_REG_INPUT_START_AREA0;
    reg_area.address = (void*)&input_reg_params.input_data0;
    reg_area.size = sizeof(float) << 2;
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(reg_area));
    
    reg_area.type = MB_PARAM_INPUT;
    reg_area.start_offset = MB_REG_INPUT_START_AREA1;
    reg_area.address = (void*)&input_reg_params.input_data4;
    reg_area.size = sizeof(float) << 2;
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(reg_area));

    // Initialization of Coils register area
    reg_area.type = MB_PARAM_COIL;
    reg_area.start_offset = MB_REG_COILS_START;
    reg_area.address = (void*)&coil_reg_params;
    reg_area.size = sizeof(coil_reg_params);
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(reg_area));

    // Initialization of Discrete Inputs register area
    reg_area.type = MB_PARAM_DISCRETE;
    reg_area.start_offset = MB_REG_DISCRETE_INPUT_START;
    reg_area.address = (void*)&discrete_reg_params;
    reg_area.size = sizeof(discrete_reg_params);
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(reg_area));

    setup_reg_data(); // Set values into known state

    // Starts of modbus controller and stack
    ESP_ERROR_CHECK(mbc_slave_start());

    // Set UART pin numbers
    ESP_ERROR_CHECK(uart_set_pin(MB_PORT_NUM, CONFIG_MB_UART_TXD,
                            CONFIG_MB_UART_RXD, CONFIG_MB_UART_RTS,
                            UART_PIN_NO_CHANGE));

    // Set UART driver mode to Half Duplex
    ESP_ERROR_CHECK(uart_set_mode(MB_PORT_NUM, UART_MODE_RS485_HALF_DUPLEX));

    ESP_LOGI(TAG, "Modbus slave stack initialized.");
    ESP_LOGI(TAG, "Start modbus test...");

    uint8_t ext_data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    // This is the way to set Slave ID fields to retrieve it by master using report slave ID command.
    int err = eMBSetSlaveID(comm_info.slave_addr, true, (uint8_t *)&ext_data, sizeof(ext_data));
    if (!err) {
        ESP_LOG_BUFFER_HEX_LEVEL("SET_SLAVE_ID", (void*)ext_data, sizeof(ext_data), ESP_LOG_WARN);
    } else {
        ESP_LOGE("SET_SLAVE_ID", "Set slave ID fail, err=%d.", err);
    }

    // The cycle below will be terminated when parameter holdingRegParams.dataChan0
    // incremented each access cycle reaches the CHAN_DATA_MAX_VAL value.
    for(;holding_reg_params.holding_data0 < MB_CHAN_DATA_MAX_VAL;) {
        // Check for read/write events of Modbus master for certain events
        (void)mbc_slave_check_event(MB_READ_WRITE_MASK);
        ESP_ERROR_CHECK_WITHOUT_ABORT(mbc_slave_get_param_info(&reg_info, MB_PAR_INFO_GET_TOUT));
        const char* rw_str = (reg_info.type & MB_READ_MASK) ? "READ" : "WRITE";

        // Filter events and process them accordingly
        if(reg_info.type & (MB_EVENT_HOLDING_REG_WR | MB_EVENT_HOLDING_REG_RD)) {
            // Get parameter information from parameter queue
            ESP_LOGI(TAG, "HOLDING %s (%" PRIu32 " us), ADDR:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 ", SIZE:%u",
                            rw_str,
                            reg_info.time_stamp,
                            (unsigned)reg_info.mb_offset,
                            (unsigned)reg_info.type,
                            (uint32_t)reg_info.address,
                            (unsigned)reg_info.size);
            if (reg_info.address == (uint8_t*)&holding_reg_params.holding_data0) {
                portENTER_CRITICAL(&param_lock);
                holding_reg_params.holding_data0 += MB_CHAN_DATA_OFFSET;
                if (holding_reg_params.holding_data0 >= (MB_CHAN_DATA_MAX_VAL - MB_CHAN_DATA_OFFSET)) {
                    coil_reg_params.coils_port1 = 0xFF;
                }
                portEXIT_CRITICAL(&param_lock);
            }
        } else if (reg_info.type & MB_EVENT_INPUT_REG_RD) {
            ESP_LOGI(TAG, "INPUT READ (%" PRIu32 " us), ADDR:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 ", SIZE:%u",
                            reg_info.time_stamp,
                            (unsigned)reg_info.mb_offset,
                            (unsigned)reg_info.type,
                            (uint32_t)reg_info.address,
                            (unsigned)reg_info.size);
        } else if (reg_info.type & MB_EVENT_DISCRETE_RD) {
            ESP_LOGI(TAG, "DISCRETE READ (%" PRIu32 " us): ADDR:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 ", SIZE:%u",
                            reg_info.time_stamp,
                            (unsigned)reg_info.mb_offset,
                            (unsigned)reg_info.type,
                            (uint32_t)reg_info.address,
                            (unsigned)reg_info.size);
        } else if (reg_info.type & (MB_EVENT_COILS_RD | MB_EVENT_COILS_WR)) {
            ESP_LOGI(TAG, "COILS %s (%" PRIu32 " us), ADDR:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 ", SIZE:%u",
                            rw_str,
                            reg_info.time_stamp,
                            (unsigned)reg_info.mb_offset,
                            (unsigned)reg_info.type,
                            (uint32_t)reg_info.address,
                            (unsigned)reg_info.size);
            if (coil_reg_params.coils_port1 == 0xFF) break;
        }
    }
    // Destroy of Modbus controller on alarm
    ESP_LOGI(TAG,"Modbus controller destroyed.");
    vTaskDelay(100);
    ESP_ERROR_CHECK(mbc_slave_destroy());
}
