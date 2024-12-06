/*
 * SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "string.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "modbus_params.h"  // for modbus parameters structures
#include "mbcontroller.h"
#include "sdkconfig.h"

#define MB_PORT_NUM     (CONFIG_MB_UART_PORT_NUM)   // Number of UART port used for Modbus connection
#define MB_DEV_SPEED    (CONFIG_MB_UART_BAUD_RATE)  // The communication speed of the UART

// Note: Some pins on target chip cannot be assigned for UART communication.
// See UART documentation for selected board and target to configure pins using Kconfig.

// The number of parameters that intended to be used in the particular control process
#define MASTER_MAX_CIDS num_device_parameters

// Number of reading of parameters from slave
#define MASTER_MAX_RETRY 10

// Timeout to update cid over Modbus
#define UPDATE_CIDS_TIMEOUT_MS          (500)
#define UPDATE_CIDS_TIMEOUT_TICS        (UPDATE_CIDS_TIMEOUT_MS / portTICK_PERIOD_MS)

// Timeout between polls
#define POLL_TIMEOUT_MS                 (1)
#define POLL_TIMEOUT_TICS               (POLL_TIMEOUT_MS / portTICK_PERIOD_MS)

// The macro to get offset for parameter in the appropriate structure
#define HOLD_OFFSET(field) ((uint16_t)(offsetof(holding_reg_params_t, field) + 1))
#define INPUT_OFFSET(field) ((uint16_t)(offsetof(input_reg_params_t, field) + 1))
#define COIL_OFFSET(field) ((uint16_t)(offsetof(coil_reg_params_t, field) + 1))
// Discrete offset macro
#define DISCR_OFFSET(field) ((uint16_t)(offsetof(discrete_reg_params_t, field) + 1))

#define STR(fieldname) ((const char *)( fieldname ))
#define TEST_HOLD_REG_START(field) (HOLD_OFFSET(field) >> 1)
#define TEST_HOLD_REG_SIZE(field) (sizeof(((holding_reg_params_t *)0)->field) >> 1)

#define TEST_INPUT_REG_START(field) (INPUT_OFFSET(field) >> 1)
#define TEST_INPUT_REG_SIZE(field) (sizeof(((input_reg_params_t *)0)->field) >> 1)

#define TEST_VALUE 12345 // default test value
#define TEST_ASCII_BIN 0xAAAAAAAA

// Options can be used as bit masks or parameter limits
#define OPTS(min_val, max_val, step_val) { .opt1 = min_val, .opt2 = max_val, .opt3 = step_val }

#define EACH_ITEM(array, length) \
(typeof(*(array)) *pitem = (array); (pitem < &((array)[length])); pitem++)

static const char *TAG = "MASTER_TEST";

// Enumeration of modbus device addresses accessed by master device
enum {
    MB_DEVICE_ADDR1 = 1 // Only one slave device used for the test (add other slave addresses here)
};

// Enumeration of all supported CIDs for device (used in parameter definition table)
enum {
    CID_INP_DATA_0 = 0,
    CID_HOLD_DATA_0,
    CID_INP_DATA_1,
    CID_HOLD_DATA_1,
    CID_INP_DATA_2,
    CID_HOLD_DATA_2,
    CID_HOLD_TEST_REG,
    CID_RELAY_P1,
    CID_RELAY_P2,
    CID_DISCR_P1,
#if CONFIG_FMB_EXT_TYPE_SUPPORT
    CID_HOLD_U8_A,
    CID_HOLD_U8_B,
    CID_HOLD_U16_AB,
    CID_HOLD_U16_BA,
    CID_HOLD_UINT32_ABCD,
    CID_HOLD_UINT32_CDAB,
    CID_HOLD_UINT32_BADC,
    CID_HOLD_UINT32_DCBA,
    CID_HOLD_FLOAT_ABCD,
    CID_HOLD_FLOAT_CDAB,
    CID_HOLD_FLOAT_BADC,
    CID_HOLD_FLOAT_DCBA,
    CID_HOLD_DOUBLE_ABCDEFGH,
    CID_HOLD_DOUBLE_HGFEDCBA,
    CID_HOLD_DOUBLE_GHEFCDAB,
    CID_HOLD_DOUBLE_BADCFEHG,
#endif
    CID_COUNT
};

// Example Data (Object) Dictionary for Modbus parameters:
// The CID field in the table must be unique.
// Modbus Slave Addr field defines slave address of the device with correspond parameter.
// Modbus Reg Type - Type of Modbus register area (Holding register, Input Register and such).
// Reg Start field defines the start Modbus register number and Reg Size defines the number of registers for the characteristic accordingly.
// The Instance Offset defines offset in the appropriate parameter structure that will be used as instance to save parameter value.
// Data Type, Data Size specify type of the characteristic and its data size.
// Parameter Options field specifies the options that can be used to process parameter value (limits or masks).
// Access Mode - can be used to implement custom options for processing of characteristic (Read/Write restrictions, factory mode values and etc).
const mb_parameter_descriptor_t device_parameters[] = {
    // { CID, Param Name, Units, Modbus Slave Addr, Modbus Reg Type, Reg Start, Reg Size, Instance Offset, Data Type, Data Size, Parameter Options, Access Mode}
    { CID_INP_DATA_0, STR("Data_channel_0"), STR("Volts"), MB_DEVICE_ADDR1, MB_PARAM_INPUT,
            TEST_INPUT_REG_START(input_data0), TEST_INPUT_REG_SIZE(input_data0),
            INPUT_OFFSET(input_data0), PARAM_TYPE_FLOAT, 4,
            OPTS( 0, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DATA_0, STR("Humidity_1"), STR("%rH"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_data0), TEST_HOLD_REG_SIZE(holding_data0),
            HOLD_OFFSET(holding_data0), PARAM_TYPE_FLOAT, 4,
            OPTS( 0, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_INP_DATA_1, STR("Temperature_1"), STR("C"), MB_DEVICE_ADDR1, MB_PARAM_INPUT,
            TEST_INPUT_REG_START(input_data1), TEST_INPUT_REG_SIZE(input_data1),
            INPUT_OFFSET(input_data1), PARAM_TYPE_FLOAT, 4,
            OPTS( -40, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DATA_1, STR("Humidity_2"), STR("%rH"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_data1), TEST_HOLD_REG_SIZE(holding_data1),
            HOLD_OFFSET(holding_data1), PARAM_TYPE_FLOAT, 4,
            OPTS( 0, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_INP_DATA_2, STR("Temperature_2"), STR("C"), MB_DEVICE_ADDR1, MB_PARAM_INPUT,
            TEST_INPUT_REG_START(input_data2), TEST_INPUT_REG_SIZE(input_data2),
            INPUT_OFFSET(input_data2), PARAM_TYPE_FLOAT, 4,
            OPTS( -40, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DATA_2, STR("Humidity_3"), STR("%rH"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_data2), TEST_HOLD_REG_SIZE(holding_data2),
            HOLD_OFFSET(holding_data2), PARAM_TYPE_FLOAT, 4, 
            OPTS( 0, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_TEST_REG, STR("Test_regs"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(test_regs), 58,
            HOLD_OFFSET(test_regs), PARAM_TYPE_ASCII, 116, 
            OPTS( 0, 100, TEST_ASCII_BIN ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_RELAY_P1, STR("RelayP1"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_COIL, 2, 6,
            COIL_OFFSET(coils_port0), PARAM_TYPE_U8, 1, 
            OPTS( 0xAA, 0x15, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_RELAY_P2, STR("RelayP2"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_COIL, 10, 6,
            COIL_OFFSET(coils_port1), PARAM_TYPE_U8, 1, 
            OPTS( 0x55, 0x2A, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_DISCR_P1, STR("DiscreteInpP1"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_DISCRETE, 2, 7,
            DISCR_OFFSET(discrete_input_port1), PARAM_TYPE_U8, 1, 
            OPTS( 0xAA, 0x15, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
#if CONFIG_FMB_EXT_TYPE_SUPPORT
    { CID_HOLD_U8_A, STR("U8_A"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_u8_a), TEST_HOLD_REG_SIZE(holding_u8_a),
            HOLD_OFFSET(holding_u8_a), PARAM_TYPE_U8_A, (TEST_HOLD_REG_SIZE(holding_u8_a) << 1), 
            OPTS( CHAR_MIN, 0x0055, 0x0055 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_U8_B, STR("U8_B"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_u8_b), TEST_HOLD_REG_SIZE(holding_u8_b),
            HOLD_OFFSET(holding_u8_b), PARAM_TYPE_U8_B, (TEST_HOLD_REG_SIZE(holding_u8_b) << 1), 
            OPTS( 0, 0x5500, 0x5500 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_U16_AB, STR("U16_AB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_u16_ab), TEST_HOLD_REG_SIZE(holding_u16_ab),
            HOLD_OFFSET(holding_u16_ab), PARAM_TYPE_U16_AB, (TEST_HOLD_REG_SIZE(holding_u16_ab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_U16_BA, STR("U16_BA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_u16_ba), TEST_HOLD_REG_SIZE(holding_u16_ba),
            HOLD_OFFSET(holding_u16_ba), PARAM_TYPE_U16_BA, (TEST_HOLD_REG_SIZE(holding_u16_ab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_UINT32_ABCD, STR("UINT32_ABCD"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_uint32_abcd), TEST_HOLD_REG_SIZE(holding_uint32_abcd),
            HOLD_OFFSET(holding_uint32_abcd), PARAM_TYPE_U32_ABCD, (TEST_HOLD_REG_SIZE(holding_uint32_abcd) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_UINT32_CDAB, STR("UINT32_CDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_uint32_cdab), TEST_HOLD_REG_SIZE(holding_uint32_cdab),
            HOLD_OFFSET(holding_uint32_cdab), PARAM_TYPE_U32_CDAB, (TEST_HOLD_REG_SIZE(holding_uint32_cdab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_UINT32_BADC, STR("UINT32_BADC"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_uint32_badc), TEST_HOLD_REG_SIZE(holding_uint32_badc),
            HOLD_OFFSET(holding_uint32_badc), PARAM_TYPE_U32_BADC, (TEST_HOLD_REG_SIZE(holding_uint32_badc) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_UINT32_DCBA, STR("UINT32_DCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_uint32_dcba), TEST_HOLD_REG_SIZE(holding_uint32_dcba),
            HOLD_OFFSET(holding_uint32_dcba), PARAM_TYPE_U32_DCBA, (TEST_HOLD_REG_SIZE(holding_uint32_dcba) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_FLOAT_ABCD, STR("FLOAT_ABCD"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_float_abcd), TEST_HOLD_REG_SIZE(holding_float_abcd),
            HOLD_OFFSET(holding_float_abcd), PARAM_TYPE_FLOAT_ABCD, (TEST_HOLD_REG_SIZE(holding_float_abcd) << 1),
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_FLOAT_CDAB, STR("FLOAT_CDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_float_cdab), TEST_HOLD_REG_SIZE(holding_float_cdab),
            HOLD_OFFSET(holding_float_cdab), PARAM_TYPE_FLOAT_CDAB, (TEST_HOLD_REG_SIZE(holding_float_cdab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_FLOAT_BADC, STR("FLOAT_BADC"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_float_badc), TEST_HOLD_REG_SIZE(holding_float_badc),
            HOLD_OFFSET(holding_float_badc), PARAM_TYPE_FLOAT_BADC, (TEST_HOLD_REG_SIZE(holding_float_badc) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_FLOAT_DCBA, STR("FLOAT_DCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_float_dcba), TEST_HOLD_REG_SIZE(holding_float_dcba),
            HOLD_OFFSET(holding_float_dcba), PARAM_TYPE_FLOAT_DCBA, (TEST_HOLD_REG_SIZE(holding_float_dcba) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DOUBLE_ABCDEFGH, STR("DOUBLE_ABCDEFGH"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_double_abcdefgh), TEST_HOLD_REG_SIZE(holding_double_abcdefgh),
            HOLD_OFFSET(holding_double_abcdefgh), PARAM_TYPE_DOUBLE_ABCDEFGH, (TEST_HOLD_REG_SIZE(holding_double_abcdefgh) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DOUBLE_HGFEDCBA, STR("DOUBLE_HGFEDCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_double_hgfedcba), TEST_HOLD_REG_SIZE(holding_double_hgfedcba),
            HOLD_OFFSET(holding_double_hgfedcba), PARAM_TYPE_DOUBLE_HGFEDCBA, (TEST_HOLD_REG_SIZE(holding_double_hgfedcba) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DOUBLE_GHEFCDAB, STR("DOUBLE_GHEFCDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_double_ghefcdab), TEST_HOLD_REG_SIZE(holding_double_ghefcdab),
            HOLD_OFFSET(holding_double_ghefcdab), PARAM_TYPE_DOUBLE_GHEFCDAB, (TEST_HOLD_REG_SIZE(holding_double_ghefcdab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DOUBLE_BADCFEHG, STR("DOUBLE_BADCFEHG"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_double_badcfehg), TEST_HOLD_REG_SIZE(holding_double_badcfehg),
            HOLD_OFFSET(holding_double_badcfehg), PARAM_TYPE_DOUBLE_BADCFEHG, (TEST_HOLD_REG_SIZE(holding_double_badcfehg) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER }
#endif
};

// Calculate number of parameters in the table
const uint16_t num_device_parameters = (sizeof(device_parameters)/sizeof(device_parameters[0]));

// The function to get pointer to parameter storage (instance) according to parameter description table
static void* master_get_param_data(const mb_parameter_descriptor_t* param_descriptor)
{
    assert(param_descriptor != NULL);
    void* instance_ptr = NULL;
    if (param_descriptor->param_offset != 0) {
       switch(param_descriptor->mb_param_type)
       {
           case MB_PARAM_HOLDING:
               instance_ptr = ((void *)&holding_reg_params + param_descriptor->param_offset - 1);
               break;
           case MB_PARAM_INPUT:
               instance_ptr = ((void *)&input_reg_params + param_descriptor->param_offset - 1);
               break;
           case MB_PARAM_COIL:
               instance_ptr = ((void *)&coil_reg_params + param_descriptor->param_offset - 1);
               break;
           case MB_PARAM_DISCRETE:
               instance_ptr = ((void *)&discrete_reg_params + param_descriptor->param_offset - 1);
               break;
           default:
               instance_ptr = NULL;
               break;
       }
    } else {
        ESP_LOGE(TAG, "Wrong parameter offset for CID #%d", (int)param_descriptor->cid);
        assert(instance_ptr != NULL);
    }
    return instance_ptr;
}

#define TEST_VERIFY_VALUES(pdescr, pinst) (__extension__(                                           \
{                                                                                                   \
    assert(pinst);                                                                                  \
    assert(pdescr);                                                                                 \
    uint8_t type = 0;                                                                               \
    esp_err_t err = ESP_FAIL;                                                                       \
    err = mbc_master_get_parameter(pdescr->cid, (char *)pdescr->param_key,                          \
                                    (uint8_t *)pinst, &type);                                       \
    if (err == ESP_OK) {                                                                            \
        bool is_correct = true;                                                                     \
        if (pdescr->param_opts.opt3) {                                                              \
            for EACH_ITEM(pinst, pdescr->param_size / sizeof(*pitem)) {                             \
                if (*pitem != (typeof(*(pinst)))pdescr->param_opts.opt3) {                          \
                    *pitem = (typeof(*(pinst)))pdescr->param_opts.opt3;                             \
                    ESP_LOGD(TAG, "Characteristic #%d (%s), initialize to 0x%" PRIx16 ".",          \
                                (int)pdescr->cid,                                                   \
                                (char *)pdescr->param_key,                                          \
                                (uint16_t)pdescr->param_opts.opt3);                                 \
                    is_correct = false;                                                             \
                }                                                                                   \
            }                                                                                       \
        }                                                                                           \
        if (!is_correct) {                                                                          \
            ESP_LOGE(TAG, "Characteristic #%d (%s), initialize.",                                   \
                        (int)pdescr->cid,                                                           \
                        (char *)pdescr->param_key);                                                 \
            err = mbc_master_set_parameter(cid, (char *)pdescr->param_key,                          \
                                                (uint8_t *)pinst, &type);                           \
            if (err != ESP_OK) {                                                                    \
                ESP_LOGE(TAG, "Characteristic #%d (%s) write fail, err = 0x%x (%s).",               \
                            (int)pdescr->cid,                                                       \
                            (char *)pdescr->param_key,                                              \
                            (int)err,                                                               \
                            (char *)esp_err_to_name(err));                                          \
            } else {                                                                                \
                ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = (..) write successful.",          \
                        (int)pdescr->cid,                                                           \
                        (char *)pdescr->param_key,                                                  \
                        (char *)pdescr->param_units);                                               \
            }                                                                                       \
        }                                                                                           \
    } else {                                                                                        \
        ESP_LOGE(TAG, "Characteristic #%d (%s) read fail, err = 0x%x (%s).",                        \
                            (int)pdescr->cid,                                                       \
                            (char *)pdescr->param_key,                                              \
                            (int)err,                                                               \
                            (char *)esp_err_to_name(err));                                          \
    }                                                                                               \
    (err);                                                                                          \
}                                                                                                   \
))

// User operation function to read slave values and check alarm
static void master_operation_func(void *arg)
{
    esp_err_t err = ESP_OK;
    bool alarm_state = false;
    const mb_parameter_descriptor_t* param_descriptor = NULL;

    ESP_LOGI(TAG, "Start modbus test...");

    // Command - 17 (0x11) Report Slave ID (Serial Line only)
    // The command contains vendor specific data and should be interpreted accordingly.
    // This version of command handler needs to define the maximum number
    // of registers that can be returned from concrete slave (buffer size).
    // The returned slave info data will be stored into the `info_buf`.
    // Request fields: slave_addr - the UID of slave, reg_start - not used, 
    // reg_size = max size of buffer (registers).
    mb_param_request_t req = {.slave_addr = 1, .command = 0x11, 
                                .reg_start = 0, .reg_size = (CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE >> 1)};

    uint8_t info_buf[CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE] = {0};

    // This is the way to retrieve slave ID information from slave (vendor specific command = 0x11).
    err = mbc_master_send_request(&req, &info_buf[0]);
    if (err != ESP_OK) {
        ESP_LOGE("SLAVE_INFO", "Read slave info fail.");
    } else {
        ESP_LOG_BUFFER_HEX_LEVEL("SLAVE_INFO", (void*)info_buf, sizeof(info_buf), ESP_LOG_WARN);
    }

    for(uint16_t retry = 0; retry <= MASTER_MAX_RETRY && (!alarm_state); retry++) {
        // Read all found characteristics from slave(s)
        for (uint16_t cid = 0; (err != ESP_ERR_NOT_FOUND) && cid < MASTER_MAX_CIDS; cid++) {
            // Get data from parameters description table
            // and use this information to fill the characteristics description table
            // and having all required fields in just one table
            err = mbc_master_get_cid_info(cid, &param_descriptor);
            if ((err != ESP_ERR_NOT_FOUND) && (param_descriptor != NULL)) {
                void *temp_data_ptr = master_get_param_data(param_descriptor);
                assert(temp_data_ptr);
                if ((param_descriptor->param_type == PARAM_TYPE_ASCII) &&
                        (param_descriptor->cid == CID_HOLD_TEST_REG)) {
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint32_t *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = (0x%" PRIx32 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(uint32_t *)temp_data_ptr);
                    }
#if CONFIG_FMB_EXT_TYPE_SUPPORT
                } else if ((param_descriptor->cid >= CID_HOLD_U16_AB) 
                            && (param_descriptor->cid <= CID_HOLD_U16_BA)) {
                    // Check the uint16 parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint16_t *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = (0x%" PRIx16 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(uint16_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_U8_A) 
                            && (param_descriptor->cid <= CID_HOLD_U8_B)) {
                    // Check the uint8 parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint16_t *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = (0x%" PRIx16 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(uint16_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_UINT32_ABCD)
                            && (param_descriptor->cid <= CID_HOLD_UINT32_DCBA)) {
                    // Check the uint32 parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint32_t *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %" PRIu32 " (0x%" PRIx32 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(uint32_t *)temp_data_ptr,
                                        *(uint32_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_FLOAT_ABCD)
                            && (param_descriptor->cid <= CID_HOLD_FLOAT_DCBA)) {
                    // Check the float parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (float *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %f (0x%" PRIx32 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(float *)temp_data_ptr,
                                        *(uint32_t *)temp_data_ptr);
                    }
                } else if (param_descriptor->cid >= CID_HOLD_DOUBLE_ABCDEFGH) {
                    // Check the double parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (double *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %lf (0x%" PRIx64 ") read successful.",
                                    (int)param_descriptor->cid,
                                    (char *)param_descriptor->param_key,
                                    (char *)param_descriptor->param_units,
                                    *(double *)temp_data_ptr,
                                    *(uint64_t *)temp_data_ptr);
                    }
#endif
                } else  if (cid <= CID_HOLD_DATA_2) {
                    uint64_t start_timestamp = esp_timer_get_time(); // Get current timestamp in microseconds
                    if (TEST_VERIFY_VALUES(param_descriptor, (float *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %f (0x%" PRIx32 ") read successful.",
                                (int)param_descriptor->cid,
                                (char *)param_descriptor->param_key,
                                (char *)param_descriptor->param_units,
                                *(float *)temp_data_ptr,
                                *(uint32_t *)temp_data_ptr);
                    }
                    float value = *(float *)temp_data_ptr;
                    if (((value > param_descriptor->param_opts.max) ||
                        (value < param_descriptor->param_opts.min))) {
                            alarm_state = true;
                            break;
                    }
                    mb_trans_info_t tinfo = {0};
                    if (mbc_master_get_transaction_info(&tinfo) == ESP_OK) {
                        bool trans_is_expired = (tinfo.trans_id >= (start_timestamp + (CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND * 1000)));
                        ESP_LOGW("TRANS_INFO", "Id: %" PRIu64 ", Addr: %x, FC: 0x%x, Exception: %u, Err: %u %s",
                                    (uint64_t)tinfo.trans_id, (int)tinfo.dest_addr,
                                    (int)tinfo.func_code, (unsigned)tinfo.exception,
                                    (int)tinfo.err_type,
                                    trans_is_expired ? "(EXPIRED)" : "");
                        // Check if the response time is expired sinse start of transaction,
                        // or the other IO is performed from different thread.
                        if (trans_is_expired) {
                            ESP_LOGE("TRANS_INFO", "Transaction Id: %" PRIu64 ", is expired.", tinfo.trans_id);
                            alarm_state = true;
                            break;
                        }
                    }
                } else if ((cid >= CID_RELAY_P1) && (cid <= CID_DISCR_P1)) {
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint8_t *)temp_data_ptr) == ESP_OK) {
                        uint8_t state = *(uint8_t *)temp_data_ptr;
                        const char* rw_str = (state & param_descriptor->param_opts.opt1) ? "ON" : "OFF";
                        if ((state & param_descriptor->param_opts.opt2) == param_descriptor->param_opts.opt2) {
                            ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %s (0x%" PRIx8 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        (const char *)rw_str,
                                        *(uint8_t *)temp_data_ptr);
                        } else {
                            ESP_LOGE(TAG, "Characteristic #%d %s (%s) value = %s (0x%" PRIx8 "), unexpected value.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        (const char *)rw_str,
                                        *(uint8_t *)temp_data_ptr);
                            alarm_state = true;
                            break;
                        }
                        if (state & param_descriptor->param_opts.opt1) {
                            alarm_state = true;
                            break;
                        }
                    }
                }
                vTaskDelay(POLL_TIMEOUT_TICS); // timeout between polls
            }
        }
        vTaskDelay(UPDATE_CIDS_TIMEOUT_TICS);
    }

    if (alarm_state) {
        ESP_LOGI(TAG, "Alarm triggered by cid #%d.",
                                        (int)param_descriptor->cid);
    } else {
        ESP_LOGE(TAG, "Alarm is not triggered after %d retries.",
                                        MASTER_MAX_RETRY);
    }
    ESP_LOGI(TAG, "Destroy master...");
    ESP_ERROR_CHECK(mbc_master_destroy());
}

// Modbus master initialization
static esp_err_t master_init(void)
{
    // Initialize and start Modbus controller
    mb_communication_info_t comm = {
            .port = MB_PORT_NUM,
#if CONFIG_MB_COMM_MODE_ASCII
            .mode = MB_MODE_ASCII,
#elif CONFIG_MB_COMM_MODE_RTU
            .mode = MB_MODE_RTU,
#endif
            .baudrate = MB_DEV_SPEED,
            .parity = MB_PARITY_NONE
    };
    void* master_handler = NULL;

    esp_err_t err = mbc_master_init(MB_PORT_SERIAL_MASTER, &master_handler);
    MB_RETURN_ON_FALSE((master_handler != NULL), ESP_ERR_INVALID_STATE, TAG,
                                "mb controller initialization fail.");
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "mb controller initialization fail, returns(0x%x).", (int)err);
    err = mbc_master_setup((void *)&comm);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "mb controller setup fail, returns(0x%x).", (int)err);

    // Set UART pin numbers
    err = uart_set_pin(MB_PORT_NUM, CONFIG_MB_UART_TXD, CONFIG_MB_UART_RXD,
                              CONFIG_MB_UART_RTS, UART_PIN_NO_CHANGE);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
            "mb serial set pin failure, uart_set_pin() returned (0x%x).", (int)err);
    err = mbc_master_start();
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "mb controller start fail, returned (0x%x).", (int)err);

    // Set driver mode to Half Duplex
    err = uart_set_mode(MB_PORT_NUM, UART_MODE_RS485_HALF_DUPLEX);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
            "mb serial set mode failure, uart_set_mode() returned (0x%x).", (int)err);

    vTaskDelay(5);
    err = mbc_master_set_descriptor(&device_parameters[0], num_device_parameters);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                                "mb controller set descriptor fail, returns(0x%x).", (int16_t)err);
    ESP_LOGI(TAG, "Modbus master stack initialized...");
    return err;
}

#define MB_PDU_DATA_OFF 1

#define EV_ERROR_EXECUTE_FUNCTION 3

void vMBMasterErrorCBUserHandler( uint64_t xTransId, uint16_t usError, uint8_t ucDestAddress, const uint8_t *pucRecvData, uint16_t ucRecvLength,
                                                        const uint8_t *pucSendData, uint16_t ucSendLength )
{
    ESP_LOGW("USER_ERR_CB", "The transaction %" PRIu64 ", error type: %u", xTransId, usError);
    if ((usError == EV_ERROR_EXECUTE_FUNCTION) && pucRecvData && ucRecvLength) {
        ESP_LOGW("USER_ERR_CB", "The command is unsupported or an exception on slave happened: %x", (int)pucRecvData[MB_PDU_DATA_OFF]);
    }
    if (pucRecvData && ucRecvLength) {
        ESP_LOG_BUFFER_HEX_LEVEL("Received buffer", (void *)pucRecvData, (uint16_t)ucRecvLength, ESP_LOG_WARN);
    }
    if (pucSendData && ucSendLength) {
        ESP_LOG_BUFFER_HEX_LEVEL("Sent buffer", (void *)pucSendData, (uint16_t)ucSendLength, ESP_LOG_WARN);
    }
}

void app_main(void)
{
    // Initialization of device peripheral and objects
    ESP_ERROR_CHECK(master_init());
    vTaskDelay(10);

    master_operation_func(NULL);
}
