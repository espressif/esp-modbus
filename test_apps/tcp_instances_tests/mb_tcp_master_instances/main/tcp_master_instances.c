/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include "unity.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "test_common.h"
#include "test_utils.h"
#include "esp_err.h"
#include "mbc_master.h"
#include "mbc_slave.h"

#include "nvs_flash.h"

#if MB_MDNS_IS_INCLUDED
#include "mdns.h"
#endif

#include "mbcontroller.h"       // for mbcontroller defines and api
#include "modbus_params.h"      // for modbus parameters structures

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
#define TEST_TCP_TASK_TIMEOUT_MS        (160000)
#define TEST_TCP_MASTER_SEND_TOUT_US    (500)
#define TEST_TASK_START_TIMEOUT     (10000 / portTICK_PERIOD_MS)
#define TEST_TASK_TICK_TIME         (50 / portTICK_PERIOD_MS)
#define TEST_TASK_NOTIFY_STOP_TOUT  (200 / portTICK_PERIOD_MS)

#define TEST_VALUE (12345) // default test value
#define TEST_ASCII_BIN (0xAAAAAAAA)
#define TEST_ARR_REG_SZ (58)
#define TEST_HUMI_MIN (-40)
#define TEST_HUMI_MAX (50)
#define TEST_TEMP_MIN (0)
#define TEST_TEMP_MAX (100)


// Number of reading of parameters from slave
#define MASTER_MAX_RETRY                (10)

// The number of parameters that intended to be used in the particular control process
#define MASTER_MAX_CIDS num_descriptors

// The macro to get offset for parameter in the appropriate structure
#define HOLD_OFFSET(field) ((uint16_t)(offsetof(holding_reg_params_t, field) + 1))
#define INPUT_OFFSET(field) ((uint16_t)(offsetof(input_reg_params_t, field) + 1))
#define COIL_OFFSET(field) ((uint16_t)(offsetof(coil_reg_params_t, field) + 1))
#define DISCR_OFFSET(field) ((uint16_t)(offsetof(discrete_reg_params_t, field) + 1))

#define TEST_HOLD_REG_START(field) (HOLD_OFFSET(field) >> 1)
#define TEST_HOLD_REG_SIZE(field) (sizeof(((holding_reg_params_t *)0)->field) >> 1)

#define TEST_INPUT_REG_START(field) (INPUT_OFFSET(field) >> 1)
#define TEST_INPUT_REG_SIZE(field) (sizeof(((input_reg_params_t *)0)->field) >> 1)

// Options can be used as bit masks or parameter limits
#define OPTS(min_val, max_val, step_val) { .opt1 = min_val, .opt2 = max_val, .opt3 = step_val }

#define EACH_ITEM(array, length) \
(typeof(*(array)) *pitem = (array); (pitem < &((array)[length])); pitem++)

#define TEST_MASTER_RESPOND_TOUT_MS     (CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND)

// The workaround to statically link the whole test library
__attribute__((unused)) bool mb_test_include_phys_impl_tcp = true;

#define TAG "MODBUS_TCP_COMM_MASTER_TEST"


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


// Example Data (Object) Dictionary for Modbus parameters
const mb_parameter_descriptor_t descriptors[] = {
    {
        CID_INP_DATA_0, STR("Data_channel_0"), STR("Volts"), MB_DEVICE_ADDR1, MB_PARAM_INPUT,
        TEST_INPUT_REG_START(input_data0), TEST_INPUT_REG_SIZE(input_data0),
        INPUT_OFFSET(input_data0), PARAM_TYPE_FLOAT, 4,
        OPTS( TEST_TEMP_MIN, TEST_TEMP_MAX, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_DATA_0, STR("Humidity_1"), STR("%rH"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_data0), TEST_HOLD_REG_SIZE(holding_data0),
        HOLD_OFFSET(holding_data0), PARAM_TYPE_FLOAT, 4,
        OPTS( TEST_HUMI_MIN, TEST_HUMI_MAX, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_INP_DATA_1, STR("Temperature_1"), STR("C"), MB_DEVICE_ADDR1, MB_PARAM_INPUT,
        TEST_INPUT_REG_START(input_data1), TEST_INPUT_REG_SIZE(input_data1),
        INPUT_OFFSET(input_data1), PARAM_TYPE_FLOAT, 4,
        OPTS( TEST_TEMP_MIN, TEST_TEMP_MAX, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_DATA_1, STR("Humidity_2"), STR("%rH"), MB_DEVICE_ADDR2, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_data1), TEST_HOLD_REG_SIZE(holding_data1),
        HOLD_OFFSET(holding_data1), PARAM_TYPE_FLOAT, 4,
        OPTS( TEST_HUMI_MIN, TEST_HUMI_MAX, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_INP_DATA_2, STR("Temperature_2"), STR("C"), MB_DEVICE_ADDR1, MB_PARAM_INPUT,
        TEST_INPUT_REG_START(input_data2), TEST_INPUT_REG_SIZE(input_data2),
        INPUT_OFFSET(input_data2), PARAM_TYPE_FLOAT, 4,
        OPTS( TEST_TEMP_MIN, TEST_TEMP_MAX, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_DATA_2, STR("Humidity_3"), STR("%rH"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_data2), TEST_HOLD_REG_SIZE(holding_data2),
        HOLD_OFFSET(holding_data2), PARAM_TYPE_FLOAT, 4,
        OPTS( TEST_HUMI_MIN, TEST_HUMI_MAX, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_TEST_REG, STR("Test_regs"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(test_regs), TEST_ARR_REG_SZ,
        HOLD_OFFSET(test_regs), PARAM_TYPE_ASCII, (TEST_ARR_REG_SZ * 2),
        OPTS( TEST_TEMP_MIN, TEST_TEMP_MAX, TEST_ASCII_BIN ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_RELAY_P1, STR("RelayP1"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_COIL, 2, 6,
        COIL_OFFSET(coils_port0), PARAM_TYPE_U8, 1,
        OPTS( 0xAA, 0x15, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_RELAY_P2, STR("RelayP2"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_COIL, 10, 6,
        COIL_OFFSET(coils_port1), PARAM_TYPE_U8, 1,
        OPTS( 0x55, 0x2A, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_DISCR_P1, STR("DiscreteInpP1"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_DISCRETE, 2, 7,
        DISCR_OFFSET(discrete_input_port1), PARAM_TYPE_U8, 1,
        OPTS( 0xAA, 0x15, 0 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
#if CONFIG_FMB_EXT_TYPE_SUPPORT
    {
        CID_HOLD_U8_A, STR("U8_A"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_u8_a), TEST_HOLD_REG_SIZE(holding_u8_a),
        HOLD_OFFSET(holding_u8_a), PARAM_TYPE_U8_A, (TEST_HOLD_REG_SIZE(holding_u8_a) << 1),
        OPTS( CHAR_MIN, 0x0055, 0x0055 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_U8_B, STR("U8_B"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_u8_b), TEST_HOLD_REG_SIZE(holding_u8_b),
        HOLD_OFFSET(holding_u8_b), PARAM_TYPE_U8_B, (TEST_HOLD_REG_SIZE(holding_u8_b) << 1),
        OPTS( 0, 0x5500, 0x5500 ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_U16_AB, STR("U16_AB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_u16_ab), TEST_HOLD_REG_SIZE(holding_u16_ab),
        HOLD_OFFSET(holding_u16_ab), PARAM_TYPE_U16_AB, (TEST_HOLD_REG_SIZE(holding_u16_ab) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_U16_BA, STR("U16_BA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_u16_ba), TEST_HOLD_REG_SIZE(holding_u16_ba),
        HOLD_OFFSET(holding_u16_ba), PARAM_TYPE_U16_BA, (TEST_HOLD_REG_SIZE(holding_u16_ab) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_UINT32_ABCD, STR("UINT32_ABCD"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_uint32_abcd), TEST_HOLD_REG_SIZE(holding_uint32_abcd),
        HOLD_OFFSET(holding_uint32_abcd), PARAM_TYPE_U32_ABCD, (TEST_HOLD_REG_SIZE(holding_uint32_abcd) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_UINT32_CDAB, STR("UINT32_CDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_uint32_cdab), TEST_HOLD_REG_SIZE(holding_uint32_cdab),
        HOLD_OFFSET(holding_uint32_cdab), PARAM_TYPE_U32_CDAB, (TEST_HOLD_REG_SIZE(holding_uint32_cdab) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_UINT32_BADC, STR("UINT32_BADC"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_uint32_badc), TEST_HOLD_REG_SIZE(holding_uint32_badc),
        HOLD_OFFSET(holding_uint32_badc), PARAM_TYPE_U32_BADC, (TEST_HOLD_REG_SIZE(holding_uint32_badc) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_UINT32_DCBA, STR("UINT32_DCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_uint32_dcba), TEST_HOLD_REG_SIZE(holding_uint32_dcba),
        HOLD_OFFSET(holding_uint32_dcba), PARAM_TYPE_U32_DCBA, (TEST_HOLD_REG_SIZE(holding_uint32_dcba) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_FLOAT_ABCD, STR("FLOAT_ABCD"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_float_abcd), TEST_HOLD_REG_SIZE(holding_float_abcd),
        HOLD_OFFSET(holding_float_abcd), PARAM_TYPE_FLOAT_ABCD, (TEST_HOLD_REG_SIZE(holding_float_abcd) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_FLOAT_CDAB, STR("FLOAT_CDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_float_cdab), TEST_HOLD_REG_SIZE(holding_float_cdab),
        HOLD_OFFSET(holding_float_cdab), PARAM_TYPE_FLOAT_CDAB, (TEST_HOLD_REG_SIZE(holding_float_cdab) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_FLOAT_BADC, STR("FLOAT_BADC"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_float_badc), TEST_HOLD_REG_SIZE(holding_float_badc),
        HOLD_OFFSET(holding_float_badc), PARAM_TYPE_FLOAT_BADC, (TEST_HOLD_REG_SIZE(holding_float_badc) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_FLOAT_DCBA, STR("FLOAT_DCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_float_dcba), TEST_HOLD_REG_SIZE(holding_float_dcba),
        HOLD_OFFSET(holding_float_dcba), PARAM_TYPE_FLOAT_DCBA, (TEST_HOLD_REG_SIZE(holding_float_dcba) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_DOUBLE_ABCDEFGH, STR("DOUBLE_ABCDEFGH"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_double_abcdefgh), TEST_HOLD_REG_SIZE(holding_double_abcdefgh),
        HOLD_OFFSET(holding_double_abcdefgh), PARAM_TYPE_DOUBLE_ABCDEFGH, (TEST_HOLD_REG_SIZE(holding_double_abcdefgh) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_DOUBLE_HGFEDCBA, STR("DOUBLE_HGFEDCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_double_hgfedcba), TEST_HOLD_REG_SIZE(holding_double_hgfedcba),
        HOLD_OFFSET(holding_double_hgfedcba), PARAM_TYPE_DOUBLE_HGFEDCBA, (TEST_HOLD_REG_SIZE(holding_double_hgfedcba) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_DOUBLE_GHEFCDAB, STR("DOUBLE_GHEFCDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_double_ghefcdab), TEST_HOLD_REG_SIZE(holding_double_ghefcdab),
        HOLD_OFFSET(holding_double_ghefcdab), PARAM_TYPE_DOUBLE_GHEFCDAB, (TEST_HOLD_REG_SIZE(holding_double_ghefcdab) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    },
    {
        CID_HOLD_DOUBLE_BADCFEHG, STR("DOUBLE_BADCFEHG"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
        TEST_HOLD_REG_START(holding_double_badcfehg), TEST_HOLD_REG_SIZE(holding_double_badcfehg),
        HOLD_OFFSET(holding_double_badcfehg), PARAM_TYPE_DOUBLE_BADCFEHG, (TEST_HOLD_REG_SIZE(holding_double_badcfehg) << 1),
        OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER
    }
#endif
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

// The function to get pointer to parameter storage (instance) according to parameter description table
void *master_get_param_data(const mb_parameter_descriptor_t *param_descriptor)
{
    assert(param_descriptor != NULL);
    void *instance_ptr = NULL;
    if (param_descriptor->param_offset != 0) {
        switch (param_descriptor->mb_param_type) {
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
        ESP_LOGE(TAG, "Wrong parameter offset for CID #%u", param_descriptor->cid);
        assert(instance_ptr != NULL);
    }
    return instance_ptr;
}


#define TEST_VERIFY_VALUES(handle, pdescr, pinst) (__extension__(                                   \
{                                                                                                   \
    assert(pinst);                                                                                  \
    assert(pdescr);                                                                                 \
    uint8_t type = 0;                                                                               \
    esp_err_t err = ESP_FAIL;                                                                       \
    err = mbc_master_get_parameter(handle, pdescr->cid, (uint8_t *)pinst, &type);                   \
    if (err == ESP_OK) {                                                                            \
        bool is_correct = true;                                                                     \
        if (pdescr->param_opts.opt3) {                                                              \
            for EACH_ITEM(pinst, pdescr->param_size / sizeof(*pitem)) {                             \
                if (*pitem != (typeof(*(pinst)))pdescr->param_opts.opt3) {                          \
                    *pitem = (typeof(*(pinst)))pdescr->param_opts.opt3;                             \
                    ESP_LOGD(TAG, "%p Characteristic #%d (%s), initialize to 0x%" PRIx16 ".",       \
                                handle,                                                             \
                                (int)pdescr->cid,                                                   \
                                (char *)pdescr->param_key,                                          \
                                (uint16_t)pdescr->param_opts.opt3);                                 \
                    is_correct = false;                                                             \
                }                                                                                   \
            }                                                                                       \
        }                                                                                           \
        if (!is_correct) {                                                                          \
            ESP_LOGE(TAG, "%p Characteristic #%d (%s), initialize.",                                \
                        handle,                                                                     \
                        (int)pdescr->cid,                                                           \
                        (char *)pdescr->param_key);                                                 \
            err = mbc_master_set_parameter(handle, cid, (uint8_t *)pinst, &type);                   \
            if (err != ESP_OK) {                                                                    \
                ESP_LOGE(TAG, "%p Characteristic #%d (%s) write fail, err = 0x%x (%s).",            \
                            handle,                                                                 \
                            (int)pdescr->cid,                                                       \
                            (char *)pdescr->param_key,                                              \
                            (int)err,                                                               \
                            (char *)esp_err_to_name(err));                                          \
            } else {                                                                                \
                ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = (..) write successful.",       \
                        handle,                                                                     \
                        (int)pdescr->cid,                                                           \
                        (char *)pdescr->param_key,                                                  \
                        (char *)pdescr->param_units);                                               \
            }                                                                                       \
        }                                                                                           \
    } else {                                                                                        \
        ESP_LOGE(TAG, "%p Characteristic #%d (%s) read fail, err = 0x%x (%s).",                     \
                            handle,                                                                 \
                            (int)pdescr->cid,                                                       \
                            (char *)pdescr->param_key,                                              \
                            (int)err,                                                               \
                            (char *)esp_err_to_name(err));                                          \
    }                                                                                               \
    (err);                                                                                          \
}                                                                                                   \
))


void func_task_master(void *arg)
{

    void *mbm_handle = arg;
    esp_err_t err = ESP_OK, request_err = ESP_OK;
    bool message_destroy_found = false;
    bool alarm_state = false;
    const mb_parameter_descriptor_t *param_descriptor = NULL;

    test_common_task_wait_start_and_stop(TEST_TASK_START_TIMEOUT);

    ESP_LOGI(TAG, "Start modbus test...");

    for (uint16_t retry = 0; retry <= MASTER_MAX_RETRY && (!alarm_state); retry++) {
        // Read all found characteristics from slave(s)
        for (uint16_t cid = 0; (err != ESP_ERR_NOT_FOUND) && cid < MASTER_MAX_CIDS; cid++) {

            if (test_common_task_wait_start_and_stop(TEST_TASK_NOTIFY_STOP_TOUT)) {
                ESP_LOGD(TAG, "Received destroy message, destroying instance: %p.", mbm_handle);
                message_destroy_found = true;
                break;
            }

            // Get data from parameters description table
            // and use this information to fill the characteristics description table
            // and having all required fields in just one table
            esp_err_t err = mbc_master_get_cid_info(mbm_handle, cid, &param_descriptor);
            if ((err != ESP_ERR_NOT_FOUND) && (param_descriptor != NULL)) {
                void *temp_data_ptr = master_get_param_data(param_descriptor);
                assert(temp_data_ptr);

                if ((param_descriptor->param_type == PARAM_TYPE_ASCII) &&
                        (param_descriptor->cid == CID_HOLD_TEST_REG)) {
                    request_err = TEST_VERIFY_VALUES(mbm_handle, param_descriptor, (uint32_t *)temp_data_ptr);
                    if (request_err == ESP_OK) {
                        ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = (0x%" PRIx32 ") read successful.",
                                 mbm_handle,
                                 (int)param_descriptor->cid,
                                 (char *)param_descriptor->param_key,
                                 (char *)param_descriptor->param_units,
                                 *(uint32_t *)temp_data_ptr);
                    }
#if CONFIG_FMB_EXT_TYPE_SUPPORT
                } else if ((param_descriptor->cid >= CID_HOLD_U16_AB)
                           && (param_descriptor->cid <= CID_HOLD_U16_BA)) {
                    // Check the uint16 parameters
                    request_err = TEST_VERIFY_VALUES(mbm_handle, param_descriptor, (uint16_t *)temp_data_ptr);
                    if (err == ESP_OK) {
                        ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = (0x%" PRIx16 ") read successful.",
                                 mbm_handle,
                                 (int)param_descriptor->cid,
                                 (char *)param_descriptor->param_key,
                                 (char *)param_descriptor->param_units,
                                 *(uint16_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_U8_A)
                           && (param_descriptor->cid <= CID_HOLD_U8_B)) {
                    // Check the uint8 parameters
                    request_err = TEST_VERIFY_VALUES(mbm_handle, param_descriptor, (uint16_t *)temp_data_ptr);
                    if (request_err == ESP_OK) {
                        ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = (0x%" PRIx16 ") read successful.",
                                 mbm_handle,
                                 (int)param_descriptor->cid,
                                 (char *)param_descriptor->param_key,
                                 (char *)param_descriptor->param_units,
                                 *(uint16_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_UINT32_ABCD)
                           && (param_descriptor->cid <= CID_HOLD_UINT32_DCBA)) {
                    // Check the uint32 parameters
                    request_err = TEST_VERIFY_VALUES(mbm_handle, param_descriptor, (uint32_t *)temp_data_ptr);
                    if (request_err == ESP_OK) {
                        ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = %" PRIu32 " (0x%" PRIx32 ") read successful.",
                                 mbm_handle,
                                 (int)param_descriptor->cid,
                                 (char *)param_descriptor->param_key,
                                 (char *)param_descriptor->param_units,
                                 *(uint32_t *)temp_data_ptr,
                                 *(uint32_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_FLOAT_ABCD)
                           && (param_descriptor->cid <= CID_HOLD_FLOAT_DCBA)) {
                    // Check the float parameters
                    request_err = TEST_VERIFY_VALUES(mbm_handle, param_descriptor, (float *)temp_data_ptr);
                    if (request_err == ESP_OK) {
                        ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = %f (0x%" PRIx32 ") read successful.",
                                 mbm_handle,
                                 (int)param_descriptor->cid,
                                 (char *)param_descriptor->param_key,
                                 (char *)param_descriptor->param_units,
                                 *(float *)temp_data_ptr,
                                 *(uint32_t *)temp_data_ptr);
                    }
                } else if (param_descriptor->cid >= CID_HOLD_DOUBLE_ABCDEFGH) {
                    // Check the double parameters
                    request_err = TEST_VERIFY_VALUES(mbm_handle, param_descriptor, (double *)temp_data_ptr);
                    if (request_err == ESP_OK) {
                        ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = %lf (0x%" PRIx64 ") read successful.",
                                 mbm_handle,
                                 (int)param_descriptor->cid,
                                 (char *)param_descriptor->param_key,
                                 (char *)param_descriptor->param_units,
                                 *(double *)temp_data_ptr,
                                 *(uint64_t *)temp_data_ptr);
                    }
#endif
                } else  if (cid <= CID_HOLD_DATA_2) {
                    request_err = TEST_VERIFY_VALUES(mbm_handle, param_descriptor, (float *)temp_data_ptr);
                    if (request_err == ESP_OK) {
                        ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = %f (0x%" PRIx32 ") read successful.",
                                 mbm_handle,
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
                } else if ((cid >= CID_RELAY_P1) && (cid <= CID_DISCR_P1)) {
                    request_err = TEST_VERIFY_VALUES(mbm_handle, param_descriptor, (uint8_t *)temp_data_ptr);
                    if (request_err == ESP_OK) {
                        uint8_t state = *(uint8_t *)temp_data_ptr;
                        const char *rw_str = (state & param_descriptor->param_opts.opt1) ? "ON" : "OFF";
                        if ((state & param_descriptor->param_opts.opt2) == param_descriptor->param_opts.opt2) {
                            ESP_LOGI(TAG, "%p Characteristic #%d %s (%s) value = %s (0x%" PRIx8 ") read successful.",
                                     mbm_handle,
                                     (int)param_descriptor->cid,
                                     (char *)param_descriptor->param_key,
                                     (char *)param_descriptor->param_units,
                                     (const char *)rw_str,
                                     *(uint8_t *)temp_data_ptr);
                        } else {
                            ESP_LOGE(TAG, "%p Characteristic #%d %s (%s) value = %s (0x%" PRIx8 "), unexpected value.",
                                     mbm_handle,
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

                if (request_err != ESP_OK) {
                    alarm_state = true;
                    break;
                }
            }

        }

        if (message_destroy_found) {
            break;
        }

        vTaskDelay(TEST_TASK_TICK_TIME); // Let the IDLE task to trigger
        if ((retry == MASTER_MAX_RETRY - 1) || alarm_state) {
            ESP_LOGI(TAG, "Alarm triggered by cid #%u.", param_descriptor->cid);
            alarm_state = false;
            break;
        }

    }
    ESP_LOGI(TAG, "Destroy master, inst: %p.", mbm_handle);
    TEST_ESP_OK(mbc_master_delete(mbm_handle));
    test_common_task_notify_done(xTaskGetCurrentTaskHandle());
    vTaskSuspend(NULL);
}


TaskHandle_t master_tcp_create_instance(mb_communication_info_t *pconfig, uint32_t priority, const mb_parameter_descriptor_t *pdescr, uint16_t descr_size)
{
    if (!pconfig || !pdescr) {
        ESP_LOGI(TAG, "invalid master configuration.");
    }

    void *mbm_handle = NULL;
    TaskHandle_t master_task_handle = NULL;

    TEST_ESP_OK(mbc_master_create_tcp(pconfig, &mbm_handle));
    mbm_controller_iface_t *pbase = mbm_handle;

    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, pdescr, descr_size));
    ESP_LOGI(TAG, "%p, Modbus master stack initialized", mbm_handle);

    TEST_ESP_OK(mbc_master_start(mbm_handle));
    ESP_LOGI(TAG, "%p, modbus master start...", mbm_handle) ;

    if (priority) {
        priority = TEST_TASK_PRIO_MASTER;
    }

    char *port_name = pbase->mb_base->descr.parent_name;
    TEST_ASSERT_TRUE(xTaskCreatePinnedToCore(func_task_master, port_name,
                     TEST_TASK_STACK_SIZE,
                     mbm_handle, TEST_TASK_PRIO_MASTER,
                     &master_task_handle, MB_PORT_TASK_AFFINITY));


    test_task_add_entry(master_task_handle, mbm_handle);

    return master_task_handle;
}

void app_main(void)
{
    void *pnetif = NULL;
    TEST_ASSERT_TRUE(test_tcp_services_init(&pnetif) == ESP_OK);
    TEST_ASSERT_NOT_NULL(pnetif);
    test_common_start();

    ESP_LOGI(TAG, "Master TCP is started.");

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

    TEST_ASSERT_NOT_NULL(master_tcp_create_instance(&tcp_master_cfg_1, 0, &descriptors[0], num_descriptors));

    TEST_ASSERT_EQUAL(test_common_task_start_all(),
                      test_common_task_wait_done_delete_all(TEST_TCP_TASK_TIMEOUT_MS));

    test_common_stop();

    test_tcp_services_destroy();
    ESP_LOGI(TAG, "Master TCP is completed. (%s).", __func__);
}
