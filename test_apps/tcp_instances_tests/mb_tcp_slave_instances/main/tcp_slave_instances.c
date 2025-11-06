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
#include "mbc_slave.h"
#include "mbc_master.h"

#include "esp_timer.h"

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
#define TEST_TCP_PORT_NUM2              (502)
#define TEST_TCP_TASK_TIMEOUT_MS        (160000)
#define TEST_TCP_SLAVE_SEND_TOUT_US     (500)

#define TEST_PAR_INFO_GET_TOUT      (10)
#define TEST_TASK_START_TIMEOUT     (10000 / portTICK_PERIOD_MS)
#define TEST_TASK_NOTIFY_STOP_TOUT  (100 / portTICK_PERIOD_MS)
#define TEST_TASK_TICK_TIME         (50 / portTICK_PERIOD_MS)

#define TEST_VALUE (12345) // default test value

// Options can be used as bit masks or parameter limits
#define OPTS(min_val, max_val, step_val) { .opt1 = min_val, .opt2 = max_val, .opt3 = step_val }

// Defines below are used to define register start address for each type of Modbus registers
#define HOLD_OFFSET_SLAVE(field) ((uint16_t)(offsetof(holding_reg_params_t, field) >> 1))
#define INPUT_OFFSET_SLAVE(field) ((uint16_t)(offsetof(input_reg_params_t, field) >> 1))
#define MB_REG_DISCRETE_INPUT_START         (0x0000)
#define MB_REG_COILS_START                  (0x0000)
#define MB_REG_INPUT_START_AREA0            (INPUT_OFFSET_SLAVE(input_data0)) // register offset input area 0
#define MB_REG_INPUT_START_AREA1            (INPUT_OFFSET_SLAVE(input_data4)) // register offset input area 1
#define MB_REG_HOLDING_START_AREA0          (HOLD_OFFSET_SLAVE(holding_data0))
#define MB_REG_HOLDING_START_AREA1          (HOLD_OFFSET_SLAVE(holding_data4))
#define MB_REG_HOLDING_START_AREA2          (HOLD_OFFSET_SLAVE(holding_u8_a))
#define MB_REG_HOLDING_START_AREA2_SIZE     ((size_t)((HOLD_OFFSET_SLAVE(holding_area2_end) - HOLD_OFFSET_SLAVE(holding_u8_a)) << 1))

#define MB_CHAN_DATA_MAX_VAL                (10)
#define MB_CHAN_DATA_OFFSET                 (1.1f)

#define MB_READ_MASK                        (MB_EVENT_INPUT_REG_RD \
                                                | MB_EVENT_HOLDING_REG_RD \
                                                | MB_EVENT_DISCRETE_RD \
                                                | MB_EVENT_COILS_RD)
#define MB_WRITE_MASK                       (MB_EVENT_HOLDING_REG_WR \
                                                | MB_EVENT_COILS_WR)
#define MB_READ_WRITE_MASK                  (MB_READ_MASK | MB_WRITE_MASK)
#define MB_TEST_VALUE                       (12345.0)

// The workaround to statically link the whole test library
__attribute__((unused)) bool mb_test_include_phys_impl_tcp = true;

#define TAG "MODBUS_TCP_COMM_SLAVE_TEST"

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

static void func_slave_task(void *arg)
{

    void *mbs_handle = arg;
    mbs_controller_iface_t *pctrl_obj = ((mbs_controller_iface_t *)mbs_handle);
    mb_param_info_t reg_info;                    // keeps the Modbus registers access information

    test_common_task_wait_start_and_stop(TEST_TASK_START_TIMEOUT);

    while (1) {
        // Get parameter information from parameter queue
        esp_err_t err = mbc_slave_get_param_info(mbs_handle, &reg_info, TEST_PAR_INFO_GET_TOUT);
        const char *rw_str = (reg_info.type & MB_READ_MASK) ? "READ" : "WRITE";

        if (test_common_task_wait_start_and_stop(TEST_TASK_NOTIFY_STOP_TOUT)) {
            ESP_LOGD(TAG, "Received destroy message, destroying instance: %p.", mbs_handle);
            break;
        }

        // Filter events and process them accordingly
        if ((err != ESP_ERR_TIMEOUT) && (reg_info.type & MB_READ_WRITE_MASK)) {

            if (reg_info.type & (MB_EVENT_HOLDING_REG_WR | MB_EVENT_HOLDING_REG_RD)) {
                // Get parameter information from parameter queue
                ESP_LOGI(TAG, "OBJ %p, HOLDING %s (%" PRIu32 " us), SL: %u, REG:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 "(0x%" PRIx16 "), SIZE:%u",
                         (void *)pctrl_obj->mb_base->descr.parent,
                         rw_str,
                         (uint32_t)reg_info.time_stamp,
                         (unsigned)pctrl_obj->opts.comm_opts.common_opts.uid,
                         (unsigned)reg_info.mb_offset,
                         (unsigned)reg_info.type,
                         (uint32_t)reg_info.address,
                         *(uint16_t *)reg_info.address,
                         (unsigned)reg_info.size);

                if (reg_info.address == (uint8_t *)&holding_reg_params.holding_data0) {
                    (void)mbc_slave_unlock(mbs_handle);
                    holding_reg_params.holding_data0 += MB_CHAN_DATA_OFFSET;
                    if (holding_reg_params.holding_data0 >= MB_CHAN_DATA_MAX_VAL) {
                        coil_reg_params.coils_port1 = 0xFF;
                        ESP_LOGI(TAG, "Reached maximum value");
                    }
                    (void)mbc_slave_unlock(mbs_handle);
                }
            } else if (reg_info.type & MB_EVENT_INPUT_REG_RD) {
                ESP_LOGI(TAG, "OBJ %p, INPUT %s (%" PRIu32 " us), SL: %u, REG:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 "(0x%" PRIx16 "), SIZE:%u",
                         (void *)pctrl_obj->mb_base->descr.parent,
                         rw_str,
                         (uint32_t)reg_info.time_stamp,
                         (unsigned)pctrl_obj->opts.comm_opts.common_opts.uid,
                         (unsigned)reg_info.mb_offset,
                         (unsigned)reg_info.type,
                         (uint32_t)reg_info.address,
                         *(uint16_t *)reg_info.address,
                         (unsigned)reg_info.size);

            } else if (reg_info.type & MB_EVENT_DISCRETE_RD) {
                ESP_LOGI(TAG, "OBJ %p, DISCRETE %s (%" PRIu32 " us), SL: %u, REG:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 "(0x%" PRIx16 "), SIZE:%u",
                         (void *)pctrl_obj->mb_base->descr.parent,
                         rw_str,
                         (uint32_t)reg_info.time_stamp,
                         (unsigned)pctrl_obj->opts.comm_opts.common_opts.uid,
                         (unsigned)reg_info.mb_offset,
                         (unsigned)reg_info.type,
                         (uint32_t)reg_info.address,
                         *(uint16_t *)reg_info.address,
                         (unsigned)reg_info.size);

            } else if (reg_info.type & (MB_EVENT_COILS_RD | MB_EVENT_COILS_WR)) {
                ESP_LOGI(TAG, "OBJ %p, COILS %s (%" PRIu32 " us), SL: %u, REG:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 "(0x%" PRIx16 "), SIZE:%u",
                         (void *)pctrl_obj->mb_base->descr.parent,
                         rw_str,
                         (uint32_t)reg_info.time_stamp,
                         (unsigned)pctrl_obj->opts.comm_opts.common_opts.uid,
                         (unsigned)reg_info.mb_offset,
                         (unsigned)reg_info.type,
                         (uint32_t)reg_info.address,
                         *(uint16_t *)reg_info.address,
                         (unsigned)reg_info.size);
            }
        }

        vTaskDelay(TEST_TASK_TICK_TIME); // Let IDLE task to trigger
        if (coil_reg_params.coils_port1 == 0xFF) {
            ESP_LOGD(TAG, "Stop slave: %p.", mbs_handle);
            vTaskDelay(TEST_TASK_TICK_TIME); // Let master to get response from slave prior to close
            break;
        }
    }
    ESP_LOGI(TAG, "Destroy slave, inst: %p.", mbs_handle);
    TEST_ESP_OK(mbc_slave_delete(mbs_handle));
    ESP_LOGD(TAG, "Notify task done, inst: %p.", xTaskGetCurrentTaskHandle());
    test_common_task_notify_done(xTaskGetCurrentTaskHandle());
    vTaskDelay(10);
    vTaskSuspend(NULL);
}

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

    holding_reg_params.holding_data0 = 0.34;
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

void instance_slave_setup_start(void *mbs_handle)
{
    TEST_ASSERT_TRUE(mbs_handle);
    mb_register_area_descriptor_t reg_area;

    reg_area.type = MB_PARAM_HOLDING; // Set type of register area
    reg_area.start_offset = MB_REG_HOLDING_START_AREA0; // Offset of register area in Modbus protocol
    reg_area.address = (void *)&holding_reg_params.holding_data0; // Set pointer to storage instance
    reg_area.size = (MB_REG_HOLDING_START_AREA1 - MB_REG_HOLDING_START_AREA0) << 1; // Set the size of register storage instance
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));


    reg_area.type = MB_PARAM_HOLDING; // Set type of register area
    reg_area.start_offset = MB_REG_HOLDING_START_AREA1; // Offset of register area in Modbus protocol
    reg_area.address = (void *)&holding_reg_params.holding_data4; // Set pointer to storage instance
    reg_area.size = sizeof(float) << 2; // Set the size of register storage instance
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));


#if CONFIG_FMB_EXT_TYPE_SUPPORT
    // The extended parameters register area
    reg_area.type = MB_PARAM_HOLDING;
    reg_area.start_offset = MB_REG_HOLDING_START_AREA2;
    reg_area.address = (void *)&holding_reg_params.holding_u8_a;
    reg_area.size = MB_REG_HOLDING_START_AREA2_SIZE;
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));

#endif

    // Initialization of Input Registers area
    reg_area.type = MB_PARAM_INPUT;
    reg_area.start_offset = MB_REG_INPUT_START_AREA0;
    reg_area.address = (void *)&input_reg_params.input_data0;
    reg_area.size = sizeof(float) << 2;
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));

    reg_area.type = MB_PARAM_INPUT;
    reg_area.start_offset = MB_REG_INPUT_START_AREA1;
    reg_area.address = (void *)&input_reg_params.input_data4;
    reg_area.size = sizeof(float) << 2;
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));

    // Initialization of Coils register area
    reg_area.type = MB_PARAM_COIL;
    reg_area.start_offset = MB_REG_COILS_START;
    reg_area.address = (void *)&coil_reg_params;
    reg_area.size = sizeof(coil_reg_params);
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));


    // Initialization of Discrete Inputs register area
    reg_area.type = MB_PARAM_DISCRETE;
    reg_area.start_offset = MB_REG_DISCRETE_INPUT_START;
    reg_area.address = (void *)&discrete_reg_params;
    reg_area.size = sizeof(discrete_reg_params);
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));


    // Set values into known state
    setup_reg_data();

    // Starts of modbus controller and stack
    TEST_ESP_OK(mbc_slave_start(mbs_handle));
}

TaskHandle_t slave_tcp_create_instance(mb_communication_info_t *pconfig, uint32_t priority)
{
    if (!pconfig) {
        ESP_LOGI(TAG, "invalid slave configuration.");
    }

    void *mbs_handle = NULL;
    TaskHandle_t slave_task_handle = NULL;

    TEST_ESP_OK(mbc_slave_create_tcp(pconfig, &mbs_handle));

    mbs_controller_iface_t *pbase = mbs_handle;
    instance_slave_setup_start(mbs_handle);

    if (priority) {
        priority = TEST_TASK_PRIO_SLAVE;
    }

    TEST_ASSERT_TRUE(xTaskCreatePinnedToCore(func_slave_task, pbase->mb_base->descr.parent_name,
                     TEST_TASK_STACK_SIZE,
                     mbs_handle, priority,
                     &slave_task_handle, MB_PORT_TASK_AFFINITY));

    test_task_add_entry(slave_task_handle, mbs_handle);

    return slave_task_handle;
}

void app_main(void)
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

    TEST_ASSERT_NOT_NULL(slave_tcp_create_instance(&tcp_slave_cfg_1, 0));

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

    TEST_ASSERT_NOT_NULL(slave_tcp_create_instance(&tcp_slave_cfg_2, 0));

    ESP_LOGI(TAG, "Slave TCP #2 is started. (%s).", __func__);

    TEST_ASSERT_EQUAL(test_common_task_start_all(),
                      test_common_task_wait_done_delete_all(TEST_TCP_TASK_TIMEOUT_MS));

    ESP_LOGI(TAG, "Slave TCP test is completed. (%s).", __func__);

    test_common_stop();

    test_tcp_services_destroy();
}
