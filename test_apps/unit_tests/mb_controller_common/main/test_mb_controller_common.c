/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include "unity_fixture.h"

#include "sdkconfig.h"
#include "test_common.h"
#include "mbc_master.h"
#include "mbc_slave.h"

#include "Mocktest_mbm_object.h"
#include "mb_object_stub.h"

#define TEST_SER_PORT_NUM 1
#define TEST_TCP_PORT_NUM 1502
#define TEST_TASKS_NUM 3
#define TEST_TASK_TIMEOUT_MS 30000
#define TEST_ALLOWED_LEAK 32
#define TEST_SLAVE_SEND_TOUT_US 30000
#define TEST_MASTER_SEND_TOUT_US 30000

#define TEST_MASTER_RESPOND_TOUT_MS CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND

#define TAG "MODBUS_CONTROLLER_COMMON_TEST"

// The workaround to statically link whole test library
__attribute__((unused)) bool mb_test_include_impl = true;

enum {
    CID_DEV_REG0_INPUT,
    CID_DEV_REG0_HOLD,
    CID_DEV_REG1_INPUT,
    CID_DEV_REG0_COIL,
    CID_DEV_REG0_DISCRITE,
    CID_DEV_REG_CNT,
    CID_ITEMS_CNT
};

// Example Data (Object) Dictionary for Modbus parameters
static const mb_parameter_descriptor_t descriptors[] = {
    {CID_DEV_REG0_INPUT, STR("MB_input_reg-0"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_INPUT, 0, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ},
    {CID_DEV_REG0_HOLD, STR("MB_hold_reg-0"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 1, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG1_INPUT, STR("MB_input_reg-1"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_INPUT, 2, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG0_COIL, STR("MB_coil_reg-0"), STR("bit"), MB_DEVICE_ADDR1, MB_PARAM_COIL, 3, 8,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG0_DISCRITE, STR("MB_discr_reg-0"), STR("bit"), MB_DEVICE_ADDR1, MB_PARAM_DISCRETE, 4, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG_CNT, STR("CYCLE_COUNTER"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 4, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
};

// Calculate number of parameters in the table
const uint16_t num_descriptors = (sizeof(descriptors) / sizeof(descriptors[0]));

TEST_GROUP(unit_test_controller);

TEST_SETUP(unit_test_controller)
{
    test_common_start();
}

TEST_TEAR_DOWN(unit_test_controller)
{
    test_common_stop();
}

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

TEST(unit_test_controller, test_setup_destroy_master_tcp)
{
    mb_communication_info_t master_config = {
        .tcp_opts.port = TEST_TCP_PORT_NUM,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = (void *)(0x44332211),
        .tcp_opts.uid = MB_DEVICE_ADDR1,
        .tcp_opts.start_disconnected = true,
        .tcp_opts.response_tout_ms = 1,
        .tcp_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US,
        .tcp_opts.ip_netif_ptr = (void *)(0x11223344)
    };

    ESP_LOGI(TAG, "TEST: Verify master create-destroy sequence TCP.");

    void *mbm_handle = NULL;
    mb_base_t *pmb_base = NULL;
    TEST_ESP_ERR(MB_ENOERR, mb_stub_tcp_create(&master_config.tcp_opts, (void *)&pmb_base));

    mbm_tcp_create_ExpectAnyArgsAndReturn(MB_ENOERR);
    mbm_tcp_create_ReturnThruPtr_in_out_obj((void **)&pmb_base);
    mbm_port_tcp_get_slave_info_IgnoreAndReturn((void *)(0x11223344));
    TEST_ESP_OK(mbc_master_create_tcp(&master_config, &mbm_handle));
    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, &descriptors[0], num_descriptors));
    TEST_ESP_OK(mbc_master_delete(mbm_handle));
    ESP_LOGI(TAG, "Test passed successfully.");
}

#endif

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

TEST(unit_test_controller, test_setup_destroy_master_serial)
{
    mb_communication_info_t master_config = {
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
    
    ESP_LOGI(TAG, "TEST: Verify master create-destroy sequence.");
    
    void *mbm_handle = NULL;
    mb_base_t *pmb_base = NULL;
    TEST_ESP_ERR(MB_ENOERR, mb_stub_serial_create(&master_config.ser_opts, (void *)&pmb_base));

    mbm_rtu_create_ExpectAnyArgsAndReturn(MB_ENOERR);
    mbm_rtu_create_ReturnThruPtr_in_out_obj((void **)&pmb_base);
    TEST_ESP_OK(mbc_master_create_serial(&master_config, &mbm_handle));
    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, &descriptors[0], num_descriptors));
    TEST_ESP_OK(mbc_master_delete(mbm_handle));

    master_config.ser_opts.mode = MB_ASCII;
    mbm_handle = NULL;
    pmb_base = NULL;

    mbm_ascii_create_ExpectAnyArgsAndReturn(MB_EINVAL);
    TEST_ESP_ERR(ESP_ERR_INVALID_STATE, mbc_master_create_serial(&master_config, &mbm_handle));
    TEST_ESP_ERR(ESP_ERR_INVALID_STATE, mbc_master_set_descriptor(mbm_handle, &descriptors[0], num_descriptors));
    TEST_ESP_ERR(ESP_ERR_INVALID_STATE, mbc_master_delete(mbm_handle));
    ESP_LOGI(TAG, "Test passed successfully.");
}

TEST(unit_test_controller, test_setup_destroy_slave_serial)
{
    // Initialize and start Modbus controller
    mb_communication_info_t slave_config = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_RTU,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_2,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = TEST_MASTER_RESPOND_TOUT_MS,
        .ser_opts.test_tout_us = TEST_MASTER_SEND_TOUT_US
    };
    
    ESP_LOGI(TAG, "TEST: Verify slave create-destroy sequence.");
    void *mbs_handle = NULL;
    mb_base_t *pmb_base = mbs_handle;
    TEST_ESP_ERR(MB_ENOERR, mb_stub_serial_create(&slave_config.ser_opts, (void *)&pmb_base));
    mbs_rtu_create_ExpectAndReturn(&slave_config.ser_opts, (void *)pmb_base, MB_ENOERR);
    mbs_rtu_create_IgnoreArg_in_out_obj();
    mbs_rtu_create_ReturnThruPtr_in_out_obj((void **)&pmb_base);
    TEST_ESP_OK(mbc_slave_create_serial(&slave_config, &mbs_handle));
    TEST_ESP_OK(mbc_slave_delete(mbs_handle));

    slave_config.ser_opts.mode = MB_ASCII;
    mbs_handle = NULL;
    mbs_ascii_create_ExpectAnyArgsAndReturn(MB_EILLSTATE);
    TEST_ESP_ERR(ESP_ERR_INVALID_STATE, mbc_slave_create_serial(&slave_config, &mbs_handle));
    TEST_ESP_ERR(ESP_ERR_INVALID_STATE, mbc_slave_delete(mbs_handle));
    ESP_LOGI(TAG, "Test passed successfully.");
}

esp_err_t test_master_registers(int par_index, mb_err_enum_t mb_err)
{
    mb_communication_info_t master_config = {
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
    mb_base_t *pmb_base = NULL; // fake mb_base handle 
    void *mbm_handle = NULL;

    TEST_ESP_ERR(MB_ENOERR, mb_stub_serial_create(&master_config.ser_opts, (void *)&pmb_base));
    pmb_base->port_obj = (mb_port_base_t *)0x44556677;
    mbm_rtu_create_ExpectAnyArgsAndReturn(MB_ENOERR);
    mbm_rtu_create_ReturnThruPtr_in_out_obj((void **)&pmb_base);
    TEST_ESP_OK(mbc_master_create_serial(&master_config, &mbm_handle));
    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, &descriptors[0], num_descriptors));
    mb_port_event_res_take_ExpectAnyArgsAndReturn(true);
    mb_port_event_res_release_ExpectAnyArgs();
    TEST_ESP_OK(mbc_master_start(mbm_handle));

    const mb_parameter_descriptor_t *param_descriptor = NULL;
    esp_err_t err = mbc_master_get_cid_info(mbm_handle, par_index, &param_descriptor);
    if ((err != ESP_ERR_NOT_FOUND) && (param_descriptor != NULL))
    {
        TEST_ASSERT_EQUAL_HEX32(&descriptors[par_index], param_descriptor);       
        uint8_t type = 0; // type of parameter from dictionary
        uint8_t *pdata = (uint8_t *)calloc(1, param_descriptor->mb_size + 1);
        ESP_LOGI(TAG, "Test CID #%d, %s, %s", param_descriptor->cid, param_descriptor->param_key, param_descriptor->param_units);
        // This is to check the request function is called with appropriate params.
        switch(param_descriptor->mb_param_type) { \
            case MB_PARAM_INPUT: \
                mbm_rq_read_inp_reg_ExpectAndReturn(pmb_base, \
                                                            param_descriptor->mb_slave_addr, \
                                                            param_descriptor->mb_reg_start, \
                                                            param_descriptor->mb_size, \
                                                            1, \
                                                            mb_err); \
                mbm_rq_read_inp_reg_IgnoreArg_tout(); \
                break; \
            case MB_PARAM_HOLDING:
                mbm_rq_read_holding_reg_ExpectAndReturn(pmb_base, \
                                                            param_descriptor->mb_slave_addr, \
                                                            param_descriptor->mb_reg_start, \
                                                            param_descriptor->mb_size, \
                                                            1, \
                                                            mb_err); \
                mbm_rq_read_holding_reg_IgnoreArg_tout(); \
                break; \
            case MB_PARAM_COIL: \
                mbm_rq_read_coils_ExpectAndReturn(pmb_base, \
                                                        param_descriptor->mb_slave_addr, \
                                                        param_descriptor->mb_reg_start, \
                                                        param_descriptor->mb_size, \
                                                        1, \
                                                        mb_err); \
                mbm_rq_read_coils_IgnoreArg_tout(); \
                break; \
            case MB_PARAM_DISCRETE: \
                mbm_rq_read_discrete_inputs_ExpectAndReturn(pmb_base, \
                                                        param_descriptor->mb_slave_addr, \
                                                        param_descriptor->mb_reg_start, \
                                                        param_descriptor->mb_size, \
                                                        1, \
                                                        mb_err); \
                mbm_rq_read_discrete_inputs_IgnoreArg_tout(); \
                break; \
            default:
                TEST_FAIL(); \
                break; \
        }    
        err = mbc_master_get_parameter(mbm_handle, par_index, pdata, &type); \
        free(pdata);
    }
    TEST_ESP_OK(mbc_master_stop(mbm_handle));
    TEST_ESP_OK(mbc_master_delete(mbm_handle));
    ESP_LOGI(TAG, "Test passed successfully.");
    return err;
}

// Check if modbus controller object forms correct modbus request from data dictionary
// and is able to transfer data using mb_object. Check possible errors returned back from
// mb_object and make sure the modbus controller handles them correctly.
TEST(unit_test_controller, test_master_send_request_serial)
{
    TEST_ESP_ERR(ESP_OK, test_master_registers(CID_DEV_REG0_INPUT, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, test_master_registers(CID_DEV_REG0_INPUT, MB_ETIMEDOUT));
    TEST_ESP_ERR(ESP_OK, test_master_registers(CID_DEV_REG0_HOLD, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, test_master_registers(CID_DEV_REG0_HOLD, MB_ETIMEDOUT));
    TEST_ESP_ERR(ESP_OK, test_master_registers(CID_DEV_REG0_COIL, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, test_master_registers(CID_DEV_REG0_COIL, MB_ETIMEDOUT));
    TEST_ESP_ERR(ESP_OK, test_master_registers(CID_DEV_REG0_DISCRITE, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, test_master_registers(CID_DEV_REG0_DISCRITE, MB_ETIMEDOUT));
}

#endif

TEST_GROUP_RUNNER(unit_test_controller)
{

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)
    RUN_TEST_CASE(unit_test_controller, test_setup_destroy_master_serial);
    RUN_TEST_CASE(unit_test_controller, test_setup_destroy_slave_serial);
    RUN_TEST_CASE(unit_test_controller, test_master_send_request_serial);
#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)
    RUN_TEST_CASE(unit_test_controller, test_setup_destroy_master_tcp);
#endif

}
