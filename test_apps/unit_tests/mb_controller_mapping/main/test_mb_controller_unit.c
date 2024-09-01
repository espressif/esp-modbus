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

#define TAG "MB_CONTROLLER_TEST"

// The workaround to statically link whole test library
__attribute__((unused)) bool mb_test_include_impl = true;

enum
{
    CID_DEV_REG0_INPUT,
    CID_DEV_REG0_HOLD,
    CID_DEV_REG1_INPUT,
    CID_DEV_REG0_COIL,
    CID_DEV_REG0_DISCRITE,
    CID_DEV_INPUT_AREA,
    CID_DEV_HOLD_AREA,
    CID_DEV_COIL_AREA,
    CID_DEV_DISCR_AREA,
};

#define TEST_AREA0_REG_OFFS 2
#define TEST_HOLD_AREA0_REG_SZ 10
#define TEST_COIL_AREA0_REG_SZ 10
#define TEST_INPUT_AREA0_REG_SZ 10
#define TEST_DISCR_AREA0_REG_SZ 10

static uint16_t input_registers[TEST_INPUT_AREA0_REG_SZ + 1] = {0};
static uint16_t hold_registers[TEST_HOLD_AREA0_REG_SZ + 1] = {0};
static uint16_t coil_registers[TEST_COIL_AREA0_REG_SZ + 1] = {0};
static uint16_t discr_registers[TEST_COIL_AREA0_REG_SZ + 1] = {0};

// Example Data (Object) Dictionary for Modbus parameters
static const mb_parameter_descriptor_t descriptors[] = {
    {CID_DEV_REG0_INPUT, STR("MB_input_reg-0"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_INPUT, 0, 2,
        (uint32_t)&input_registers[0], PARAM_TYPE_U32, 4, OPTS(0, 0, 0), PAR_PERMS_READ},
    {CID_DEV_REG0_HOLD, STR("MB_hold_reg-0"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 1, 2,
        (uint32_t)&hold_registers[1], PARAM_TYPE_U32, 4, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG1_INPUT, STR("MB_input_reg-1"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_INPUT, 2, 1,
        0, PARAM_TYPE_U16, 2, OPTS(0, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG0_COIL, STR("MB_coil_reg-0"), STR("Bit"), MB_DEVICE_ADDR1, MB_PARAM_COIL, 3, TEST_COIL_AREA0_REG_SZ,
        0, PARAM_TYPE_U16, 2, OPTS(0x03ff, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_REG0_DISCRITE, STR("MB_discr_reg-0"), STR("Bit"), MB_DEVICE_ADDR1, MB_PARAM_DISCRETE, 4, TEST_DISCR_AREA0_REG_SZ,
        0, PARAM_TYPE_U16, 2, OPTS(0x03fe, 0, 0), PAR_PERMS_READ_WRITE_TRIGGER},
    {CID_DEV_INPUT_AREA, STR("MB_input_area"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_INPUT, TEST_AREA0_REG_OFFS, TEST_INPUT_AREA0_REG_SZ,
        (uint32_t)&input_registers[1], PARAM_TYPE_ASCII, (TEST_INPUT_AREA0_REG_SZ * 2), OPTS(0, 0, 0), PAR_PERMS_READ},
    {CID_DEV_HOLD_AREA, STR("MB_holding_area"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, TEST_AREA0_REG_OFFS, TEST_HOLD_AREA0_REG_SZ,
        (uint32_t)&hold_registers[1], PARAM_TYPE_ASCII, (TEST_HOLD_AREA0_REG_SZ * 2), OPTS(0, 0, 0), PAR_PERMS_READ},
    {CID_DEV_COIL_AREA, STR("MB_coil_area"), STR("Bit"), MB_DEVICE_ADDR1, MB_PARAM_COIL, TEST_AREA0_REG_OFFS, TEST_COIL_AREA0_REG_SZ,
        (uint32_t)&coil_registers[1], PARAM_TYPE_U16, ((TEST_COIL_AREA0_REG_SZ >> 3) + 1), OPTS(0, 0, 0), PAR_PERMS_READ},
    {CID_DEV_DISCR_AREA, STR("MB_discr_area"), STR("Bit"), MB_DEVICE_ADDR1, MB_PARAM_COIL, TEST_AREA0_REG_OFFS, TEST_DISCR_AREA0_REG_SZ,
        (uint32_t)&discr_registers[1], PARAM_TYPE_U16, ((TEST_DISCR_AREA0_REG_SZ >> 3) + 1), OPTS(0, 0, 0), PAR_PERMS_READ},
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

static void test_slave_check_descriptor(int par_index)
{
    mb_communication_info_t slave_config = {
        .ser_opts.port = TEST_SER_PORT_NUM,
        .ser_opts.mode = MB_RTU,
        .ser_opts.uid = MB_DEVICE_ADDR1,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1,
        .ser_opts.baudrate = 115200,
        .ser_opts.parity = UART_PARITY_DISABLE,
        .ser_opts.response_tout_ms = 0,
        .ser_opts.test_tout_us = 0
    };

    void *mbs_handle = NULL;
    mb_base_t *pmb_base = NULL; // fake mb_base handle

    TEST_ESP_ERR(MB_ENOERR, mb_stub_serial_create(&slave_config.ser_opts, (void *)&pmb_base));
    pmb_base->port_obj = (mb_port_base_t *)0x44556677;
    mbs_rtu_create_ExpectAnyArgsAndReturn(MB_ENOERR);
    mbs_rtu_create_ReturnThruPtr_in_out_obj((void **)&pmb_base);

    TEST_ESP_OK(mbc_slave_create_serial(&slave_config, &mbs_handle));
    TEST_ASSERT(mbs_handle);

    mbs_controller_iface_t *mbs_iface = (mbs_controller_iface_t *)mbs_handle;
    //mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(mbs_iface);
    TEST_ASSERT_EQUAL_HEX32(mbs_iface->mb_base, pmb_base);

    TEST_ASSERT_EQUAL_HEX32(pmb_base->rw_cbs.reg_input_cb, mbc_reg_input_slave_cb);
    TEST_ASSERT_EQUAL_HEX32(pmb_base->rw_cbs.reg_holding_cb, mbc_reg_holding_slave_cb);
    TEST_ASSERT_EQUAL_HEX32(pmb_base->rw_cbs.reg_coils_cb, mbc_reg_coils_slave_cb);
    TEST_ASSERT_EQUAL_HEX32(pmb_base->rw_cbs.reg_discrete_cb, mbc_reg_discrete_slave_cb);

    mb_parameter_descriptor_t *pdescr = (mb_parameter_descriptor_t *)&descriptors[par_index];
    mb_register_area_descriptor_t reg_area;
    ESP_LOGI(TAG, "Test CID #%d, %s, %s", pdescr->cid, pdescr->param_key, pdescr->param_units);

    uint16_t n_bytes = ((pdescr->mb_param_type == MB_PARAM_INPUT) || (pdescr->mb_param_type == MB_PARAM_HOLDING))
                                ? (pdescr->mb_size << 1) : ((pdescr->mb_size >> 3) + 1);

    // First define the correct area
    reg_area.type = pdescr->mb_param_type;
    reg_area.start_offset = pdescr->mb_reg_start;
    reg_area.address = (void *)pdescr->param_offset;
    reg_area.size = n_bytes;
    ESP_LOGI(TAG, "Area (type, reg_start, address, size): %d, %u, 0x%" PRIx32 ", %d, is defined.",
                        (int)reg_area.type, (unsigned)reg_area.start_offset, (uint32_t)reg_area.address, (int)reg_area.size);
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));

    // Check additional area overlapped 
    reg_area.start_offset = (pdescr->mb_reg_start + pdescr->mb_size - 2);
    reg_area.size = 2;
    ESP_LOGI(TAG, "Area overlapped (type, reg_start, address, size): %d, %u, 0x%" PRIx32 ", %d.",
                        (int)reg_area.type, (unsigned)reg_area.start_offset, (uint32_t)reg_area.address, (int)reg_area.size);
    TEST_ESP_ERR(ESP_ERR_INVALID_ARG, mbc_slave_set_descriptor(mbs_handle, reg_area));
    
    reg_area.start_offset = pdescr->mb_reg_start;
    reg_area.size = n_bytes;
    reg_area.address = (void *)pdescr->param_offset - 2;
    ESP_LOGI(TAG, "Area redefine (type, reg_start, address, size): %d, %u, 0x%" PRIx32 ", %d.",
                        (int)reg_area.type, (unsigned)reg_area.start_offset, (uint32_t)reg_area.address, (int)reg_area.size);
    TEST_ESP_ERR(ESP_ERR_INVALID_ARG, mbc_slave_set_descriptor(mbs_handle, reg_area));

    TEST_ESP_OK(mbc_slave_delete(mbs_handle)); // the destructor of mb controller destroys the fake mb_object as well
    TEST_ASSERT_EQUAL_HEX(mb_port_get_inst_counter(), 0);
    ESP_LOGI(TAG, "Test passed successfully.");
}

static esp_err_t test_master_read_req(int par_index, mb_err_enum_t mb_err)
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
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US};
    mb_base_t *pmb_base = NULL; // fake mb_base handle
    void *mbm_handle = NULL;

    TEST_ESP_ERR(MB_ENOERR, mb_stub_serial_create(&master_config.ser_opts, (void *)&pmb_base));
    pmb_base->port_obj = (mb_port_base_t *)0x44556677;
    mbm_rtu_create_ExpectAnyArgsAndReturn(MB_ENOERR);
    mbm_rtu_create_ReturnThruPtr_in_out_obj((void **)&pmb_base);
    TEST_ESP_OK(mbc_master_create_serial(&master_config, &mbm_handle));
    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, &descriptors[0], num_descriptors));
    mb_port_event_post_ExpectAndReturn(pmb_base->port_obj, EVENT(EV_FRAME_TRANSMIT | EV_TRANS_START), true);
    TEST_ESP_OK(mbc_master_start(mbm_handle));
    mb_port_event_wait_req_finish_ExpectAndReturn(pmb_base->port_obj, mb_err);

    const mb_parameter_descriptor_t *param_descriptor = NULL;
    TEST_ESP_OK(mbc_master_get_cid_info(mbm_handle, par_index, &param_descriptor));
    TEST_ASSERT_EQUAL_HEX32(&descriptors[par_index], param_descriptor);
    uint8_t type = 0; // type of parameter from dictionary
    uint8_t pdata[100] = {0};
    ESP_LOGI(TAG, "Test CID #%d, %s, %s", param_descriptor->cid, param_descriptor->param_key, param_descriptor->param_units);
    mb_port_event_res_take_ExpectAnyArgsAndReturn(true);
    mb_port_event_res_release_ExpectAnyArgs();
    mb_port_event_res_take_ExpectAnyArgsAndReturn(true);
    mb_port_event_res_release_ExpectAnyArgs();

    // Call the read method of modbus controller
    esp_err_t err = mbc_master_get_parameter(mbm_handle, par_index, pdata, &type);
    uint8_t *mb_frame_ptr = NULL;
    // get send buffer back using the fake mb_object
    pmb_base->get_send_buf(pmb_base, &mb_frame_ptr);
    TEST_ASSERT_EQUAL_HEX8(pmb_base->get_dest_addr(pmb_base), param_descriptor->mb_slave_addr);
    uint8_t send_len = pmb_base->get_send_len(pmb_base);
    TEST_ASSERT_EQUAL_HEX8(send_len, (MB_PDU_SIZE_MIN + MB_PDU_REQ_READ_SIZE));
    // Check that request function forms correct buffer
    switch (param_descriptor->mb_param_type)
    {
        case MB_PARAM_INPUT:
            // TEST_CHECK_EQ
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_FUNC_OFF], MB_FUNC_READ_INPUT_REGISTER);
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF], (param_descriptor->mb_reg_start >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF + 1], (param_descriptor->mb_reg_start & 0x00FF));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_REGCNT_OFF], (param_descriptor->mb_size >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_REGCNT_OFF + 1], (param_descriptor->mb_size & 0x00FF));
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, (void *)mb_frame_ptr, send_len, ESP_LOG_INFO);
            break;
        case MB_PARAM_HOLDING:
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_FUNC_OFF], MB_FUNC_READ_HOLDING_REGISTER);
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF], (param_descriptor->mb_reg_start >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF + 1], (param_descriptor->mb_reg_start & 0x00FF));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_REGCNT_OFF], (param_descriptor->mb_size >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_REGCNT_OFF + 1], (param_descriptor->mb_size & 0x00FF));
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, (void *)mb_frame_ptr, send_len, ESP_LOG_INFO);
            break;
        case MB_PARAM_COIL:
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_FUNC_OFF], MB_FUNC_READ_COILS);
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF], (param_descriptor->mb_reg_start >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF + 1], (param_descriptor->mb_reg_start & 0x00FF));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_COILCNT_OFF], (param_descriptor->mb_size >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_COILCNT_OFF + 1], (param_descriptor->mb_size & 0x00FF));
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, (void *)mb_frame_ptr, send_len, ESP_LOG_INFO);
            break;
        case MB_PARAM_DISCRETE:
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_FUNC_OFF], MB_FUNC_READ_DISCRETE_INPUTS);
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF], (param_descriptor->mb_reg_start >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_ADDR_OFF + 1], (param_descriptor->mb_reg_start & 0x00FF));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_DISCCNT_OFF], (param_descriptor->mb_size >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_READ_DISCCNT_OFF + 1], (param_descriptor->mb_size & 0x00FF));
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, (void *)mb_frame_ptr, send_len, ESP_LOG_INFO);
            break;
        default:
            TEST_FAIL();
            break;
    }
    TEST_ESP_OK(mbc_master_stop(mbm_handle));
    TEST_ESP_OK(mbc_master_delete(mbm_handle)); // the destructor of mb controller destroys the fake mb_object as well
    TEST_ASSERT_EQUAL_HEX(mb_port_get_inst_counter(), 0);
    ESP_LOGI(TAG, "Test passed successfully.");
    return err;
}

static esp_err_t test_master_write_req(int par_index, mb_err_enum_t mb_err)
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
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US};
    mb_base_t *pmb_base = NULL; // fake mb_base handle
    void *mbm_handle = NULL;

    TEST_ESP_ERR(MB_ENOERR, mb_stub_serial_create(&master_config.ser_opts, (void *)&pmb_base));
    pmb_base->port_obj = (mb_port_base_t *)0x44556677;
    mbm_rtu_create_ExpectAnyArgsAndReturn(MB_ENOERR);
    mbm_rtu_create_ReturnThruPtr_in_out_obj((void **)&pmb_base);
    TEST_ESP_OK(mbc_master_create_serial(&master_config, &mbm_handle));
    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, &descriptors[0], num_descriptors));
    mb_port_event_post_ExpectAndReturn(pmb_base->port_obj, EVENT(EV_FRAME_TRANSMIT | EV_TRANS_START), true);
    mb_port_event_wait_req_finish_ExpectAndReturn(pmb_base->port_obj, mb_err);
    TEST_ESP_OK(mbc_master_start(mbm_handle));

    const mb_parameter_descriptor_t *param_descriptor = NULL;
    TEST_ESP_OK(mbc_master_get_cid_info(mbm_handle, par_index, &param_descriptor));
    TEST_ASSERT_EQUAL_HEX32(&descriptors[par_index], param_descriptor);
    uint8_t type = 0; // type of parameter from dictionary
    uint8_t reg_data[] = {0x11, 0x22, 0x33, 0x44};
    ESP_LOGI(TAG, "Test CID #%d, %s, %s", param_descriptor->cid, param_descriptor->param_key, param_descriptor->param_units);
    mb_port_event_res_take_ExpectAnyArgsAndReturn(true);
    mb_port_event_res_release_ExpectAnyArgs();
    mb_port_event_res_take_ExpectAnyArgsAndReturn(true);
    mb_port_event_res_release_ExpectAnyArgs();

    // Call the read method of modbus controller
    esp_err_t err = mbc_master_set_parameter(mbm_handle, par_index, reg_data, &type);
    uint8_t *mb_frame_ptr = NULL;
    // get send buffer back using the fake mb_object
    pmb_base->get_send_buf(pmb_base, &mb_frame_ptr);
    TEST_ASSERT_EQUAL_HEX8(pmb_base->get_dest_addr(pmb_base), param_descriptor->mb_slave_addr);
    uint8_t send_len = pmb_base->get_send_len(pmb_base);
    // Check that request function forms correct buffer
    switch (param_descriptor->mb_param_type)
    {
        case MB_PARAM_HOLDING:
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_FUNC_OFF], MB_FUNC_WRITE_MULTIPLE_REGISTERS);
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_ADDR_OFF], (param_descriptor->mb_reg_start >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_ADDR_OFF + 1], (param_descriptor->mb_reg_start & 0x00FF));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_REGCNT_OFF], (param_descriptor->mb_size >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_REGCNT_OFF + 1], (param_descriptor->mb_size & 0x00FF));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_BYTECNT_OFF], (param_descriptor->mb_size << 1));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_BYTECNT_OFF], sizeof(reg_data));
            TEST_ASSERT_EQUAL_HEX8(send_len, ((MB_PDU_SIZE_MIN + MB_PDU_REQ_WRITE_MUL_SIZE_MIN + 2 * param_descriptor->mb_size)));
            for (int i = 0; (i < param_descriptor->mb_size); i++)
            {
                TEST_ASSERT_EQUAL_HEX8(reg_data[0], mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_VALUES_OFF + 1]);
                TEST_ASSERT_EQUAL_HEX8(reg_data[1], mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_VALUES_OFF]);
            }
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, (void *)mb_frame_ptr, send_len, ESP_LOG_INFO);
            // TEST_ESP_ERR(MB_ENOERR, mbs_fn_write_holding_reg(pmb_base, mb_frame_ptr, &send_len));
            break;
        case MB_PARAM_COIL:
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_FUNC_OFF], MB_FUNC_WRITE_MULTIPLE_COILS);
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_ADDR_OFF], (param_descriptor->mb_reg_start >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_ADDR_OFF + 1], (param_descriptor->mb_reg_start & 0x00FF));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_COILCNT_OFF], (param_descriptor->mb_size >> 8));
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_COILCNT_OFF + 1], (param_descriptor->mb_size & 0x00FF));
            uint8_t byte_cnt = (param_descriptor->mb_size & 0x0007) ? ((param_descriptor->mb_size >> 3) + 1) : (param_descriptor->mb_size >> 3);
            TEST_ASSERT_EQUAL_HEX8(mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_BYTECNT_OFF], byte_cnt);
            TEST_ASSERT_EQUAL_HEX8(send_len, (MB_PDU_SIZE_MIN + MB_PDU_REQ_WRITE_MUL_SIZE_MIN + byte_cnt));
            TEST_ASSERT_EQUAL_HEX8(reg_data[0], mb_frame_ptr[MB_PDU_REQ_WRITE_MUL_VALUES_OFF]);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, (void *)mb_frame_ptr, send_len, ESP_LOG_INFO);
            break;
        default:
            TEST_FAIL();
            break;
    }
    TEST_ESP_OK(mbc_master_stop(mbm_handle));
    TEST_ESP_OK(mbc_master_delete(mbm_handle));
    TEST_ASSERT_EQUAL_HEX(mb_port_get_inst_counter(), 0);
    ESP_LOGI(TAG, "Test passed successfully.");
    return err;
}

static esp_err_t test_master_check_callback(int par_index, mb_err_enum_t mb_err)
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
        .ser_opts.test_tout_us = TEST_SLAVE_SEND_TOUT_US};
    mb_base_t *pmb_base = NULL; // fake mb_base handle
    void *mbm_handle = NULL;

    TEST_ESP_ERR(MB_ENOERR, mb_stub_serial_create(&master_config.ser_opts, (void *)&pmb_base));
    pmb_base->port_obj = (mb_port_base_t *)0x44556677;
    mbm_rtu_create_ExpectAnyArgsAndReturn(MB_ENOERR);
    mbm_rtu_create_ReturnThruPtr_in_out_obj((void **)&pmb_base);
    TEST_ESP_OK(mbc_master_create_serial(&master_config, &mbm_handle));
    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, &descriptors[0], num_descriptors));
    mbm_controller_iface_t *mbm_controller_iface = (mbm_controller_iface_t *)mbm_handle;
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(mbm_controller_iface);
    TEST_ASSERT_EQUAL_HEX32(mbm_controller_iface->mb_base, pmb_base);

    TEST_ASSERT_EQUAL_HEX32(pmb_base->rw_cbs.reg_input_cb, mbc_reg_input_master_cb);
    TEST_ASSERT_EQUAL_HEX32(pmb_base->rw_cbs.reg_holding_cb, mbc_reg_holding_master_cb);
    TEST_ASSERT_EQUAL_HEX32(pmb_base->rw_cbs.reg_coils_cb, mbc_reg_coils_master_cb);
    TEST_ASSERT_EQUAL_HEX32(pmb_base->rw_cbs.reg_discrete_cb, mbc_reg_discrete_master_cb);

    TEST_ESP_OK(mbc_master_start(mbm_handle));

    const mb_parameter_descriptor_t *param_descriptor = NULL;
    TEST_ESP_OK(mbc_master_get_cid_info(mbm_handle, par_index, &param_descriptor));
    TEST_ASSERT_EQUAL_HEX32(&descriptors[par_index], param_descriptor);
    uint8_t reg_data_in[] = {0x11, 0x22, 0x33, 0x44};
    uint8_t reg_data_out[4] = {0};
    mbm_opts->reg_buffer_size = param_descriptor->mb_size;
    mbm_opts->reg_buffer_ptr = &reg_data_out[0];
    esp_err_t err = ESP_FAIL;
    uint8_t byte_cnt = 0;
    // Check that request function forms correct buffer
    switch (param_descriptor->mb_param_type)
    {
        case MB_PARAM_HOLDING:
            err = mbc_reg_holding_master_cb(pmb_base, reg_data_in, param_descriptor->mb_reg_start,
                                            param_descriptor->mb_size, MB_REG_READ);
            for (int i = 0; (i < param_descriptor->mb_size); i++)
            {
                TEST_ASSERT_EQUAL_HEX8(reg_data_in[(i << 1)], reg_data_out[(i << 1) + 1]);
                TEST_ASSERT_EQUAL_HEX8(reg_data_in[(i << 1) + 1], reg_data_out[(i << 1)]);
            }
            ESP_LOG_BUFFER_HEX_LEVEL(TAG ", INPUT_BUFF", (void *)reg_data_in, (param_descriptor->mb_size << 1), ESP_LOG_INFO);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG ", OUTPUT_BUFF", (void *)reg_data_out, (param_descriptor->mb_size << 1), ESP_LOG_INFO);
            break;

        case MB_PARAM_INPUT:
            err = mbc_reg_input_master_cb(pmb_base, reg_data_in, param_descriptor->mb_reg_start,
                                        param_descriptor->mb_size);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG ", INPUT_BUFF", (void *)reg_data_in, (param_descriptor->mb_size << 1), ESP_LOG_INFO);
            for (int i = 0; (i < param_descriptor->mb_size); i++)
            {
                TEST_ASSERT_EQUAL_HEX8(reg_data_in[(i << 1)], reg_data_out[(i << 1) + 1]);
                TEST_ASSERT_EQUAL_HEX8(reg_data_in[(i << 1) + 1], reg_data_out[(i << 1)]);
            }
            ESP_LOG_BUFFER_HEX_LEVEL(TAG ", OUTPUT_BUFF", (void *)reg_data_out, (param_descriptor->mb_size << 1), ESP_LOG_INFO);
            break;

        case MB_PARAM_COIL:
            reg_data_in[0] = 0xFF;
            reg_data_in[1] = 0xFF;
            err = mbc_reg_coils_master_cb(pmb_base, reg_data_in, param_descriptor->mb_reg_start, param_descriptor->mb_size, MB_REG_READ);
            byte_cnt = (param_descriptor->mb_size & 0x0007) ? ((param_descriptor->mb_size >> 3) + 1) : (param_descriptor->mb_size >> 3);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG ", INPUT_BUFF", (void *)reg_data_in, byte_cnt, ESP_LOG_INFO);
            TEST_ASSERT_EQUAL_HEX8((reg_data_out[0] & param_descriptor->param_opts.opt1), param_descriptor->param_opts.opt1);
            TEST_ASSERT_EQUAL_HEX8((reg_data_out[1] & ((param_descriptor->param_opts.opt1 >> 8) & 0xFF)), ((param_descriptor->param_opts.opt1 >> 8) & 0xFF));
            ESP_LOG_BUFFER_HEX_LEVEL(TAG ", OUTPUT_BUFF", (void *)reg_data_out, byte_cnt, ESP_LOG_INFO);
            break;

        case MB_PARAM_DISCRETE:
            reg_data_in[0] = 0xFF;
            reg_data_in[1] = 0xFF;
            err = mbc_reg_discrete_master_cb(pmb_base, reg_data_in, param_descriptor->mb_reg_start, param_descriptor->mb_size);
            byte_cnt = (param_descriptor->mb_size & 0x0007) ? ((param_descriptor->mb_size >> 3) + 1) : (param_descriptor->mb_size >> 3);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG ", INPUT_BUFF", (void *)reg_data_in, byte_cnt, ESP_LOG_INFO);
            TEST_ASSERT_EQUAL_HEX8((reg_data_out[0] & param_descriptor->param_opts.opt1), param_descriptor->param_opts.opt1);
            TEST_ASSERT_EQUAL_HEX8((reg_data_out[1] & ((param_descriptor->param_opts.opt1 >> 8) & 0xFF)), ((param_descriptor->param_opts.opt1 >> 8) & 0xFF));
            ESP_LOG_BUFFER_HEX_LEVEL(TAG ", OUTPUT_BUFF", (void *)reg_data_out, byte_cnt, ESP_LOG_INFO);
            break;

        default:
            break;
    }
    TEST_ESP_OK(mbc_master_stop(mbm_handle));
    TEST_ESP_OK(mbc_master_delete(mbm_handle));
    ESP_LOGI(TAG, "Test passed successfully.");
    return err;
}

// Check if modbus controller object forms correct modbus request from data dictionary
// and is able to transfer data using mb_object. Check possible errors returned back from
// mb_object and make sure the modbus controller handles them correctly.
TEST(unit_test_controller, test_master_send_read_request)
{
    ESP_LOGI(TAG, "TEST: Check the modbus master controller handles read requests correctly.");
    TEST_ESP_ERR(ESP_OK, test_master_read_req(CID_DEV_REG0_INPUT, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, test_master_read_req(CID_DEV_REG0_INPUT, MB_ETIMEDOUT));
    TEST_ESP_ERR(ESP_ERR_INVALID_RESPONSE, test_master_read_req(CID_DEV_REG0_INPUT, MB_ERECVDATA));
    TEST_ESP_ERR(ESP_OK, test_master_read_req(CID_DEV_REG0_HOLD, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_INVALID_RESPONSE, test_master_read_req(CID_DEV_REG0_HOLD, MB_ERECVDATA));
    TEST_ESP_ERR(ESP_OK, test_master_read_req(CID_DEV_REG0_COIL, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, test_master_read_req(CID_DEV_REG0_COIL, MB_ETIMEDOUT));
    TEST_ESP_ERR(ESP_OK, test_master_read_req(CID_DEV_REG0_DISCRITE, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, test_master_read_req(CID_DEV_REG0_DISCRITE, MB_ETIMEDOUT));
}

TEST(unit_test_controller, test_master_send_write_request)
{
    ESP_LOGI(TAG, "TEST: Check the modbus master controller handles write requests correctly.");
    TEST_ESP_ERR(ESP_OK, test_master_write_req(CID_DEV_REG0_HOLD, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_INVALID_RESPONSE, test_master_write_req(CID_DEV_REG0_HOLD, MB_ERECVDATA));
    TEST_ESP_ERR(ESP_OK, test_master_write_req(CID_DEV_REG0_COIL, MB_ENOERR));
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, test_master_write_req(CID_DEV_REG0_COIL, MB_ETIMEDOUT));
}

TEST(unit_test_controller, test_slave_check_area_descriptor)
{
    ESP_LOGI(TAG, "TEST: Check the modbus master controller defines the area descriptors correctly.");
    test_slave_check_descriptor(CID_DEV_INPUT_AREA);
    test_slave_check_descriptor(CID_DEV_HOLD_AREA);
    test_slave_check_descriptor(CID_DEV_COIL_AREA);
    test_slave_check_descriptor(CID_DEV_DISCR_AREA);
}

TEST(unit_test_controller, test_master_register_callbacks)
{
    ESP_LOGI(TAG, "TEST: Check the modbus master controller handles mapping callback functions correctly.");
    TEST_ESP_ERR(ESP_OK, test_master_check_callback(CID_DEV_REG0_HOLD, MB_ENOERR));
    TEST_ESP_ERR(ESP_OK, test_master_check_callback(CID_DEV_REG0_INPUT, MB_ENOERR));
    TEST_ESP_ERR(ESP_OK, test_master_check_callback(CID_DEV_REG0_COIL, MB_ENOERR));
    TEST_ESP_ERR(ESP_OK, test_master_check_callback(CID_DEV_REG0_DISCRITE, MB_ENOERR));
}

TEST_GROUP_RUNNER(unit_test_controller)
{
    RUN_TEST_CASE(unit_test_controller, test_master_send_read_request);
    RUN_TEST_CASE(unit_test_controller, test_master_send_write_request);
    RUN_TEST_CASE(unit_test_controller, test_master_register_callbacks);
    RUN_TEST_CASE(unit_test_controller, test_slave_check_area_descriptor);
}
