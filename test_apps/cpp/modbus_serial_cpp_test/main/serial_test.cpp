#include "esp_log.h"

#include "sdkconfig.h"
#include "mbcontroller.h"

#define TEST_PORT_NUM (uart_port_t)1
#define TEST_SPEED 115200

#define TAG "CPP_TEST"
#define MB_SLAVE_SHORT_ADDRESS 1

enum {
    MB_DEVICE_ADDR1 = 1
};

// Enumeration of all supported CIDs for device (used in parameter definition table)
enum {
    CID_DEV_REG0 = 0
};

#define STR(fieldname) ((const char*)( fieldname ))
#define OPTS(min_val, max_val, step_val) { .opt1 = min_val, .opt2 = max_val, .opt3 = step_val }

static void *pmaster_handle = NULL;
static void *pslave_handle = NULL;

// Example Data (Object) Dictionary for Modbus parameters
const mb_parameter_descriptor_t dummy_dict[] = {
    // CID, Name, Units, Modbus addr, register type, Modbus Reg Start Addr, Modbus Reg read length, 
    // Instance offset (NA), Instance type, Instance length (bytes), Options (NA), Permissions
    { CID_DEV_REG0, STR("MB_hold_reg-0"), STR("Data"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 0, 1,
                    0, PARAM_TYPE_U16, PARAM_SIZE_U16, OPTS( 0,0,0 ), PAR_PERMS_READ_WRITE_TRIGGER },
};

// Calculate number of parameters in the table
const uint16_t num_device_parameters = (sizeof(dummy_dict)/sizeof(dummy_dict[0]));

// Modbus serial master initialization
static esp_err_t master_serial_init(void **pinst)
{
    mb_communication_info_t comm;
    comm.ser_opts.port = (uart_port_t)TEST_PORT_NUM;
    comm.ser_opts.mode = (mb_comm_mode_t)MB_RTU;
    comm.ser_opts.baudrate = TEST_SPEED;
    comm.ser_opts.parity = MB_PARITY_NONE;
    comm.ser_opts.uid = 0;
    comm.ser_opts.response_tout_ms = 100;
    comm.ser_opts.data_bits = UART_DATA_8_BITS;
    comm.ser_opts.stop_bits = UART_STOP_BITS_1;
    // Initialize Modbus controller
    esp_err_t err = mbc_master_create_serial(&comm, pinst);
    MB_RETURN_ON_FALSE((pinst != NULL), ESP_ERR_INVALID_STATE, TAG,
                                "mbc master initialization fail.");
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "mbc master initialization fail, returns(0x%x).", (int)err);
    err = mbc_master_set_descriptor(*pinst, &dummy_dict[0], num_device_parameters);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                                "mbc master set descriptor fail, returns(0x%x).", (int)err);
    err = mbc_master_start(*pinst);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "mbc master start fail, returned (0x%x).", (int)err);
    const mb_parameter_descriptor_t *pdescriptor = NULL;
    err = mbc_master_get_cid_info(*pinst, CID_DEV_REG0, &pdescriptor);
    MB_RETURN_ON_FALSE(((err != ESP_ERR_NOT_FOUND) && (pdescriptor != NULL)), ESP_ERR_INVALID_STATE, TAG,
                            "mbc master get descriptor fail, returned (0x%x).", (int)err);
    uint16_t regs[] = {0x1111, 0x2222};
    uint8_t type = 0;
    err = mbc_master_get_parameter(*pinst, pdescriptor->cid, (uint8_t *)&regs[0], &type);
    MB_RETURN_ON_FALSE((err != ESP_ERR_INVALID_STATE), ESP_ERR_INVALID_STATE, TAG,
                            "mbc master get parameter fail, returned (0x%x).", (int)err);
    ESP_LOGI(TAG, "Modbus master stack initialized...");
    return ESP_OK;
}

// Modbus serial slave initialization
static esp_err_t slave_serial_init(void **pinst)
{
    mb_register_area_descriptor_t reg_area;
    mb_communication_info_t comm;
    comm.ser_opts.port = (uart_port_t)TEST_PORT_NUM;
    comm.ser_opts.mode = (mb_comm_mode_t)MB_RTU;
    comm.ser_opts.baudrate = TEST_SPEED;
    comm.ser_opts.parity = MB_PARITY_NONE;
    comm.ser_opts.uid = MB_SLAVE_SHORT_ADDRESS;
    comm.ser_opts.response_tout_ms = 100;
    comm.ser_opts.data_bits = UART_DATA_8_BITS;
    comm.ser_opts.stop_bits = UART_STOP_BITS_1;
    // Initialize Modbus controller
    esp_err_t err = mbc_slave_create_serial(&comm, pinst);
    MB_RETURN_ON_FALSE((pinst != NULL), ESP_ERR_INVALID_STATE, TAG,
                                "mbc slave initialization fail.");
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "mbc slave initialization fail, returns(0x%x).", (int)err);
    uint16_t holding_regs[] = {0x1111, 0x2222, 0x3333, 0x4444};
    reg_area.type = MB_PARAM_HOLDING;
    reg_area.start_offset = 0;
    reg_area.address = (void*)&holding_regs[0];
    reg_area.size = sizeof(holding_regs);
    reg_area.access = MB_ACCESS_RW;
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(*pinst, reg_area));
    err = mbc_slave_start(*pinst);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "mbc slave start fail, returned (0x%x).", (int)err);
    ESP_LOGI(TAG, "Modbus slave stack initialized...");
    return err;
}

mb_exception_t test_handler(void *pinst, uint8_t *frame_ptr, uint16_t *plen)
{
    return MB_EX_CRITICAL; // Set the exception code for slave appropriately
}

static int check_custom_handlers(void *pinst)
{
    mb_fn_handler_fp phandler = NULL;
    int entry;
    uint16_t count = 0;
    esp_err_t err = ESP_FAIL;
    err = mbc_get_handler_count(pinst, &count);
    MB_RETURN_ON_FALSE((err == ESP_OK), 0, TAG,
                            "mbc slave get handler count, returns(0x%x).", (int)err);
    ESP_LOGI(TAG,"Object %p, custom handler test, (registered:max) handlers: %d:%d.", pinst, count, CONFIG_FMB_FUNC_HANDLERS_MAX);
    for (entry = 0x01; entry < CONFIG_FMB_FUNC_HANDLERS_MAX; entry++) {
        // Try to remove the handler
        err = mbc_delete_handler(pinst, (uint8_t)entry);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Could not remove handler for command: (0x%x), returned (0x%x), already empty?", entry, (int)err);
        }
        err = mbc_set_handler(pinst, (uint8_t)entry, test_handler);
        if (err != ESP_OK) {
            ESP_LOGE(TAG,"Could not set handler for command 0x%x, returned (0x%x).", entry, (int)err);
            break;
        } else {
            ESP_LOGI(TAG,"Set handler for command 0x%x, returned (0x%x).", entry, (int)err);
        }
        err = mbc_get_handler(pinst, (uint8_t)entry, &phandler);
        if (err != ESP_OK || phandler != test_handler) {
            ESP_LOGE(TAG, "Could not get handler for command (0x%x) = (%p), returned (0x%x).", entry, phandler, (int)err);
            break;
        }
    }
    ESP_LOGI(TAG, "Last entry processed: %d.", entry);
    return entry;
}

// Intentionally verify that atomic values are layout compatible with original types
static_assert(
    sizeof(std::atomic<int>) == sizeof(int),
    "CPP atomic int types are not layout compatible with int"
);

extern "C" void app_main(void)
{
    // Initialization of device peripheral and objects
    ESP_LOGI(TAG, "Setup master cpp....");
    ESP_ERROR_CHECK(master_serial_init(&pmaster_handle));
    ESP_ERROR_CHECK(mbc_master_stop(pmaster_handle));
    int last_entry = check_custom_handlers(pmaster_handle);
    MB_RETURN_ON_FALSE((last_entry >= CONFIG_FMB_FUNC_HANDLERS_MAX), ;, TAG,
                        "Incorrect number of command entries for master: %d.", (int)last_entry);
    ESP_ERROR_CHECK(mbc_master_delete(pmaster_handle));
    ESP_LOGI(TAG, "Master test passed successfully.");
    ESP_LOGI(TAG, "Setup slave cpp....");
    ESP_ERROR_CHECK(slave_serial_init(&pslave_handle));
    last_entry = check_custom_handlers(pslave_handle);
    // explicitly check stop method before delete
    ESP_ERROR_CHECK(mbc_slave_stop(pslave_handle));
    ESP_ERROR_CHECK(mbc_slave_delete(pslave_handle));
    MB_RETURN_ON_FALSE((last_entry >= CONFIG_FMB_FUNC_HANDLERS_MAX), ;, TAG,
                        "Incorrect number of command entries for slave: %d.", (int)last_entry);
    ESP_LOGI(TAG, "Slave test passed successfully.");
}
