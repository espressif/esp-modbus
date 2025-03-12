/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"                // for esp_err_t
#include "esp_timer.h"              // for esp_timer_get_time()
#include "sdkconfig.h"              // for KConfig defines

#include "mbc_slave.h"              // for slave private type definitions
#include "esp_modbus_common.h"      // for common defines
#include "esp_modbus_slave.h"       // for public slave defines

#include "mb_utils.h"               // for stack bit setting utilities

#if CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT

#define MB_ID_BYTE0(id) ((uint8_t)(id))
#define MB_ID_BYTE1(id) ((uint8_t)(((uint16_t)(id) >> 8) & 0xFF))
#define MB_ID_BYTE2(id) ((uint8_t)(((uint32_t)(id) >> 16) & 0xFF))
#define MB_ID_BYTE3(id) ((uint8_t)(((uint32_t)(id) >> 24) & 0xFF))

#define MB_CONTROLLER_SLAVE_ID (CONFIG_FMB_CONTROLLER_SLAVE_ID)
#define MB_SLAVE_ID_SHORT      (MB_ID_BYTE3(MB_CONTROLLER_SLAVE_ID))

// Slave ID constant
static uint8_t mb_slave_id[] = { MB_ID_BYTE0(MB_CONTROLLER_SLAVE_ID),
                                MB_ID_BYTE1(MB_CONTROLLER_SLAVE_ID),
                                MB_ID_BYTE2(MB_CONTROLLER_SLAVE_ID) };

#endif

static const char TAG[] __attribute__((unused)) = "MB_CONTROLLER_SLAVE";

// Searches the register in the area specified by type, returns descriptor if found, else NULL
static mb_descr_entry_t *mbc_slave_find_reg_descriptor(void *ctx, mb_param_type_t type, uint16_t addr, size_t regs)
{
    mb_descr_entry_t *it;
    uint16_t reg_size = 0;
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);

    if (LIST_EMPTY(&mbs_opts->area_descriptors[type])) {
        return NULL;
    }
    // search for the register in each area
    for (it = LIST_FIRST(&mbs_opts->area_descriptors[type]); it != NULL; it = LIST_NEXT(it, entries)) {
        reg_size = REG_SIZE(type, it->size);
        if ((addr >= it->start_offset)
            && (it->p_data)
            && (regs >= 1)
            && ((addr + regs) <= (it->start_offset + reg_size))
            && (reg_size >= 1)) {
            return it;
        }
    }
    return NULL;
}

static void mbc_slave_free_descriptors(void *ctx)
{
    mb_descr_entry_t *it;
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);

    for (int descr_type = 0; descr_type < MB_PARAM_COUNT; descr_type++) {
        while ((it = LIST_FIRST(&mbs_opts->area_descriptors[descr_type]))) {
            LIST_REMOVE(it, entries);
            free(it);
        }
    }
}

void mbc_slave_init_iface(void *ctx)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);

    // Initialize list head for register areas
    LIST_INIT(&mbs_opts->area_descriptors[MB_PARAM_INPUT]);
    LIST_INIT(&mbs_opts->area_descriptors[MB_PARAM_HOLDING]);
    LIST_INIT(&mbs_opts->area_descriptors[MB_PARAM_COIL]);
    LIST_INIT(&mbs_opts->area_descriptors[MB_PARAM_DISCRETE]);
}

/**
 * Modbus controller delete function
 */
esp_err_t mbc_slave_delete(void *ctx)
{
    esp_err_t error = ESP_OK;
    // Is initialization done?
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                        "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *mbs_controller = MB_SLAVE_GET_IFACE(ctx);
    
    // Check if interface has been initialized
    MB_RETURN_ON_FALSE(mbs_controller->delete,
                        ESP_ERR_INVALID_STATE, TAG,
                        "Slave interface is not correctly configured.");
    // Call the slave controller destroy function
    error = mbs_controller->delete(ctx);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "Slave delete failure error=(0x%x).", (uint16_t)error);
    }
    // Destroy all opened descriptors
    mbc_slave_free_descriptors(ctx);
    free(mbs_controller);
    mbs_controller = NULL;
    return error;
}

/**
 * Critical section lock function
 */
esp_err_t mbc_slave_lock(void *ctx)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                            "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *mbs_controller = MB_SLAVE_GET_IFACE(ctx);
    mb_base_t *pmb_obj = (mb_base_t *)mbs_controller->mb_base;
    MB_RETURN_ON_FALSE((pmb_obj && pmb_obj->lock), ESP_ERR_INVALID_STATE, TAG,
                            "Slave interface is not correctly initialized.");
    CRITICAL_SECTION_LOCK(pmb_obj->lock);
    return ESP_OK;
}

/**
 * Critical section unlock function
 */
esp_err_t mbc_slave_unlock(void *ctx)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                            "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *mbs_controller = MB_SLAVE_GET_IFACE(ctx);
    mb_base_t *pmb_obj = (mb_base_t *)mbs_controller->mb_base;
    MB_RETURN_ON_FALSE((pmb_obj && pmb_obj->lock), ESP_ERR_INVALID_STATE, TAG,
                            "Slave interface is not correctly initialized.");
    CRITICAL_SECTION_UNLOCK(pmb_obj->lock);
    return ESP_OK;
}

#if CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT
/**
 * Set object ID for the Modbus controller
 */
esp_err_t mbc_set_slave_id(void *ctx, uint8_t slave_addr, bool is_running, uint8_t const *pdata, uint8_t data_len)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                        "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *pmbs_controller = MB_SLAVE_GET_IFACE(ctx);
    // The Report Slave ID functionality is useful for TCP and gateway,
    // so the design decision is to keep this functionality for all slaves
    // Set the slave ID if the KConfig option is selected
    mb_err_enum_t status = mbs_set_slave_id(pmbs_controller->mb_base, slave_addr, is_running, (uint8_t *)pdata, data_len);
    MB_RETURN_ON_FALSE((status == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG, "mb stack set slave ID failure.");
    return MB_ERR_TO_ESP_ERR(status);
}

/**
 * Get object ID from the Modbus controller
 */
esp_err_t mbc_get_slave_id(void *ctx, uint8_t const *pdata, uint8_t *pdata_len)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                        "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *pmbs_controller = MB_SLAVE_GET_IFACE(ctx);
    mb_err_enum_t status = mbs_get_slave_id(pmbs_controller->mb_base, (uint8_t *)pdata, pdata_len);
    MB_RETURN_ON_FALSE((status == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG, "mb stack get slave ID failure.");
    return MB_ERR_TO_ESP_ERR(status);
}
#endif

/**
 * Start Modbus controller start function
 */
esp_err_t mbc_slave_start(void *ctx)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                        "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *mbs_controller = MB_SLAVE_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE(mbs_controller->start, ESP_ERR_INVALID_STATE, TAG,
                    "Slave interface is not correctly configured.");
    uint8_t slave_uid = mbs_controller->opts.comm_opts.common_opts.uid;
#if CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT
    // Set the default slave ID if the KConfig option is selected
    error = mbc_set_slave_id(mbs_controller, slave_uid, true, (uint8_t *)mb_slave_id, sizeof(mb_slave_id));
    MB_RETURN_ON_FALSE((error == ESP_OK), ESP_ERR_INVALID_STATE, TAG, "mb stack set slave ID failure.");
#endif
    error = mbs_controller->start(ctx);
    MB_RETURN_ON_FALSE((error == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                    "Slave start failure error=(0x%x).", (uint16_t)error);
    mbs_controller->is_active = true;
    return error;
}

/**
 * Start Modbus controller stop function
 */
esp_err_t mbc_slave_stop(void *ctx)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                        "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *mbs_controller = MB_SLAVE_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE(mbs_controller->stop,
                        ESP_ERR_INVALID_STATE, TAG,
                        "Slave interface is not correctly configured.");
    error = mbs_controller->stop(ctx);
    MB_RETURN_ON_FALSE((error == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                    "Slave stop failure error=(0x%x).", (uint16_t)error);
    mbs_controller->is_active = false;
    return error;
}

/**
 * Blocking function to get event on parameter group change for application task
 */
mb_event_group_t mbc_slave_check_event(void *ctx, mb_event_group_t group)
{
    MB_RETURN_ON_FALSE(ctx, MB_EVENT_NO_EVENTS, TAG,
                        "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *mbs_controller = MB_SLAVE_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((mbs_controller->check_event && mbs_controller->is_active),
                    MB_EVENT_NO_EVENTS, TAG,
                    "Slave interface is not correctly configured.");
    mb_event_group_t event = mbs_controller->check_event(ctx, group);
    return event;
}

/**
 * Function to get notification about parameter change from application task
 */
esp_err_t mbc_slave_get_param_info(void *ctx, mb_param_info_t *reg_info, uint32_t timeout)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                    "Slave interface is not correctly initialized.");
    mbs_controller_iface_t *mbs_controller = MB_SLAVE_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((mbs_controller->get_param_info && mbs_controller->is_active),
                    ESP_ERR_INVALID_STATE, TAG,
                    "Slave interface is not correctly configured.");
    return mbs_controller->get_param_info(ctx, reg_info, timeout);
}

/**
 * Function to set area descriptors for modbus parameters
 */
esp_err_t mbc_slave_set_descriptor(void *ctx, mb_register_area_descriptor_t descr_data)
{
    MB_RETURN_ON_FALSE((ctx), ESP_ERR_INVALID_STATE, TAG,
                    "Slave interface is not correctly initialized.");
    esp_err_t error = ESP_OK;
    mbs_controller_iface_t *mbs_controller = MB_SLAVE_GET_IFACE(ctx);
    if (mbs_controller->set_descriptor) {
        error = mbs_controller->set_descriptor(ctx, descr_data);
        MB_RETURN_ON_FALSE((error == ESP_OK),
                        ESP_ERR_INVALID_STATE, TAG,
                        "Slave set descriptor failure error=(0x%x).",
                        (uint16_t)error);
    } else {
        mb_slave_options_t *mbs_opts = &mbs_controller->opts;

        MB_RETURN_ON_FALSE((descr_data.size < MB_INST_MAX_SIZE) && (descr_data.size >= MB_INST_MIN_SIZE), 
                            ESP_ERR_INVALID_ARG, TAG, "mb area size is incorrect.");
        uint16_t reg_size = REG_SIZE(descr_data.type, descr_data.size);

        // Check if the address is already in the descriptor list
        mb_descr_entry_t *it = mbc_slave_find_reg_descriptor(ctx, descr_data.type, descr_data.start_offset, reg_size);
        if (!it) {
            // Start register exists in any area?
            it = mbc_slave_find_reg_descriptor(ctx, descr_data.type, descr_data.start_offset, 1);
        }

        MB_RETURN_ON_FALSE((it == NULL), ESP_ERR_INVALID_ARG, TAG, "mb incorrect descriptor or already defined.");

        mb_descr_entry_t *new_descr = (mb_descr_entry_t*) heap_caps_malloc(sizeof(mb_descr_entry_t),
                                            MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
        MB_RETURN_ON_FALSE(new_descr, ESP_ERR_NO_MEM, TAG, "mb can not allocate memory for descriptor.");
        new_descr->start_offset = descr_data.start_offset;
        new_descr->type = descr_data.type;
        new_descr->p_data = descr_data.address;
        new_descr->size = descr_data.size;
        new_descr->access = descr_data.access;
        LIST_INSERT_HEAD(&mbs_opts->area_descriptors[descr_data.type], new_descr, entries);
        error = ESP_OK;
    }
    return error;
}

// The helper function to get time stamp in microseconds
static uint64_t mbc_slave_get_time_stamp(void)
{
    uint64_t time_stamp = esp_timer_get_time();
    return time_stamp;
}

// Helper function to send parameter information to application task
static esp_err_t mbc_slave_send_param_info(void *ctx, mb_event_group_t par_type, uint16_t mb_offset,
                                    uint8_t *par_address, uint16_t par_size)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                    "Slave interface is not correctly initialized.");
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    esp_err_t error = ESP_FAIL;
    mb_param_info_t par_info;
    // Check if queue is not full the send parameter information
    par_info.type = par_type;
    par_info.size = par_size;
    par_info.address = par_address;
    par_info.time_stamp = mbc_slave_get_time_stamp();
    par_info.mb_offset = mb_offset;
    BaseType_t status = xQueueSend(mbs_opts->notification_queue_handle, &par_info, MB_PAR_INFO_TOUT);
    if (pdTRUE == status) {
        ESP_LOGD(TAG, "Queue send parameter info (type, address, size): %d, 0x%" PRIx32 ", %d",
                        (int)par_type, (uint32_t)par_address, (int)par_size);
        error = ESP_OK;
    } else if (errQUEUE_FULL == status) {
        ESP_LOGD(TAG, "Parameter queue is overflowed.");
    }
    return error;
}

// Helper function to send notification
static esp_err_t mbc_slave_send_param_access_notification(void *ctx, mb_event_group_t event)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                        "Slave interface is not correctly initialized.");
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    esp_err_t err = ESP_FAIL;
    mb_event_group_t bits = (mb_event_group_t)xEventGroupSetBits(mbs_opts->event_group_handle, (EventBits_t)event);
    if (bits & event) {
        ESP_LOGD(TAG, "The MB_REG_CHANGE_EVENT = 0x%.2x is set.", (int)event);
        err = ESP_OK;
    }
    return err;
}

/*
 * Below are the common slave read/write register callback functions
 * The concrete slave port can override them using interface function pointers
 */

// Callback function for reading of MB Input Registers
mb_err_enum_t mbc_reg_input_slave_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t address, uint16_t n_regs)
{
    void *ctx = (void *)MB_SLAVE_GET_IFACE_FROM_BASE(inst);
    MB_RETURN_ON_FALSE(reg_buffer, MB_EINVAL, TAG, "Slave stack call failed.");
    mb_err_enum_t status = MB_ENOERR;
    address--; // address of register is already +1
    mb_descr_entry_t *it = mbc_slave_find_reg_descriptor(ctx, MB_PARAM_INPUT, address, n_regs);
    if (it) {
        uint16_t input_reg_start = (uint16_t)it->start_offset; // Get Modbus start address
        uint8_t *input_buffer = (uint8_t *)it->p_data; // Get instance address
        uint16_t regs = n_regs;
        uint16_t reg_index;
        // If input or configuration parameters are incorrect then return an error to stack layer
        reg_index = (uint16_t)(address - input_reg_start);
        reg_index <<= 1; // register Address to byte address
        input_buffer += reg_index;
        uint8_t *buffer_start = input_buffer;
        CRITICAL_SECTION(inst->lock)
        {
            while (regs > 0) {
                _XFER_2_RD(reg_buffer, input_buffer);
                reg_index += 2;
                regs -= 1;
            }
        }
        // Send access notification
        (void)mbc_slave_send_param_access_notification(ctx, MB_EVENT_INPUT_REG_RD);
        // Send parameter info to application task
        (void)mbc_slave_send_param_info(ctx, MB_EVENT_INPUT_REG_RD, address,
                                            (uint8_t *)buffer_start, n_regs);
    } else {
        status = MB_ENOREG;
    }
    return status;
}

// Callback function for reading of MB Holding Registers
// Executed by stack when request to read/write holding registers is received
mb_err_enum_t mbc_reg_holding_slave_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t address, uint16_t n_regs, mb_reg_mode_enum_t mode)
{
    void *ctx = (void *)MB_SLAVE_GET_IFACE_FROM_BASE(inst);
    MB_RETURN_ON_FALSE(reg_buffer, MB_EINVAL, TAG, "Slave stack call failed.");
    mb_err_enum_t status = MB_ENOERR;
    uint16_t reg_index;
    address--; // address of register is already +1
    mb_descr_entry_t *it = mbc_slave_find_reg_descriptor(ctx, MB_PARAM_HOLDING, address, n_regs);
    if (it) {
        uint16_t reg_holding_start = (uint16_t)it->start_offset; // Get Modbus start address
        uint8_t *holding_buffer = (uint8_t *)it->p_data; // Get instance address
        uint16_t regs = n_regs;
        reg_index = (uint16_t) (address - reg_holding_start);
        reg_index <<= 1; // register Address to byte address
        holding_buffer += reg_index;
        uint8_t *buffer_start = holding_buffer;
        switch (mode) {
            case MB_REG_READ:
                if (it->access != MB_ACCESS_WO) {
                    CRITICAL_SECTION(inst->lock)
                    {
                        while (regs > 0) {
                            _XFER_2_RD(reg_buffer, holding_buffer);
                            reg_index += 2;
                            regs -= 1;
                        };
                    }
                    // Send access notification
                    (void)mbc_slave_send_param_access_notification(ctx, MB_EVENT_HOLDING_REG_RD);
                    // Send parameter info
                    (void)mbc_slave_send_param_info(ctx, MB_EVENT_HOLDING_REG_RD, address,
                                                        (uint8_t *)buffer_start, n_regs);
                } else {
                    status = MB_EINVAL;
                }
                break;
            case MB_REG_WRITE:
                if (it->access != MB_ACCESS_RO) {
                    CRITICAL_SECTION(inst->lock)
                    {
                        while (regs > 0) {
                            _XFER_2_WR(holding_buffer, reg_buffer);
                            holding_buffer += 2;
                            reg_index += 2;
                            regs -= 1;
                        };
                    }
                    // Send access notification
                    (void)mbc_slave_send_param_access_notification(ctx, MB_EVENT_HOLDING_REG_WR);
                    // Send parameter info
                    (void)mbc_slave_send_param_info(ctx, MB_EVENT_HOLDING_REG_WR, (uint16_t)address,
                                    (uint8_t *)buffer_start, (uint16_t)n_regs);
                } else {
                    status = MB_EINVAL;
                }
                break;
        }
    } else {
        status = MB_ENOREG;
    }
    return status;
}

// Callback function for reading of MB Coils Registers
mb_err_enum_t mbc_reg_coils_slave_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t address, uint16_t n_coils, mb_reg_mode_enum_t mode)
{
    void *ctx =(void *)MB_SLAVE_GET_IFACE_FROM_BASE(inst);
    MB_RETURN_ON_FALSE(ctx, MB_EILLSTATE, TAG, "Slave stack uninitialized.");
    MB_RETURN_ON_FALSE(reg_buffer, MB_EINVAL, TAG, "Slave stack call failed.");
    mb_err_enum_t status = MB_ENOERR;
    uint16_t reg_index;
    uint16_t coils = n_coils;
    address--; // The address is already +1
    mb_descr_entry_t *it = mbc_slave_find_reg_descriptor(ctx, MB_PARAM_COIL, address, n_coils);
    if (it) {
        uint16_t reg_coils_start = (uint16_t)it->start_offset; // MB offset of coils
        uint8_t *reg_coils_buf = (uint8_t *)it->p_data;
        reg_index = (uint16_t) (address - it->start_offset);
        char *coils_data_buf = (char *)(reg_coils_buf + (reg_index >> 3));
        switch (mode) {
                case MB_REG_READ:
                if (it->access != MB_ACCESS_WO) {
                    CRITICAL_SECTION(inst->lock)
                    {
                        while (coils > 0) {
                            uint8_t result = mb_util_get_bits((uint8_t *)reg_coils_buf, reg_index, 1);
                            mb_util_set_bits(reg_buffer, reg_index - (address - reg_coils_start), 1, result);
                            reg_index++;
                            coils--;
                        }
                    }
                    // Send an event to notify application task about event
                    (void)mbc_slave_send_param_access_notification(ctx, MB_EVENT_COILS_RD);
                    (void)mbc_slave_send_param_info(ctx, MB_EVENT_COILS_RD, address,
                                                        (uint8_t *)(coils_data_buf), n_coils);
                } else {
                    status = MB_EINVAL;
                }
                break;
            case MB_REG_WRITE:
                if (it->access != MB_ACCESS_RO) {
                    CRITICAL_SECTION(inst->lock)
                    {
                        while (coils > 0) {
                            uint8_t result = mb_util_get_bits(reg_buffer,
                                    reg_index - (address - reg_coils_start), 1);
                            mb_util_set_bits((uint8_t *)reg_coils_buf, reg_index, 1, result);
                            reg_index++;
                            coils--;
                        }
                    }
                    // Send an event to notify application task about event
                    (void)mbc_slave_send_param_access_notification(ctx, MB_EVENT_COILS_WR);
                    (void)mbc_slave_send_param_info(ctx, MB_EVENT_COILS_WR, address,
                                                        (uint8_t *)coils_data_buf, n_coils);
                } else {
                    status = MB_EINVAL;
                }
                break;
        } // switch ( mode )
    } else {
        // If the configuration or input parameters are incorrect then return error to stack
        status = MB_ENOREG;
    }
    return status;
}

// Callback function for reading of MB Discrete Input Registers
mb_err_enum_t mbc_reg_discrete_slave_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t address, uint16_t n_discrete)
{
    void *ctx = (void *)MB_SLAVE_GET_IFACE_FROM_BASE(inst);
    MB_RETURN_ON_FALSE(reg_buffer, MB_EINVAL, TAG, "Slave stack call failed.");
    mb_err_enum_t status = MB_ENOERR;
    uint16_t reg_index;
    uint16_t reg_bit_index;
    uint16_t n_reg;
    uint8_t *discrete_input_buf;
    // It already plus one in modbus function method.
    address--;
    mb_descr_entry_t *it = mbc_slave_find_reg_descriptor(ctx, MB_PARAM_DISCRETE, address, n_discrete);
    if (it) {
        uint16_t reg_discrete_start = (uint16_t)it->start_offset; // MB offset of registers
        n_reg = (n_discrete >> 3) + 1;
        discrete_input_buf = (uint8_t *)it->p_data; // the storage address
        reg_index = (uint16_t) (address - reg_discrete_start) / 8; // Get register index in the buffer for bit number
        reg_bit_index = (uint16_t)(address - reg_discrete_start) % 8; // Get bit index
        uint8_t *temp_buf = &discrete_input_buf[reg_index];
        CRITICAL_SECTION(inst->lock)
        {
            while (n_reg > 0) {
                *reg_buffer++ = mb_util_get_bits(&discrete_input_buf[reg_index++], reg_bit_index, 8);
                n_reg--;
            }
        }
        reg_buffer--;
        // Last discrete
        n_discrete = n_discrete % 8;
        // Filling zero to high bit
        *reg_buffer = *reg_buffer << (8 - n_discrete);
        *reg_buffer = *reg_buffer >> (8 - n_discrete);
        // Send an event to notify application task about event
        (void)mbc_slave_send_param_access_notification(ctx, MB_EVENT_DISCRETE_RD);
        (void)mbc_slave_send_param_info(ctx, MB_EVENT_DISCRETE_RD, address,
                                            (uint8_t *)temp_buf, n_discrete);
    } else {
        status = MB_ENOREG;
    }
    return status;
}
