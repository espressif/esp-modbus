/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// mbc_serial_master.c
// Serial master implementation of the  Modbus controller

#include <sys/time.h>               // for calculation of time stamp in milliseconds
#include "esp_log.h"                // for log_write
#include <string.h>                 // for memcpy
#include "freertos/FreeRTOS.h"      // for task creation
#include "freertos/task.h"          // for task api access
#include "freertos/event_groups.h"  // for event groups

#include "sdkconfig.h"              // for KConfig values
#include "esp_modbus_common.h"      // for common types
#include "esp_modbus_master.h"      // for public master types
#include "mbc_master.h"             // for private master types
#include "mbc_serial_master.h"      // for serial master create function and types

#include "mb_common.h"              // for mb types definition
#include "mb_config.h"
#include "mb_proto.h"

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

/*-----------------------Master mode use these variables----------------------*/

static const char *TAG = "mbc_serial.master";

// Modbus event processing task
static void mbc_ser_master_task(void *param)
{
    mbm_controller_iface_t *mbm_iface = MB_MASTER_GET_IFACE(param);
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(param);

    // Main Modbus stack processing cycle
    for (;;)
    {
        // Wait for poll events
        BaseType_t status = xEventGroupWaitBits(mbm_opts->event_group_handle,
                                                (BaseType_t)(MB_EVENT_STACK_STARTED),
                                                pdFALSE,
                                                pdFALSE,
                                                portMAX_DELAY);
        // Check if stack started then poll for data
        if (status & MB_EVENT_STACK_STARTED)
        {
            (void)mbm_iface->mb_base->poll(mbm_iface->mb_base);
        }
    }
}

// Modbus controller stack start function
static esp_err_t mbc_serial_master_start(void *ctx)
{
    mbm_controller_iface_t *mbm_iface = MB_MASTER_GET_IFACE(ctx);
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(ctx);
    mb_err_enum_t status = MB_EIO;
    mbm_iface->mb_base->descr.parent = ctx;
    MB_RETURN_ON_FALSE((mbm_opts->mbm_param_descriptor_size >= 1),
                       ESP_ERR_INVALID_ARG, TAG, "mb descriptor table size is incorrect.");
    status = mbm_iface->mb_base->enable(mbm_iface->mb_base);
    MB_RETURN_ON_FALSE((status == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack start fail, returned (0x%x).", (int)status);
    // Set the mbcontroller start flag
    EventBits_t flag = xEventGroupSetBits(mbm_opts->event_group_handle,
                                          (EventBits_t)MB_EVENT_STACK_STARTED);
    MB_RETURN_ON_FALSE((flag & MB_EVENT_STACK_STARTED),
                       ESP_ERR_INVALID_STATE, TAG, "mb stack start event set error.");
    mbm_iface->is_active = true;
    return ESP_OK;
}

// Modbus controller stack stop function
static esp_err_t mbc_serial_master_stop(void *ctx)
{
    mbm_controller_iface_t *mbm_iface = MB_MASTER_GET_IFACE(ctx);
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(ctx);
    mb_err_enum_t status = MB_EIO;
    mbm_iface->mb_base->descr.parent = ctx;

    // Set the mbcontroller start flag
    EventBits_t flag = xEventGroupClearBits(mbm_opts->event_group_handle,
                                            (EventBits_t)MB_EVENT_STACK_STARTED);
    status = mbm_iface->mb_base->disable(mbm_iface->mb_base);
    MB_RETURN_ON_FALSE((status == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack disable fail, returned (0x%x).", (int)status);
    MB_RETURN_ON_FALSE((flag & MB_EVENT_STACK_STARTED),
                       ESP_ERR_INVALID_STATE, TAG, "mb stack stop event set error.");
    mbm_iface->is_active = false;
    return ESP_OK;
}

// Modbus controller destroy function
static esp_err_t mbc_serial_master_delete(void *ctx)
{
    mbm_controller_iface_t *mbm_iface = MB_MASTER_GET_IFACE(ctx);
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(ctx);
    mb_err_enum_t mb_error = MB_ENOERR;

    // Check the stack started bit
    BaseType_t status = xEventGroupWaitBits(mbm_opts->event_group_handle,
                                            (BaseType_t)(MB_EVENT_STACK_STARTED),
                                            pdFALSE,
                                            pdFALSE,
                                            pdMS_TO_TICKS(MB_MASTER_TIMEOUT_MS_RESPOND));
    if (mbm_iface->is_active || (status & MB_EVENT_STACK_STARTED))
    {
        ESP_LOGV(TAG, "mb stack is active, try to disable.");
        MB_RETURN_ON_FALSE((mbc_serial_master_stop(ctx) == ESP_OK),
                           ESP_ERR_INVALID_STATE, TAG, "mb stack stop failure.");
    }

    vTaskDelete(mbm_opts->task_handle);
    mbm_opts->task_handle = NULL;
    vEventGroupDelete(mbm_opts->event_group_handle);
    mbm_opts->event_group_handle = NULL;
    mb_error = mbm_iface->mb_base->delete(mbm_iface->mb_base);
    MB_RETURN_ON_FALSE((mb_error == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack delete failure, returned (0x%x).", (int)mb_error);
    mbm_iface->mb_base = NULL;
    free(mbm_iface); // free the memory allocated
    return ESP_OK;
}

// Set Modbus parameter description table
static esp_err_t mbc_serial_master_set_descriptor(void *ctx, const mb_parameter_descriptor_t *descriptor, const uint16_t num_elements)
{
    MB_RETURN_ON_FALSE((descriptor), ESP_ERR_INVALID_ARG, TAG, "mb incorrect descriptor.");
    MB_RETURN_ON_FALSE((num_elements >= 1), ESP_ERR_INVALID_ARG, TAG, "mb table size is incorrect.");
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(ctx);
    const mb_parameter_descriptor_t *reg_ptr = descriptor;
    // Go through all items in the table to check all Modbus registers
    for (uint16_t counter = 0; counter < (num_elements); counter++, reg_ptr++)
    {
        // Below is the code to check consistency of the table format and required fields.
        MB_RETURN_ON_FALSE((reg_ptr->cid == counter),
                           ESP_ERR_INVALID_ARG, TAG, "mb descriptor cid field is incorrect.");
        MB_RETURN_ON_FALSE((reg_ptr->param_key),
                           ESP_ERR_INVALID_ARG, TAG, "mb descriptor param key is incorrect.");
        MB_RETURN_ON_FALSE((reg_ptr->mb_size > 0),
                           ESP_ERR_INVALID_ARG, TAG, "mb descriptor param size is incorrect.");
    }
    mbm_opts->param_descriptor_table = descriptor;
    mbm_opts->mbm_param_descriptor_size = num_elements;
    return ESP_OK;
}

// Send custom Modbus request defined as mb_param_request_t structure
static esp_err_t mbc_serial_master_send_request(void *ctx, mb_param_request_t *request, void *data_ptr)
{
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(ctx);
    mbm_controller_iface_t *mbm_controller_iface = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((request), ESP_ERR_INVALID_ARG, TAG, "mb request structure.");
    MB_RETURN_ON_FALSE((data_ptr), ESP_ERR_INVALID_ARG, TAG, "mb incorrect data pointer.");

    mb_err_enum_t mb_error = MB_EBUSY;
    esp_err_t error = ESP_FAIL;

    if (mb_port_evt_res_take(mbm_controller_iface->mb_base->port_obj, pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS)))
    {

        uint8_t mb_slave_addr = request->slave_addr;
        uint8_t mb_command = request->command;
        uint16_t mb_offset = request->reg_start;
        uint16_t mb_size = request->reg_size;

        // Set the buffer for callback function processing of received data
        mbm_opts->reg_buffer_ptr = (uint8_t *)data_ptr;
        mbm_opts->reg_buffer_size = mb_size;

        mb_port_evt_res_release(mbm_controller_iface->mb_base->port_obj);

        // Calls appropriate request function to send request and waits response
        switch (mb_command)
        {

#if MB_FUNC_READ_COILS_ENABLED
        case MB_FUNC_READ_COILS:
            mb_error = mbm_rq_read_coils(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr, (uint16_t)mb_offset,
                                         (uint16_t)mb_size,
                                         pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif

#if MB_FUNC_WRITE_COIL_ENABLED
        case MB_FUNC_WRITE_SINGLE_COIL:
            mb_error = mbm_rq_write_coil(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr, (uint16_t)mb_offset,
                                         *(uint16_t *)data_ptr,
                                         pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif

#if MB_FUNC_WRITE_MULTIPLE_COILS_ENABLED
        case MB_FUNC_WRITE_MULTIPLE_COILS:
            mb_error = mbm_rq_write_multi_coils(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr, (uint16_t)mb_offset,
                                                (uint16_t)mb_size, (uint8_t *)data_ptr,
                                                pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif

#if MB_FUNC_READ_DISCRETE_INPUTS_ENABLED
        case MB_FUNC_READ_DISCRETE_INPUTS:
            mb_error = mbm_rq_read_discrete_inputs(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr, (uint16_t)mb_offset,
                                                   (uint16_t)mb_size,
                                                   pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif

#if MB_FUNC_READ_HOLDING_ENABLED
        case MB_FUNC_READ_HOLDING_REGISTER:
            mb_error = mbm_rq_read_holding_reg(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr, (uint16_t)mb_offset,
                                               (uint16_t)mb_size,
                                               pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif

#if MB_FUNC_WRITE_HOLDING_ENABLED
        case MB_FUNC_WRITE_REGISTER:
            mb_error = mbm_rq_write_holding_reg(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr, (uint16_t)mb_offset,
                                                *(uint16_t *)data_ptr,
                                                pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif

#if MB_FUNC_WRITE_MULTIPLE_HOLDING_ENABLED
        case MB_FUNC_WRITE_MULTIPLE_REGISTERS:
            mb_error = mbm_rq_write_multi_holding_reg(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr,
                                                      (uint16_t)mb_offset, (uint16_t)mb_size,
                                                      (uint16_t *)data_ptr,
                                                      pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif

#if MB_FUNC_READWRITE_HOLDING_ENABLED
        case MB_FUNC_READWRITE_MULTIPLE_REGISTERS:
            mb_error = mbm_rq_rw_multi_holding_reg(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr, (uint16_t)mb_offset,
                                                   (uint16_t)mb_size, (uint16_t *)data_ptr,
                                                   (uint16_t)mb_offset, (uint16_t)mb_size,
                                                   pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif

#if MB_FUNC_READ_INPUT_ENABLED
        case MB_FUNC_READ_INPUT_REGISTER:
            mb_error = mbm_rq_read_inp_reg(mbm_controller_iface->mb_base, (uint8_t)mb_slave_addr, (uint16_t)mb_offset,
                                           (uint16_t)mb_size,
                                           pdMS_TO_TICKS(MB_MAX_RESP_DELAY_MS));
            break;
#endif
        default:
            ESP_LOGE(TAG, "%s: Incorrect or unsupported function in request (%u) ",
                     __FUNCTION__, mb_command);
            mb_error = MB_ENOREG;
            break;
        }
    }

    // Propagate the Modbus errors to higher level
    switch (mb_error)
    {
    case MB_ENOERR:
        error = ESP_OK;
        break;

    case MB_ENOREG:
        error = ESP_ERR_NOT_SUPPORTED; // Invalid register request
        break;

    case MB_ETIMEDOUT:
        error = ESP_ERR_TIMEOUT; // Slave did not send response
        break;

    case MB_EILLFUNC:
    case MB_ERECVDATA:
        error = ESP_ERR_INVALID_RESPONSE; // Invalid response from slave
        break;

    case MB_EBUSY:
        error = ESP_ERR_INVALID_STATE; // Master is busy (previous request is pending)
        break;

    default:
        ESP_LOGE(TAG, "%s: Incorrect return code (%x) ", __FUNCTION__, (uint16_t)mb_error);
        error = ESP_FAIL;
        break;
    }

    return error;
}

static esp_err_t mbc_serial_master_get_cid_info(void *ctx, uint16_t cid, const mb_parameter_descriptor_t **param_buffer)
{
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(ctx);

    MB_RETURN_ON_FALSE((param_buffer),
                       ESP_ERR_INVALID_ARG, TAG, "mb incorrect data buffer pointer.");
    MB_RETURN_ON_FALSE((mbm_opts->param_descriptor_table),
                       ESP_ERR_INVALID_ARG, TAG, "mb incorrect descriptor table or not set.");
    MB_RETURN_ON_FALSE((cid < mbm_opts->mbm_param_descriptor_size),
                       ESP_ERR_NOT_FOUND, TAG, "mb incorrect cid of characteristic.");

    // It is assumed that characteristics cid increased in the table
    const mb_parameter_descriptor_t *reg_info = &mbm_opts->param_descriptor_table[cid];

    MB_RETURN_ON_FALSE((reg_info->param_key),
                       ESP_ERR_INVALID_ARG, TAG, "mb incorrect characteristic key.");
    *param_buffer = reg_info;
    return ESP_OK;
}

// Helper function to get modbus command for each type of Modbus register area
static uint8_t mbc_serial_master_get_command(mb_param_type_t param_type, mb_param_mode_t mode)
{
    uint8_t command = 0;
    switch (param_type)
    {
    case MB_PARAM_HOLDING:
        command = (mode == MB_PARAM_WRITE) ? MB_FUNC_WRITE_MULTIPLE_REGISTERS : MB_FUNC_READ_HOLDING_REGISTER;
        break;
    case MB_PARAM_INPUT:
        command = MB_FUNC_READ_INPUT_REGISTER;
        break;
    case MB_PARAM_COIL:
        command = (mode == MB_PARAM_WRITE) ? MB_FUNC_WRITE_MULTIPLE_COILS : MB_FUNC_READ_COILS;
        break;
    case MB_PARAM_DISCRETE:
        if (mode != MB_PARAM_WRITE)
        {
            command = MB_FUNC_READ_DISCRETE_INPUTS;
        }
        else
        {
            ESP_LOGE(TAG, "%s: Incorrect mode (%u)",
                     __FUNCTION__, (unsigned)mode);
        }
        break;
    default:
        ESP_LOGE(TAG, "%s: Incorrect param type (%u)",
                 __FUNCTION__, (unsigned)param_type);
        break;
    }
    return command;
}

// Helper to search parameter by name in the parameter description table
// and fills Modbus request fields accordingly
static esp_err_t mbc_serial_master_set_request(void *ctx, uint8_t cid, mb_param_mode_t mode,
                                               mb_param_request_t *request,
                                               mb_parameter_descriptor_t *reg_data)
{
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(ctx);
    esp_err_t error = ESP_ERR_NOT_FOUND;
    MB_RETURN_ON_FALSE((request), ESP_ERR_INVALID_ARG, TAG, "mb incorrect request parameter.");
    MB_RETURN_ON_FALSE((mode <= MB_PARAM_WRITE), ESP_ERR_INVALID_ARG, TAG, "mb incorrect mode.");
    MB_RETURN_ON_FALSE((cid < mbm_opts->mbm_param_descriptor_size), ESP_ERR_INVALID_ARG, TAG, "mb incorrect cid parameter.");
    MB_RETURN_ON_FALSE((mbm_opts->param_descriptor_table), ESP_ERR_INVALID_ARG, TAG, "mb data dictionary is incorrect.");
    const mb_parameter_descriptor_t *reg_ptr = mbm_opts->param_descriptor_table;
    reg_ptr += cid;
    if (reg_ptr->cid == cid)
    {
        request->slave_addr = reg_ptr->mb_slave_addr;
        request->reg_start = reg_ptr->mb_reg_start;
        request->reg_size = reg_ptr->mb_size;
        request->command = mbc_serial_master_get_command(reg_ptr->mb_param_type, mode);
        MB_RETURN_ON_FALSE((request->command > 0), ESP_ERR_INVALID_ARG, TAG, "mb incorrect command or parameter type.");
        if (reg_data)
        {
            *reg_data = *reg_ptr; // Set the cid registered parameter data
        }
        error = ESP_OK;
    }
    return error;
}

// Get parameter data for corresponding characteristic
static esp_err_t mbc_serial_master_get_parameter(void *ctx, uint16_t cid,
                                                 uint8_t *value_ptr, uint8_t *type)
{
    MB_RETURN_ON_FALSE((type), ESP_ERR_INVALID_ARG, TAG, "type pointer is incorrect.");
    MB_RETURN_ON_FALSE((value_ptr), ESP_ERR_INVALID_ARG, TAG, "value pointer is incorrect.");
    esp_err_t error = ESP_ERR_INVALID_RESPONSE;
    mb_param_request_t request;
    mb_parameter_descriptor_t reg_info = {0};

    error = mbc_serial_master_set_request(ctx, cid, MB_PARAM_READ, &request, &reg_info);
    if ((error == ESP_OK) && (cid == reg_info.cid) && (request.slave_addr != MB_SLAVE_ADDR_PLACEHOLDER))
    {
        // Send request to read characteristic data
        error = mbc_serial_master_send_request(ctx, &request, value_ptr);
        if (error == ESP_OK)
        {
            ESP_LOGD(TAG, "%s: Good response for get cid(%u) = %s",
                     __FUNCTION__, (unsigned)reg_info.cid, (char *)esp_err_to_name(error));
        }
        else
        {
            ESP_LOGD(TAG, "%s: Bad response to get cid(%u) = %s",
                     __FUNCTION__, (unsigned)reg_info.cid, (char *)esp_err_to_name(error));
        }
        // Set the type of parameter found in the table
        *type = reg_info.param_type;
    }
    else
    {
        ESP_LOGE(TAG, "%s: The cid(%u) address information is not found in the data dictionary.",
                 __FUNCTION__, reg_info.cid);
        error = ESP_ERR_INVALID_ARG;
    }
    return error;
}

// Get parameter data for corresponding characteristic
static esp_err_t mbc_serial_master_get_parameter_with(void *ctx, uint16_t cid, uint8_t uid,
                                                      uint8_t *value_ptr, uint8_t *type)
{
    MB_RETURN_ON_FALSE((type), ESP_ERR_INVALID_ARG, TAG, "type pointer is incorrect.");
    MB_RETURN_ON_FALSE((value_ptr), ESP_ERR_INVALID_ARG, TAG, "value pointer is incorrect.");
    esp_err_t error = ESP_ERR_INVALID_RESPONSE;
    mb_param_request_t request;
    mb_parameter_descriptor_t reg_info = {0};

    error = mbc_serial_master_set_request(ctx, cid, MB_PARAM_READ, &request, &reg_info);
    if ((error == ESP_OK) && (cid == reg_info.cid))
    {
        if (request.slave_addr == MB_SLAVE_ADDR_PLACEHOLDER)
        {
            ESP_LOGD(TAG, "%s: override uid %d = %d for cid(%u)",
                     __FUNCTION__, (int)request.slave_addr, (int)uid, (unsigned)reg_info.cid);
        }
        request.slave_addr = uid; // override the UID
        // Send request to read characteristic data
        error = mbc_serial_master_send_request(ctx, &request, value_ptr);
        if (error == ESP_OK)
        {
            ESP_LOGD(TAG, "%s: Good response for get cid(%u) = %s",
                     __FUNCTION__, (unsigned)reg_info.cid, (char *)esp_err_to_name(error));
        }
        else
        {
            ESP_LOGD(TAG, "%s: Bad response to get cid(%u) = %s",
                     __FUNCTION__, (unsigned)reg_info.cid, (char *)esp_err_to_name(error));
        }
        // Set the type of parameter found in the table
        *type = reg_info.param_type;
    }
    else
    {
        ESP_LOGE(TAG, "%s: The cid(%u) not found in the data dictionary.",
                 __FUNCTION__, (unsigned)reg_info.cid);
        error = ESP_ERR_INVALID_ARG;
    }
    return error;
}

// Set parameter value for characteristic selected by name and cid
static esp_err_t mbc_serial_master_set_parameter(void *ctx, uint16_t cid,
                                                 uint8_t *value_ptr, uint8_t *type)
{
    MB_RETURN_ON_FALSE((value_ptr), ESP_ERR_INVALID_ARG, TAG, "value pointer is incorrect.");
    MB_RETURN_ON_FALSE((type), ESP_ERR_INVALID_ARG, TAG, "type pointer is incorrect.");
    esp_err_t error = ESP_ERR_INVALID_RESPONSE;
    mb_param_request_t request;
    mb_parameter_descriptor_t reg_info = {0};

    error = mbc_serial_master_set_request(ctx, cid, MB_PARAM_WRITE, &request, &reg_info);
    if ((error == ESP_OK) && (cid == reg_info.cid) && (request.slave_addr != MB_SLAVE_ADDR_PLACEHOLDER))
    {
        // Send request to write characteristic data
        error = mbc_serial_master_send_request(ctx, &request, value_ptr);
        if (error == ESP_OK)
        {
            ESP_LOGD(TAG, "%s: Good response for set cid(%u) = %s",
                     __FUNCTION__, (unsigned)reg_info.cid, (char *)esp_err_to_name(error));
        }
        else
        {
            ESP_LOGD(TAG, "%s: Bad response to set cid(%u) = %s",
                     __FUNCTION__, (unsigned)reg_info.cid, (char *)esp_err_to_name(error));
        }
        // Set the type of parameter found in the table
        *type = reg_info.param_type;
    }
    else
    {
        ESP_LOGE(TAG, "%s: The requested cid(%u) address information is not found in the data dictionary.",
                 __FUNCTION__, (unsigned)reg_info.cid);
        error = ESP_ERR_INVALID_ARG;
    }
    return error;
}

// Set parameter value for characteristic selected by name and cid
static esp_err_t mbc_serial_master_set_parameter_with(void *ctx, uint16_t cid, uint8_t uid,
                                                      uint8_t *value_ptr, uint8_t *type)
{
    MB_RETURN_ON_FALSE((value_ptr), ESP_ERR_INVALID_ARG, TAG, "value pointer is incorrect.");
    MB_RETURN_ON_FALSE((type), ESP_ERR_INVALID_ARG, TAG, "type pointer is incorrect.");
    esp_err_t error = ESP_ERR_INVALID_RESPONSE;
    mb_param_request_t request;
    mb_parameter_descriptor_t reg_info = {0};

    error = mbc_serial_master_set_request(ctx, cid, MB_PARAM_WRITE, &request, &reg_info);
    if ((error == ESP_OK) && (cid == reg_info.cid))
    {
        if (request.slave_addr == MB_SLAVE_ADDR_PLACEHOLDER)
        {
            ESP_LOGD(TAG, "%s: override uid %d = %d for cid(%u)",
                     __FUNCTION__, (int)request.slave_addr, (int)uid, (unsigned)reg_info.cid);
        }
        request.slave_addr = uid; // override the UID
        // Send request to write characteristic data
        error = mbc_serial_master_send_request(ctx, &request, value_ptr);
        if (error == ESP_OK)
        {
            ESP_LOGD(TAG, "%s: Good response for set cid(%u) = %s",
                     __FUNCTION__, (unsigned)reg_info.cid, (char *)esp_err_to_name(error));
        }
        else
        {
            ESP_LOGD(TAG, "%s: Bad response to set cid(%u) = %s",
                     __FUNCTION__, (unsigned)reg_info.cid, (char *)esp_err_to_name(error));
        }
        // Set the type of parameter found in the table
        *type = reg_info.param_type;
    }
    else
    {
        ESP_LOGE(TAG, "%s: The requested cid(%u) not found in the data dictionary.",
                 __FUNCTION__, (unsigned)reg_info.cid);
        error = ESP_ERR_INVALID_ARG;
    }
    return error;
}

static void mbc_serial_master_iface_free(void *ctx)
{
    mbm_controller_iface_t *mbm_iface = (mbm_controller_iface_t *)(ctx);
    if (mbm_iface)
    {
        if (mbm_iface->opts.task_handle)
        {
            vTaskDelete(mbm_iface->opts.task_handle);
            mbm_iface->opts.task_handle = NULL;
        }
        if (mbm_iface->opts.event_group_handle)
        {
            vEventGroupDelete(mbm_iface->opts.event_group_handle);
            mbm_iface->opts.event_group_handle = NULL;
        }
        free(mbm_iface); // free the memory allocated for interface
    }   
}

static esp_err_t mbc_serial_master_controller_create(void **ctx)
{
    MB_RETURN_ON_FALSE((ctx), ESP_ERR_INVALID_STATE, TAG, "mb stack init interface fail.");
    mbm_controller_iface_t *mbm_controller_iface = NULL;

    esp_err_t ret = ESP_ERR_INVALID_STATE;
    BaseType_t status = 0;

    // Allocate space for controller
    mbm_controller_iface = malloc(sizeof(mbm_controller_iface_t));
    MB_GOTO_ON_FALSE((mbm_controller_iface), ESP_ERR_INVALID_STATE, error,
                     TAG, "mb stack memory allocation fail.");

    // Initialize interface properties
    mb_master_options_t *mbm_opts = &mbm_controller_iface->opts;

    // Initialization of active context of the modbus controller
    mbm_opts->event_group_handle = xEventGroupCreate();
    MB_GOTO_ON_FALSE((mbm_opts->event_group_handle), ESP_ERR_INVALID_STATE, error, TAG, "mb event group error.");
    // Create modbus controller task
    status = xTaskCreatePinnedToCore((void *)&mbc_ser_master_task,
                                     "mbc_ser_master",
                                     MB_CONTROLLER_STACK_SIZE,
                                     mbm_controller_iface,
                                     MB_CONTROLLER_PRIORITY,
                                     &mbm_opts->task_handle,
                                     MB_PORT_TASK_AFFINITY);
    MB_GOTO_ON_FALSE((status == pdPASS), ESP_ERR_INVALID_STATE, error, TAG,
                     "mb controller task creation error");
    MB_MASTER_ASSERT(mbm_opts->task_handle); // The task is created but handle is incorrect

    // Initialize public interface methods of the interface
    mbm_controller_iface->create = mbc_serial_master_create;
    mbm_controller_iface->delete = mbc_serial_master_delete;
    mbm_controller_iface->start = mbc_serial_master_start;
    mbm_controller_iface->stop = mbc_serial_master_stop;
    mbm_controller_iface->get_cid_info = mbc_serial_master_get_cid_info;
    mbm_controller_iface->get_parameter = mbc_serial_master_get_parameter;
    mbm_controller_iface->get_parameter_with = mbc_serial_master_get_parameter_with;
    mbm_controller_iface->send_request = mbc_serial_master_send_request;
    mbm_controller_iface->set_descriptor = mbc_serial_master_set_descriptor;
    mbm_controller_iface->set_parameter = mbc_serial_master_set_parameter;
    mbm_controller_iface->set_parameter_with = mbc_serial_master_set_parameter_with;
    mbm_controller_iface->mb_base = NULL;
    *ctx = mbm_controller_iface;
    return ESP_OK;

error:
    mbc_serial_master_iface_free((void *)mbm_controller_iface);
    return ret;
}

// Initialization of resources for Modbus serial master controller
esp_err_t mbc_serial_master_create(mb_communication_info_t *config, void **ctx)
{
    mbm_controller_iface_t *mbm_controller_iface = NULL;
    MB_RETURN_ON_FALSE((ctx && config), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack init interface fail.");
    MB_RETURN_ON_FALSE((!*ctx), ESP_ERR_INVALID_STATE, TAG, "mb stack is not destroyed?");

    mb_serial_opts_t *pcomm_info = &config->ser_opts;

    // Check communication options
    MB_RETURN_ON_FALSE(((pcomm_info->mode == MB_RTU) || (pcomm_info->mode == MB_ASCII)),
                       ESP_ERR_INVALID_ARG, TAG, "mb incorrect mode = (%u).", (unsigned)pcomm_info->mode);
    MB_RETURN_ON_FALSE((pcomm_info->port <= UART_NUM_MAX), ESP_ERR_INVALID_ARG, TAG,
                       "mb wrong port to set = (%u).", (unsigned)pcomm_info->port);
    MB_RETURN_ON_FALSE((pcomm_info->parity <= UART_PARITY_ODD), ESP_ERR_INVALID_ARG, TAG,
                       "mb wrong parity option = (%u).", (unsigned)pcomm_info->parity);

    esp_err_t ret = mbc_serial_master_controller_create((void *)&mbm_controller_iface);
    MB_GOTO_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE, error, TAG, "mbc create returns (0x%x).", (int)ret);

    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(mbm_controller_iface);
    mbm_opts->comm_opts = *config;
    mbm_opts->port_type = MB_PORT_SERIAL_MASTER;

    // Keep the response time setting
    if (!pcomm_info->response_tout_ms)
    {
        mbm_opts->comm_opts.ser_opts.response_tout_ms = CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND;
    }

    // Initialize Modbus stack using mbcontroller parameters
    mb_err_enum_t err = MB_EILLSTATE;
    void *pinst = (void *)mbm_controller_iface;

    if (pcomm_info->mode == MB_RTU)
    {
        err = mbm_rtu_create(pcomm_info, &pinst);
    }
    else if (pcomm_info->mode == MB_ASCII)
    {
        err = mbm_ascii_create(pcomm_info, &pinst);
    }
    MB_GOTO_ON_FALSE((err == MB_ENOERR), ESP_ERR_INVALID_STATE, error, TAG,
                     "mb object create returns (0x%x).", (int)err);
    mbm_controller_iface->mb_base = (mb_base_t *)pinst;

    const mb_rw_callbacks_t rw_cbs = {
        .reg_input_cb = mbc_reg_input_master_cb,
        .reg_holding_cb = mbc_reg_holding_master_cb,
        .reg_coils_cb = mbc_reg_coils_master_cb,
        .reg_discrete_cb = mbc_reg_discrete_master_cb
    };

    mbm_controller_iface->mb_base->rw_cbs = rw_cbs;
    mbm_controller_iface->is_active = false;
    *ctx = mbm_controller_iface;
    return ESP_OK;

error:
    if (mbm_controller_iface)
    {
        if (mbm_controller_iface->mb_base)
        {
            mbm_controller_iface->mb_base->delete(mbm_controller_iface->mb_base);
            mbm_controller_iface->mb_base = NULL;
        }
        mbc_serial_master_iface_free((void *)mbm_controller_iface);
        *ctx = NULL;
    }
    return ret;
}

#endif