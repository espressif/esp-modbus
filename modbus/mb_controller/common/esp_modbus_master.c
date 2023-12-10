/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"           // for esp_err_t
#include "mbc_master.h"        // for master interface define
#include "esp_modbus_master.h" // for public interface defines

static const char TAG[] __attribute__((unused)) = "MB_CONTROLLER_MASTER";

// This file implements public API for Modbus master controller.

/**
 * Modbus controller delete function
 */
esp_err_t mbc_master_delete(void *ctx)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE(mbm_controller->delete, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    error = mbm_controller->delete (ctx);
    MB_RETURN_ON_FALSE((error == ESP_OK), error,
                       TAG, "Master delete failure, error=(0x%x).", (uint16_t)error);
    return error;
}

/**
 * Critical section lock function
 */
esp_err_t mbc_master_lock(void *ctx)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                            "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    mb_base_t *pmb_obj = (mb_base_t *)mbm_controller->mb_base;
    MB_RETURN_ON_FALSE((pmb_obj && pmb_obj->lock), ESP_ERR_INVALID_STATE, TAG,
                            "Master interface is not correctly initialized.");
    CRITICAL_SECTION_LOCK(pmb_obj->lock);
    return ESP_OK;
}

/**
 * Critical section unlock function
 */
esp_err_t mbc_master_unlock(void *ctx)
{
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                            "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    mb_base_t *pmb_obj = (mb_base_t *)mbm_controller->mb_base;
    MB_RETURN_ON_FALSE((pmb_obj && pmb_obj->lock), ESP_ERR_INVALID_STATE, TAG,
                            "Master interface is not correctly initialized.");
    CRITICAL_SECTION_UNLOCK(pmb_obj->lock);
    return ESP_OK;
}

esp_err_t mbc_master_get_cid_info(void *ctx, uint16_t cid, const mb_parameter_descriptor_t **param_info)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((mbm_controller->get_cid_info && mbm_controller->is_active),
                       ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly configured.");
    error = mbm_controller->get_cid_info(ctx, cid, param_info);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master get cid info failure, error=(0x%x).", (uint16_t)error);
    return error;
}

/**
 * Set parameter value for characteristic selected by name and cid
 */
esp_err_t mbc_master_set_parameter(void *ctx, uint16_t cid, uint8_t *value, uint8_t *type)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((mbm_controller->set_parameter && mbm_controller->is_active),
                       ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    error = mbm_controller->set_parameter(ctx, cid, value, type);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master set parameter failure, error=(0x%x) (%s).",
                       (uint16_t)error, esp_err_to_name(error));
    return ESP_OK;
}

/**
 * Set parameter value for characteristic selected by name and cid
 */
esp_err_t mbc_master_set_parameter_with(void *ctx, uint16_t cid, uint8_t uid, uint8_t *value, uint8_t *type)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((mbm_controller->set_parameter_with && mbm_controller->is_active),
                       ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    error = mbm_controller->set_parameter_with(ctx, cid, uid, value, type);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master set parameter failure, error=(0x%x) (%s).",
                       (uint16_t)error, esp_err_to_name(error));
    return ESP_OK;
}

/**
 * Get parameter data for corresponding characteristic
 */
esp_err_t mbc_master_get_parameter(void *ctx, uint16_t cid, uint8_t *value, uint8_t *type)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((mbm_controller->get_parameter && mbm_controller->is_active),
                       ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly configured.");
    error = mbm_controller->get_parameter(ctx, cid, value, type);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master get parameter failure, error=(0x%x) (%s).",
                       (uint16_t)error, esp_err_to_name(error));
    return error;
}

/**
 * Get parameter data for corresponding characteristic
 */
esp_err_t mbc_master_get_parameter_with(void *ctx, uint16_t cid, uint8_t uid, uint8_t *value, uint8_t *type)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((mbm_controller->get_parameter_with && mbm_controller->is_active),
                       ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly configured.");
    error = mbm_controller->get_parameter_with(ctx, cid, uid, value, type);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master get parameter failure, error=(0x%x) (%s).",
                       (uint16_t)error, esp_err_to_name(error));
    return error;
}

/**
 * Send custom Modbus request defined as mb_param_request_t structure
 */
esp_err_t mbc_master_send_request(void *ctx, mb_param_request_t *request, void *data_ptr)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE((mbm_controller->send_request && mbm_controller->is_active),
                       ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly configured.");
    error = mbm_controller->send_request(ctx, request, data_ptr);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master send request failure error=(0x%x) (%s).",
                       (uint16_t)error, esp_err_to_name(error));
    return ESP_OK;
}

/**
 * Set Modbus parameter description table
 */
esp_err_t mbc_master_set_descriptor(void *ctx, const mb_parameter_descriptor_t *descriptor,
                                    const uint16_t num_elements)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE(mbm_controller->set_descriptor,
                       ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly configured.");
    error = mbm_controller->set_descriptor(ctx, descriptor, num_elements);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master set descriptor failure, error=(0x%x) (%s).",
                       (uint16_t)error, esp_err_to_name(error));
    return ESP_OK;
}

/**
 * Modbus controller stack start function
 */
esp_err_t mbc_master_start(void *ctx)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE(mbm_controller->start, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    error = mbm_controller->start(ctx);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master start failure, error=(0x%x) (%s).",
                       (uint16_t)error, esp_err_to_name(error));
    return ESP_OK;
}

/**
 * Modbus controller stack stop function
 */
esp_err_t mbc_master_stop(void *ctx)
{
    esp_err_t error = ESP_OK;
    MB_RETURN_ON_FALSE(ctx, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    mbm_controller_iface_t *mbm_controller = MB_MASTER_GET_IFACE(ctx);
    MB_RETURN_ON_FALSE(mbm_controller->stop, ESP_ERR_INVALID_STATE, TAG,
                       "Master interface is not correctly initialized.");
    error = mbm_controller->stop(ctx);
    MB_RETURN_ON_FALSE((error == ESP_OK), error, TAG,
                       "Master stop failure, error=(0x%x) (%s).",
                       (uint16_t)error, esp_err_to_name(error));
    return ESP_OK;
}

/* ----------------------- Callback functions for Modbus stack ---------------------------------*/
// These are executed by modbus stack to read appropriate type of registers.

/**
 * Modbus master input register callback function.
 *
 * @param ctx interface context pointer
 * @param reg_buffer input register buffer
 * @param reg_addr input register address
 * @param num_regs input register number
 *
 * @return result
 */
// Callback function for reading of MB Input Registers
// mbm_reg_input_cb_serial
mb_err_enum_t mbc_reg_input_master_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t reg_addr, uint16_t num_regs)
{
    MB_RETURN_ON_FALSE((reg_buffer), MB_EINVAL, TAG,
                       "Master stack processing error.");
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(MB_MASTER_GET_IFACE_FROM_BASE(inst));
    // Number of input registers to be transferred
    uint16_t num_input_regs = (uint16_t)mbm_opts->reg_buffer_size;
    uint8_t *input_reg_buf = (uint8_t *)mbm_opts->reg_buffer_ptr; // Get instance address
    uint16_t regs_cnt = num_regs;
    mb_err_enum_t status = MB_ENOERR;
    // If input or configuration parameters are incorrect then return an error to stack layer
    if ((input_reg_buf) && (num_regs >= 1) && (num_input_regs == regs_cnt))
    {
        CRITICAL_SECTION(inst->lock)
        {
            while (regs_cnt > 0)
            {
                _XFER_2_RD(input_reg_buf, reg_buffer);
                regs_cnt -= 1;
            }
        }
    }
    else
    {
        status = MB_ENOREG;
    }
    return status;
}

/**
 * Modbus master holding register callback function.
 *
 * @param ctx interface context pointer
 * @param reg_buffer holding register buffer
 * @param reg_addr holding register address
 * @param num_regs holding register number
 * @param mode read or write
 *
 * @return result
 */
// Callback function for reading of MB Holding Registers
// Executed by stack when request to read/write holding registers is received
// mbm_reg_holding_cb_serial
mb_err_enum_t mbc_reg_holding_master_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t reg_addr,
                                        uint16_t num_regs, mb_reg_mode_enum_t mode)
{
    MB_RETURN_ON_FALSE((reg_buffer), MB_EINVAL, TAG, "Master stack processing error.");
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(MB_MASTER_GET_IFACE_FROM_BASE(inst));
    uint16_t num_hold_regs = (uint16_t)mbm_opts->reg_buffer_size;
    uint8_t *holding_buf = (uint8_t *)mbm_opts->reg_buffer_ptr;
    mb_err_enum_t status = MB_ENOERR;
    uint16_t regs_cnt = num_regs;
    // Check input and configuration parameters for correctness
    if ((holding_buf) && (num_hold_regs == num_regs) && (num_regs >= 1))
    {
        switch (mode)
        {
        case MB_REG_WRITE:
            CRITICAL_SECTION(inst->lock)
            {
                while (regs_cnt > 0)
                {
                    _XFER_2_RD(reg_buffer, holding_buf);
                    regs_cnt -= 1;
                }
            }
            break;
        case MB_REG_READ:
            CRITICAL_SECTION(inst->lock)
            {
                while (regs_cnt > 0)
                {
                    _XFER_2_WR(holding_buf, reg_buffer);
                    holding_buf += 2;
                    regs_cnt -= 1;
                }
            }
            break;
        }
    }
    else
    {
        status = MB_ENOREG;
    }
    return status;
}

/**
 * Modbus master coils callback function.
 *
 * @param ctx interface context pointer
 * @param reg_buffer coils buffer
 * @param reg_addr coils address
 * @param ncoils coils number
 * @param mode read or write
 *
 * @return result
 */
// Callback function for reading of MB Coils Registers
// mbm_reg_coils_cb_serial
mb_err_enum_t mbc_reg_coils_master_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t reg_addr,
                                      uint16_t ncoils, mb_reg_mode_enum_t mode)
{
    MB_RETURN_ON_FALSE((reg_buffer), MB_EINVAL, TAG, "Master stack processing error.");
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(MB_MASTER_GET_IFACE_FROM_BASE(inst));
    uint16_t num_coil_regs = (uint16_t)mbm_opts->reg_buffer_size;
    uint8_t *coils_buf = (uint8_t *)mbm_opts->reg_buffer_ptr;
    mb_err_enum_t status = MB_ENOERR;
    uint16_t reg_index;
    uint16_t coils_cnt = ncoils;
    reg_addr--; // The address is already + 1
    if ((num_coil_regs >= 1) && (coils_buf) && (ncoils == num_coil_regs))
    {
        reg_index = (reg_addr % 8);
        switch (mode)
        {
        case MB_REG_WRITE:
            CRITICAL_SECTION(inst->lock)
            {
                while (coils_cnt > 0)
                {
                    uint8_t result = mb_util_get_bits((uint8_t *)coils_buf, reg_index - (reg_addr % 8), 1);
                    mb_util_set_bits(reg_buffer, reg_index - (reg_addr % 8), 1, result);
                    reg_index++;
                    coils_cnt--;
                }
            }
            break;
        case MB_REG_READ:
            CRITICAL_SECTION(inst->lock)
            {
                while (coils_cnt > 0)
                {
                    uint8_t result = mb_util_get_bits(reg_buffer, reg_index - (reg_addr % 8), 1);
                    mb_util_set_bits((uint8_t *)coils_buf, reg_index - (reg_addr % 8), 1, result);
                    reg_index++;
                    coils_cnt--;
                }
            }
            break;
        } // switch ( mode )
    }
    else
    {
        // If the configuration or input parameters are incorrect then return error to stack
        status = MB_ENOREG;
    }
    return status;
}

/**
 * Modbus master discrete callback function.
 *
 * @param ctx - pointer to interface structure
 * @param reg_buffer discrete buffer
 * @param reg_addr discrete address
 * @param n_discrete discrete number
 *
 * @return result
 */
// Callback function for reading of MB Discrete Input Registers
// mbm_reg_discrete_cb_serial
mb_err_enum_t mbc_reg_discrete_master_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t reg_addr,
                                         uint16_t n_discrete)
{
    MB_RETURN_ON_FALSE((reg_buffer), MB_EINVAL, TAG, "Master stack processing error.");
    mb_master_options_t *mbm_opts = MB_MASTER_GET_OPTS(MB_MASTER_GET_IFACE_FROM_BASE(inst));
    uint16_t num_discr_regs = (uint16_t)mbm_opts->reg_buffer_size;
    uint8_t *discr_buf = (uint8_t *)mbm_opts->reg_buffer_ptr;
    mb_err_enum_t status = MB_ENOERR;
    uint16_t bit_index, num_reg;
    uint8_t *temp_discr_buf;
    num_reg = n_discrete;
    temp_discr_buf = (uint8_t *)discr_buf;
    // It is already plus one in Modbus function method.
    reg_addr--;
    if ((num_discr_regs >= 1) && (discr_buf) && (n_discrete >= 1) && (n_discrete == num_discr_regs))
    {
        bit_index = (uint16_t)(reg_addr) % 8; // Get bit index
        CRITICAL_SECTION(inst->lock)
        {
            while (num_reg > 0)
            {
                uint8_t result = mb_util_get_bits(reg_buffer, bit_index - (reg_addr % 8), 1);
                mb_util_set_bits(temp_discr_buf, bit_index - (reg_addr % 8), 1, result);
                bit_index++;
                num_reg--;
            }
        }
    }
    else
    {
        status = MB_ENOREG;
    }
    return status;
}
