/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "esp_err.h"           // for esp_err_t
#include "mbc_master.h"        // for master interface define
#include "esp_modbus_master.h" // for public interface defines

// Helper macro to set custom command
#define GET_CMD(mode, access, rd_cmd, wr_cmd) (((mode == MB_PARAM_WRITE) && (access & PAR_PERMS_WRITE)) ? wr_cmd : \
                                               ((mode == MB_PARAM_READ) && (access & PAR_PERMS_READ)) ? rd_cmd : 0)

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

mb_err_enum_t mbc_reg_common_cb(mb_base_t *inst, uint8_t *pdata, uint16_t address, uint16_t bytes)
{
    MB_RETURN_ON_FALSE((pdata), MB_EINVAL, TAG, "incorrect parameters provided.");

    mb_master_options_t *popts = MB_MASTER_GET_OPTS(MB_MASTER_GET_IFACE_FROM_BASE(inst));
    uint16_t reg_len = popts->reg_buffer_size;
    uint8_t *ppar_buffer = (uint8_t *)popts->reg_buffer_ptr; // Get instance address
    mb_err_enum_t status = MB_ENOERR;
    if (ppar_buffer && !address && (bytes >= 2) && (((reg_len << 1) >= bytes))){
        CRITICAL_SECTION(inst->lock) {
            memmove(ppar_buffer, pdata, bytes);
        }
    } else {
        status = MB_ENORES;
    }
    return status;
}

/**
 * Modbus master input register callback function.
 *
 * @param inst interface context pointer
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
 * @param inst interface context pointer
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
 * @param inst interface context pointer
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
 * @param inst - pointer to interface structure
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

// Helper function to set parameter buffer according to its type
esp_err_t mbc_master_set_param_data(void* dest, void* src, mb_descr_type_t param_type, size_t param_size)
{
    esp_err_t err = ESP_OK;
    MB_RETURN_ON_FALSE((src), ESP_ERR_INVALID_STATE, TAG,"incorrect data pointer.");
    MB_RETURN_ON_FALSE((dest), ESP_ERR_INVALID_STATE, TAG,"incorrect data pointer.");
    void *pdest = dest;
    void *psrc = src;

    // Transfer parameter data into value of characteristic
    switch(param_type)
    {
        case PARAM_TYPE_U8:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U8) {
                *((uint8_t *)pdest) = *((uint8_t*)psrc);
            }
            break;

        case PARAM_TYPE_U16:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U16) {
                *((uint16_t *)pdest) = *((uint16_t*)psrc);
            }
            break;

        case PARAM_TYPE_U32:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U32) {
                *((uint32_t *)pdest) = *((uint32_t*)psrc);
            }
            break;

        case PARAM_TYPE_FLOAT:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_FLOAT) {
                *((float *)pdest) = *(float*)psrc;
            }
            break;

        case PARAM_TYPE_ASCII:
        case PARAM_TYPE_BIN:
            memcpy((void *)dest, (void*)src, (size_t)param_size);
            break;

#if CONFIG_FMB_EXT_TYPE_SUPPORT

        case PARAM_TYPE_I8_A:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U8_REG) {
                mb_set_int8_a((val_16_arr *)pdest, (*(int8_t*)psrc));
                ESP_LOGV(TAG, "Convert uint8 B[%d] 0x%04" PRIx16 " = 0x%04" PRIx16, i, *(uint16_t *)psrc, *(uint16_t *)pdest);
            }
            break;

        case PARAM_TYPE_I8_B:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U8_REG) {
                mb_set_int8_b((val_16_arr *)pdest, (int8_t)((*(uint16_t*)psrc) >> 8));
                ESP_LOGV(TAG, "Convert int8 A[%d] 0x%02" PRIx16 " = 0x%02" PRIx16, i, *(uint16_t *)psrc, *(uint16_t *)pdest);
            }
            break;

        case PARAM_TYPE_U8_A:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U8_REG) {
                mb_set_uint8_a((val_16_arr *)pdest, (*(uint8_t*)psrc));
                ESP_LOGV(TAG, "Convert uint8 A[%d] 0x%02" PRIx16 " = %02" PRIx16, i, *(uint16_t *)psrc, *(uint16_t *)pdest);
            }
            break;

        case PARAM_TYPE_U8_B:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U8_REG) {
                uint8_t data = (uint8_t)((*(uint16_t*)psrc) >> 8);
                mb_set_uint8_b((val_16_arr *)pdest, data);
                ESP_LOGV(TAG, "Convert uint8 B[%d] 0x%02" PRIx16 " = 0x%02" PRIx16, i, *(uint16_t *)psrc, *(uint16_t *)pdest);
            }
            break;

        case PARAM_TYPE_I16_AB:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I16) {
                mb_set_int16_ab((val_16_arr *)pdest, *(int16_t*)psrc);
                ESP_LOGV(TAG, "Convert int16 AB[%d] 0x%04" PRIx16 " = 0x%04" PRIx16, i, *(uint16_t *)psrc, *(uint16_t *)pdest);
            }
            break;

        case PARAM_TYPE_I16_BA:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I16) {
                mb_set_int16_ba((val_16_arr *)pdest, *(int16_t*)psrc);
                ESP_LOGV(TAG, "Convert int16 BA[%d] 0x%04" PRIx16 " = 0x%04" PRIx16, i, *(uint16_t *)psrc, *(uint16_t *)pdest);
            }
            break;

        case PARAM_TYPE_U16_AB:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U16) {
                mb_set_uint16_ab((val_16_arr *)pdest, *(uint16_t*)psrc);
                ESP_LOGV(TAG, "Convert uint16 AB[%d] 0x%02" PRIx16 " = 0x%02" PRIx16, i, *(uint16_t *)psrc, *(uint16_t *)pdest);
            }
            break;

        case PARAM_TYPE_U16_BA:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U16) {
                mb_set_uint16_ba((val_16_arr *)pdest, *(uint16_t*)psrc);
                ESP_LOGV(TAG, "Convert uint16 BA[%d] 0x%02" PRIx16 " = 0x%02" PRIx16, i, *(uint16_t *)psrc, *(uint16_t *)pdest);
            }
            break;

        case PARAM_TYPE_I32_ABCD:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I32) {
                mb_set_int32_abcd((val_32_arr *)pdest, *(int32_t *)psrc);
                ESP_LOGV(TAG, "Convert int32 ABCD[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_U32_ABCD:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U32) {
                mb_set_uint32_abcd((val_32_arr *)pdest, *(uint32_t *)psrc);
                ESP_LOGV(TAG, "Convert uint32 ABCD[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_FLOAT_ABCD:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_FLOAT) {
                mb_set_float_abcd((val_32_arr *)pdest, *(float *)psrc);
                ESP_LOGV(TAG, "Convert float ABCD[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_I32_CDAB:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I32) {
                mb_set_int32_cdab((val_32_arr *)pdest, *(int32_t *)psrc);
                ESP_LOGV(TAG, "Convert int32 CDAB[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_U32_CDAB:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U32) {
                mb_set_uint32_cdab((val_32_arr *)pdest, *(uint32_t *)psrc);
                ESP_LOGV(TAG, "Convert uint32 CDAB[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_FLOAT_CDAB:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_FLOAT) {
                mb_set_float_cdab((val_32_arr *)pdest, *(float *)psrc);
                ESP_LOGV(TAG, "Convert float CDAB[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_I32_BADC:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I32) {
                mb_set_int32_badc((val_32_arr *)pdest, *(int32_t *)psrc);
                ESP_LOGV(TAG, "Convert int32 BADC[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_U32_BADC:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U32) {
                mb_set_uint32_badc((val_32_arr *)pdest, *(uint32_t *)psrc);
                ESP_LOGV(TAG, "Convert uint32 BADC[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_FLOAT_BADC:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_FLOAT) {
                mb_set_float_badc((val_32_arr *)pdest, *(float *)psrc);
                ESP_LOGV(TAG, "Convert float BADC[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_I32_DCBA:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I32) {
                mb_set_int32_dcba((val_32_arr *)pdest, *(int32_t *)psrc);
                ESP_LOGV(TAG, "Convert int32 DCBA[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_U32_DCBA:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U32) {
                mb_set_uint32_dcba((val_32_arr *)pdest, *(uint32_t *)psrc);
                ESP_LOGV(TAG, "Convert uint32 DCBA[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_FLOAT_DCBA:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_FLOAT) {
                mb_set_float_dcba((val_32_arr *)pdest, *(float *)psrc);
                ESP_LOGV(TAG, "Convert float DCBA[%d] 0x%04" PRIx32 " = 0x%04" PRIx32, i, *(uint32_t *)psrc, *(uint32_t *)pdest);
            }
            break;

        case PARAM_TYPE_I64_ABCDEFGH:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I64) {
                mb_set_int64_abcdefgh((val_64_arr *)pdest, *(int64_t *)psrc);
                ESP_LOGV(TAG, "Convert int64 ABCDEFGH[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_U64_ABCDEFGH:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U64) {
                mb_set_uint64_abcdefgh((val_64_arr *)pdest, *(uint64_t *)psrc);
                ESP_LOGV(TAG, "Convert double ABCDEFGH[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_DOUBLE_ABCDEFGH:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_DOUBLE) {
                mb_set_double_abcdefgh((val_64_arr *)pdest, *(double *)psrc);
                ESP_LOGV(TAG, "Convert double ABCDEFGH[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_I64_HGFEDCBA:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I64) {
                mb_set_int64_hgfedcba((val_64_arr *)pdest, *(int64_t *)psrc);
                ESP_LOGV(TAG, "Convert int64 HGFEDCBA[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_U64_HGFEDCBA:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U64) {
                mb_set_uint64_hgfedcba((val_64_arr *)pdest, *(uint64_t *)psrc);
                ESP_LOGV(TAG, "Convert double HGFEDCBA[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_DOUBLE_HGFEDCBA:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_DOUBLE) {
                mb_set_double_hgfedcba((val_64_arr *)pdest, *(double *)psrc);
                ESP_LOGV(TAG, "Convert double HGFEDCBA[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_I64_GHEFCDAB:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I64) {
                mb_set_int64_ghefcdab((val_64_arr *)pdest, *(int64_t *)psrc);
                ESP_LOGV(TAG, "Convert int64 GHEFCDAB[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_U64_GHEFCDAB:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U64) {
                mb_set_uint64_ghefcdab((val_64_arr *)pdest, *(uint64_t *)psrc);
                ESP_LOGV(TAG, "Convert uint64 GHEFCDAB[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_DOUBLE_GHEFCDAB:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_DOUBLE) {
                mb_set_double_ghefcdab((val_64_arr *)pdest, *(double *)psrc);
                ESP_LOGV(TAG, "Convert double GHEFCDAB[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_I64_BADCFEHG:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_I64) {
                mb_set_int64_badcfehg((val_64_arr *)pdest, *(int64_t *)psrc);
                ESP_LOGV(TAG, "Convert int64 BADCFEHG[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_U64_BADCFEHG:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_U64) {
                mb_set_uint64_badcfehg((val_64_arr *)pdest, *(uint64_t *)psrc);
                ESP_LOGV(TAG, "Convert uint64 BADCFEHG[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

        case PARAM_TYPE_DOUBLE_BADCFEHG:
            for MB_EACH_ELEM(psrc, pdest, param_size, PARAM_SIZE_DOUBLE) {
                mb_set_double_badcfehg((val_64_arr *)pdest, *(double *)psrc);
                ESP_LOGV(TAG, "Convert double BADCFEHG[%d] 0x%" PRIx64 " = 0x%" PRIx64, i, *(uint64_t *)psrc, *(uint64_t *)pdest);
            }
            break;

#endif
        default:
            ESP_LOGE(TAG, "%s: Incorrect param type (%u).",
                        __FUNCTION__, (unsigned)param_type);
            err = ESP_ERR_NOT_SUPPORTED;
            break;
    }
    return err;
}

// Helper function to get configured Modbus command for each type of Modbus register area.
// Supports custom command options using the PAR_PERMS_CUST_CMD permission.
// The MB_PARAM_CUSTOM register type mimics the custom commands specificly handled with
// custom command handlers which have to be defined in command handling table.
uint8_t mbc_master_get_command(const mb_parameter_descriptor_t *pdescr, mb_param_mode_t mode)
{
    MB_RETURN_ON_FALSE((pdescr), 0, TAG, "incorrect data pointer.");
    uint8_t command = 0;
    switch(pdescr->mb_param_type)
    {
        case MB_PARAM_HOLDING:
            command = GET_CMD(mode, pdescr->access, MB_FUNC_READ_HOLDING_REGISTER, MB_FUNC_WRITE_MULTIPLE_REGISTERS);
            break;
        case MB_PARAM_INPUT:
            command = GET_CMD(mode, pdescr->access, MB_FUNC_READ_INPUT_REGISTER, 0);
            break;
        case MB_PARAM_COIL:
            command = GET_CMD(mode, pdescr->access, MB_FUNC_READ_COILS, MB_FUNC_WRITE_MULTIPLE_COILS);
            break;
        case MB_PARAM_DISCRETE:
            command = GET_CMD(mode, pdescr->access, MB_FUNC_READ_DISCRETE_INPUTS, 0);
            break;
        case MB_PARAM_CUSTOM:
            if (pdescr->access & PAR_PERMS_CUST_CMD) {
                // Use custom command in the request for read or write
                command = GET_CMD(mode, pdescr->access, (uint8_t)pdescr->param_opts.cust_cmd_read, (uint8_t)pdescr->param_opts.cust_cmd_write);
            } else {
                command = 0;
            }
            break;
        default:
            ESP_LOGE(TAG, "%s: Incorrect param type (%u)", __FUNCTION__, (unsigned)pdescr->mb_param_type);
            break;
    }
    return command;
}

