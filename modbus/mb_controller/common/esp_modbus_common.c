/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "esp_err.h"
#include "mbc_master.h"         // for master interface define
#include "mbc_slave.h"          // for slave interface define
#include "esp_modbus_common.h"  // for public interface defines

static const char TAG[] __attribute__((unused)) = "MB_CONTROLLER_COMMON";

/**
 * Register or override command handler for the command in object command handler table
 */
esp_err_t mbc_set_handler(void *ctx, uint8_t func_code, mb_fn_handler_fp handler)
{
    MB_RETURN_ON_FALSE((ctx && handler && func_code), ESP_ERR_INVALID_STATE, TAG,
                            "Incorrect arguments for the function.");
    mb_err_enum_t ret = MB_EINVAL;
    mb_controller_common_t *mb_controller = (mb_controller_common_t *)(ctx);
    mb_base_t *mb_obj = (mb_base_t *)mb_controller->mb_base;
    MB_RETURN_ON_FALSE(mb_obj, ESP_ERR_INVALID_STATE, TAG,
                            "Controller interface is not correctly initialized.");
    if (mb_obj->descr.is_master) {
        ret = mbm_set_handler(mb_controller->mb_base, func_code, handler);
    } else {
        ret = mbs_set_handler(mb_controller->mb_base, func_code, handler);
    }
    return  MB_ERR_TO_ESP_ERR(ret);
}

/**
 * Get command handler from the command handler table of the object
 */
esp_err_t mbc_get_handler(void *ctx, uint8_t func_code, mb_fn_handler_fp *handler)
{
    MB_RETURN_ON_FALSE((ctx && func_code && handler), ESP_ERR_INVALID_STATE, TAG,
                            "Incorrect arguments for the function.");
    mb_err_enum_t ret = MB_EINVAL;
    mb_controller_common_t *mb_controller = (mb_controller_common_t *)(ctx);
    mb_base_t *mb_obj = (mb_base_t *)mb_controller->mb_base;
    MB_RETURN_ON_FALSE(mb_obj, ESP_ERR_INVALID_STATE, TAG,
                            "Controller interface is not correctly initialized.");
    if (mb_obj->descr.is_master) {
        ret = mbm_get_handler(mb_controller->mb_base, func_code, handler);
    } else {
        ret = mbs_get_handler(mb_controller->mb_base, func_code, handler);
    }
    return  MB_ERR_TO_ESP_ERR(ret);
}

/**
 * Delete command handler from the command handler table of the object
 */
esp_err_t mbc_delete_handler(void *ctx, uint8_t func_code)
{
    MB_RETURN_ON_FALSE((ctx && func_code), ESP_ERR_INVALID_STATE, TAG,
                            "Incorrect arguments for the function.");
    mb_err_enum_t ret = MB_EINVAL;
    mb_controller_common_t *mb_controller = (mb_controller_common_t *)(ctx);
    mb_base_t *mb_obj = (mb_base_t *)mb_controller->mb_base;
    MB_RETURN_ON_FALSE(mb_obj, ESP_ERR_INVALID_STATE, TAG,
                            "Controller interface is not correctly initialized.");
    if (mb_obj->descr.is_master) {
        ret = mbm_delete_handler(mb_controller->mb_base, func_code);
    } else {
        ret = mbs_delete_handler(mb_controller->mb_base, func_code);
    }
    return  MB_ERR_TO_ESP_ERR(ret);
}

/**
 * Get number of registered command handlers for the object
 */
esp_err_t mbc_get_handler_count(void *ctx, uint16_t *count)
{
    MB_RETURN_ON_FALSE((ctx && count), ESP_ERR_INVALID_STATE, TAG,
                            "Controller interface is not correctly initialized.");
    mb_err_enum_t ret = MB_EINVAL;
    mb_controller_common_t *mb_controller = (mb_controller_common_t *)(ctx);
    mb_base_t *mb_obj = (mb_base_t *)mb_controller->mb_base;
    MB_RETURN_ON_FALSE(mb_obj, ESP_ERR_INVALID_STATE, TAG,
                            "Controller interface is not correctly initialized.");
    if (mb_obj->descr.is_master) {
        ret = mbm_get_handler_count(mb_controller->mb_base, count);
    } else {
        ret = mbs_get_handler_count(mb_controller->mb_base, count);
    }
    return  MB_ERR_TO_ESP_ERR(ret);
}