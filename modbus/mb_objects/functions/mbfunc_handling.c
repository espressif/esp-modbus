/*
 * SPDX-FileCopyrightText: 2021-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "mb_common.h"
#include "mb_proto.h"

/* ----------------------- Defines ------------------------------------------*/
#define MB_IS_VALID_FUNC_CODE(fc)   ((fc) >= MB_FUNC_CODE_MIN && (fc) <= MB_FUNC_CODE_MAX)
static const char TAG[] __attribute__((unused)) = "MB_FUNC_HANDLING";

mb_err_enum_t mb_set_handler(handler_descriptor_t *pdescriptor, uint8_t func_code, mb_fn_handler_fp phandler)
{
    MB_RETURN_ON_FALSE((pdescriptor && phandler && pdescriptor->instance), MB_EINVAL, TAG, "invalid arguments.");
    MB_RETURN_ON_FALSE(MB_IS_VALID_FUNC_CODE(func_code), MB_EINVAL, TAG,
                        "invalid function code (0x%x)", (int)func_code);

    mb_command_entry_t *pitem = NULL;
    LIST_FOREACH(pitem, &pdescriptor->head, entries) {
        if (pitem && pitem->func_code == func_code) {
            // The handler for the function already exists, rewrite it.
            pitem->handler = phandler;
            ESP_LOGD(TAG, "Inst: %p, set handler: 0x%x, %p", pdescriptor->instance, pitem->func_code, pitem->handler);
            return MB_ENOERR;
        }
    }

    // Insert new handler entry into list
    if (pdescriptor->count >= MB_FUNC_HANDLERS_MAX) {
        return MB_ENORES;
    } else {
        pdescriptor->count += 1;
    }
    pitem = (mb_command_entry_t *) heap_caps_malloc(sizeof(mb_command_entry_t), MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);

    MB_RETURN_ON_FALSE(pitem, MB_ENORES, TAG, "mb can not allocate memory for command handler 0x%x.", func_code);
    pitem->func_code = func_code;
    pitem->handler = phandler;
    LIST_INSERT_HEAD(&pdescriptor->head, pitem, entries);
    ESP_LOGD(TAG, "Inst: %p, add handler: 0x%x, %p", pdescriptor->instance, pitem->func_code, pitem->handler);

    return MB_ENOERR;
}

mb_err_enum_t mb_get_handler(handler_descriptor_t *pdescriptor, uint8_t func_code, mb_fn_handler_fp *phandler)
{
    MB_RETURN_ON_FALSE((pdescriptor && phandler && pdescriptor->instance), MB_EINVAL, TAG, "invalid arguments.");
    MB_RETURN_ON_FALSE(MB_IS_VALID_FUNC_CODE(func_code), MB_EINVAL, TAG,
                        "invalid function code (0x%x)", (int)func_code);

    mb_command_entry_t *pitem = NULL;
    LIST_FOREACH(pitem, &pdescriptor->head, entries) {
        if (pitem && pitem->func_code == func_code) {
            *phandler = pitem->handler;
            ESP_LOGD(TAG, "Inst: %p, get handler: 0x%x, %p", pdescriptor->instance, pitem->func_code, pitem->handler);
            return MB_ENOERR;
        }
    }
    return MB_ENORES;
}

// Helper function to get handler
mb_err_enum_t mb_delete_handler(handler_descriptor_t *pdescriptor, uint8_t func_code)
{
    MB_RETURN_ON_FALSE((pdescriptor && pdescriptor->instance), MB_EINVAL, TAG, "invalid arguments.");
    MB_RETURN_ON_FALSE(MB_IS_VALID_FUNC_CODE(func_code), MB_EINVAL, TAG,
                        "invalid function code (0x%x)", (int)func_code);

    if (LIST_EMPTY(&pdescriptor->head)) {
        return MB_EINVAL;
    }
    
    mb_command_entry_t *pitem = NULL;
    mb_command_entry_t *ptemp = NULL;
    LIST_FOREACH_SAFE(pitem, &pdescriptor->head, entries, ptemp) {
        if (pitem && pitem->func_code == func_code) {
            ESP_LOGD(TAG, "Inst: %p, remove handler: 0x%x, %p", pdescriptor->instance, pitem->func_code, pitem->handler);
            LIST_REMOVE(pitem, entries);
            free(pitem);
            if (pdescriptor->count) {
                pdescriptor->count--;
            }
            return MB_ENOERR;
        }
    }

    return MB_ENORES;
}

// Helper function to close all registered handlers in the list
mb_err_enum_t mb_delete_command_handlers(handler_descriptor_t *pdescriptor)
{
    MB_RETURN_ON_FALSE((pdescriptor), MB_EINVAL, TAG, "invalid arguments.");
    
    if (LIST_EMPTY(&pdescriptor->head)) {
        return MB_EINVAL;
    }

    mb_command_entry_t *pitem = NULL;
    while ((pitem = LIST_FIRST(&pdescriptor->head))) {
        ESP_LOGD(TAG, "Inst: %p, close handler: 0x%x, %p", pdescriptor->instance, pitem->func_code, pitem->handler);
        LIST_REMOVE(pitem, entries);
        free(pitem);
        if (pdescriptor->count) {
            pdescriptor->count--;
        }
    }
    return MB_ENOERR;
}