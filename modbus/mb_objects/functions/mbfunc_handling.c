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

mb_err_enum_t mb_set_handler(handler_descriptor_t *descriptor, uint8_t func_code, mb_fn_handler_fp handler)
{
    MB_RETURN_ON_FALSE((descriptor && handler && descriptor->instance), MB_EINVAL, TAG, "invalid arguments.");
    MB_RETURN_ON_FALSE(MB_IS_VALID_FUNC_CODE(func_code), MB_EINVAL, TAG,
                        "invalid function code (0x%x)", (int)func_code);

    mb_command_entry_t *item_ptr = NULL;
    LIST_FOREACH(item_ptr, &descriptor->head, entries) {
        if (item_ptr && item_ptr->func_code == func_code) {
            // The handler for the function already exists, rewrite it.
            item_ptr->handler = handler;
            ESP_LOGD(TAG, "Inst: %p, set handler: 0x%x, %p", descriptor->instance, item_ptr->func_code, item_ptr->handler);
            return MB_ENOERR;
        }
    }

    // Insert new handler entry into list
    if (descriptor->count >= MB_FUNC_HANDLERS_MAX) {
        return MB_ENORES;
    }
    descriptor->count += 1;
    item_ptr = (mb_command_entry_t *) heap_caps_malloc(sizeof(mb_command_entry_t), MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);

    MB_RETURN_ON_FALSE(item_ptr, MB_ENORES, TAG, "mb can not allocate memory for command handler 0x%x.", func_code);
    item_ptr->func_code = func_code;
    item_ptr->handler = handler;
    LIST_INSERT_HEAD(&descriptor->head, item_ptr, entries);
    ESP_LOGD(TAG, "Inst: %p, add handler: 0x%x, %p", descriptor->instance, item_ptr->func_code, item_ptr->handler);

    return MB_ENOERR;
}

mb_err_enum_t mb_get_handler(handler_descriptor_t *descriptor, uint8_t func_code, mb_fn_handler_fp *handler)
{
    MB_RETURN_ON_FALSE((descriptor && handler && descriptor->instance), MB_EINVAL, TAG, "invalid arguments.");
    MB_RETURN_ON_FALSE(MB_IS_VALID_FUNC_CODE(func_code), MB_EINVAL, TAG,
                        "invalid function code (0x%x)", (int)func_code);

    mb_command_entry_t *item_ptr = NULL;
    LIST_FOREACH(item_ptr, &descriptor->head, entries) {
        if (item_ptr && item_ptr->func_code == func_code) {
            *handler = item_ptr->handler;
            ESP_LOGD(TAG, "Inst: %p, get handler: 0x%x, %p", descriptor->instance, item_ptr->func_code, item_ptr->handler);
            return MB_ENOERR;
        }
    }
    return MB_ENORES;
}

// Helper function to get handler
mb_err_enum_t mb_delete_handler(handler_descriptor_t *descriptor, uint8_t func_code)
{
    MB_RETURN_ON_FALSE((descriptor && descriptor->instance), MB_EINVAL, TAG, "invalid arguments.");
    MB_RETURN_ON_FALSE(MB_IS_VALID_FUNC_CODE(func_code), MB_EINVAL, TAG,
                        "invalid function code (0x%x)", (int)func_code);

    if (LIST_EMPTY(&descriptor->head)) {
        return MB_EINVAL;
    }
    
    mb_command_entry_t *item_ptr = NULL;
    mb_command_entry_t *ptemp = NULL;
    LIST_FOREACH_SAFE(item_ptr, &descriptor->head, entries, ptemp) {
        if (item_ptr && item_ptr->func_code == func_code) {
            ESP_LOGD(TAG, "Inst: %p, remove handler: 0x%x, %p", descriptor->instance, item_ptr->func_code, item_ptr->handler);
            LIST_REMOVE(item_ptr, entries);
            free(item_ptr);
            if (descriptor->count) {
                descriptor->count--;
            }
            return MB_ENOERR;
        }
    }

    return MB_ENORES;
}

// Helper function to close all registered handlers in the list
mb_err_enum_t mb_delete_command_handlers(handler_descriptor_t *descriptor)
{
    MB_RETURN_ON_FALSE((descriptor), MB_EINVAL, TAG, "invalid arguments.");
    
    if (LIST_EMPTY(&descriptor->head)) {
        return MB_EINVAL;
    }

    mb_command_entry_t *item_ptr = NULL;
    while ((item_ptr = LIST_FIRST(&descriptor->head))) {
        ESP_LOGD(TAG, "Inst: %p, close handler: 0x%x, %p", descriptor->instance, item_ptr->func_code, item_ptr->handler);
        LIST_REMOVE(item_ptr, entries);
        free(item_ptr);
        if (descriptor->count) {
            descriptor->count--;
        }
    }
    return MB_ENOERR;
}