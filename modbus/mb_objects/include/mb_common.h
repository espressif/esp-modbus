/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdint.h>
#include <sys/queue.h>

#include "mb_config.h"
#include "mb_frame.h"
#include "mb_types.h"
#include "port_common.h"
#include "mb_callbacks.h"
#include "mb_port_types.h"

#include "esp_log.h"

#include "sdkconfig.h"

/* Common definitions */

#ifdef __cplusplus
extern "C" {
#endif

#if __has_include("esp_check.h")
#include "esp_check.h"

#define MB_RETURN_ON_FALSE(a, err_code, tag, format, ...) ESP_RETURN_ON_FALSE(a, err_code, tag, format __VA_OPT__(,) __VA_ARGS__)
#define MB_GOTO_ON_ERROR(x, goto_tag, log_tag, format, ...) ESP_GOTO_ON_ERROR(x, goto_tag, log_tag, format __VA_OPT__(,) __VA_ARGS__)
#define MB_GOTO_ON_FALSE(a, err_code, goto_tag, log_tag, format, ...) ESP_GOTO_ON_FALSE(a, err_code, goto_tag, log_tag, format __VA_OPT__(,) __VA_ARGS__)

#else

// if cannot include esp_check then use custom check macro

#define MB_RETURN_ON_FALSE(a, err_code, tag, format, ...) do {                                         \
        if (!(a)) {                                                                                    \
            ESP_LOGE(tag, "%s(%d): " format, __FUNCTION__, __LINE__ __VA_OPT__(,) __VA_ARGS__);        \
            return err_code;                                                                           \
        }                                                                                              \
} while(0)

#define MB_GOTO_ON_ERROR(x, goto_tag, log_tag, format, ...) do {                                           \
        esp_err_t err_rc_ = (x);                                                                           \
        if (err_rc_ != ESP_OK) {                                                                           \
            ESP_LOGE(log_tag, "%s(%d): " format, __FUNCTION__, __LINE__ __VA_OPT__(,) __VA_ARGS__);        \
            ret = err_rc_;                                                                                 \
            goto goto_tag;                                                                                 \
        }                                                                                                  \
    } while(0)

#define MB_GOTO_ON_FALSE(a, err_code, goto_tag, log_tag, format, ...) do {                                  \
        (void)log_tag;                                                                                      \
        if (!(a)) {                                                                                         \
            ESP_LOGE(log_tag, "%s(%d): " format, __FUNCTION__, __LINE__ __VA_OPT__(,) __VA_ARGS__);         \
            ret = (err_code);                                                                               \
            goto goto_tag;                                                                                  \
        }                                                                                                   \
    } while (0) 

#endif

#define MB_CAT_BUF_SIZE (100)
#define MB_HANDLER_UNLOCK_TICKS (pdMS_TO_TICKS(5000))

#define SEMA_SECTION(sema, tout) for (int st = (int)xSemaphoreTake(sema, tout); (st > 0); xSemaphoreGive(sema), st = -1)

#define MB_PRT_BUF(pref, message, buffer, length, level) (__extension__(            \
{                                                                                   \
    assert(buffer);                                                                 \
    char str_buf##__FUNCTION__##__LINE__[MB_CAT_BUF_SIZE];                          \
    strncpy(&(str_buf##__FUNCTION__##__LINE__)[0], pref, (MB_CAT_BUF_SIZE - 1));    \
    strncat((str_buf##__FUNCTION__##__LINE__), message, (MB_CAT_BUF_SIZE - 1));     \
    ESP_LOG_BUFFER_HEX_LEVEL(&((str_buf##__FUNCTION__##__LINE__)[0]),               \
                                (void *)buffer, (uint16_t)length, level);           \
    (&((str_buf##__FUNCTION__##__LINE__)[0]));                                      \
}                                                                                   \
))

#define MB_OBJ_FMT "%p"

#define MB_GET_OBJ_CTX(inst, type, base) (__extension__(    \
{                                                           \
    assert(inst);                                           \
    ((type *)__containerof(inst, type, base));              \
}                                                           \
))

#define MB_OBJ(inst) (__extension__( \
{                                           \
    assert(inst);                           \
    ((typeof(inst))(inst));                 \
}                                           \
))

#define MB_OBJ_PARENT(inst) (((obj_descr_t*)(inst))->parent)

#define MB_BASE2PORT(inst) (__extension__(      \
{                                               \
    assert(inst);                               \
    assert(((mb_base_t *)inst)->port_obj);      \
    (((mb_base_t *)inst)->port_obj);            \
}                                               \
))

/**
 * @brief Modbus function handlers entry
 */
typedef struct mb_command_entry_s {
    uint8_t func_code;                          /*!< function code */
    mb_fn_handler_fp handler;                   /*!< handler function pointer */
    LIST_ENTRY(mb_command_entry_s) entries;     /*!< command handler entry */
} mb_command_entry_t;

typedef LIST_HEAD(handler_head, mb_command_entry_s) handler_head_t;

typedef struct mb_handler_descriptor_s {
    SemaphoreHandle_t sema;
    void* instance;
    handler_head_t head;
    uint16_t count;
} handler_descriptor_t;

typedef struct mb_base_t mb_base_t;
typedef struct mb_trans_base_t mb_trans_base_t;
typedef struct mb_port_base_t mb_port_base_t;
typedef struct obj_descr_s obj_descr_t;

typedef mb_err_enum_t (*mb_delete_fp)(mb_base_t *inst);
typedef mb_err_enum_t (*mb_enable_fp)(mb_base_t *inst);
typedef mb_err_enum_t (*mb_disable_fp)(mb_base_t *inst);
typedef mb_err_enum_t (*mb_poll_fp)(mb_base_t *inst);
typedef void (*mb_set_addr_fp)(mb_base_t *inst, uint8_t dest_addr);
typedef uint8_t (*mb_get_addr_fp)(mb_base_t *inst);
typedef void (*mb_set_send_len_fp)(mb_base_t *inst, uint16_t len);
typedef uint16_t (*mb_get_send_len_fp)(mb_base_t *inst);
typedef void (*mb_get_send_buf_fp)(mb_base_t *inst, uint8_t **buf);

typedef enum
{
    STATE_ENABLED,
    STATE_DISABLED,
    STATE_NOT_INITIALIZED
} mb_state_enum_t;

struct mb_base_t
{
    obj_descr_t descr;
    _lock_t lock;                   // base object lock
    mb_trans_base_t *transp_obj;
    mb_port_base_t  *port_obj;

#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
    uint8_t *obj_id;
    uint16_t obj_id_len;
    uint8_t obj_id_chunks;
#endif

    mb_delete_fp delete;
    mb_enable_fp enable;
    mb_disable_fp disable;
    mb_poll_fp poll;
    mb_set_addr_fp set_dest_addr;
    mb_get_addr_fp get_dest_addr;
    mb_set_send_len_fp set_send_len;
    mb_get_send_len_fp get_send_len;
    mb_get_send_buf_fp get_send_buf;

    mb_rw_callbacks_t rw_cbs;
};

// Helper functions for command handlers registration
mb_err_enum_t mb_set_handler(handler_descriptor_t *descriptor, uint8_t func_code, mb_fn_handler_fp handler);
mb_err_enum_t mb_get_handler(handler_descriptor_t *descriptor, uint8_t func_code, mb_fn_handler_fp *handler);
mb_err_enum_t mb_delete_handler(handler_descriptor_t *descriptor, uint8_t func_code);
mb_err_enum_t mb_delete_command_handlers(handler_descriptor_t *descriptor);

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

typedef struct port_serial_opts_s mb_serial_opts_t;

mb_err_enum_t mbs_rtu_create(mb_serial_opts_t *ser_opts, void **in_out_obj);
mb_err_enum_t mbs_ascii_create(mb_serial_opts_t *ser_opts, void **in_out_obj);

#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

typedef struct port_tcp_opts_s mb_tcp_opts_t;
mb_err_enum_t mbs_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);

#endif

mb_err_enum_t mbs_delete(mb_base_t *inst);
mb_err_enum_t mbs_enable(mb_base_t *inst);
mb_err_enum_t mbs_disable(mb_base_t *inst);
mb_err_enum_t mbs_poll(mb_base_t *inst);

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

mb_err_enum_t mbm_rtu_create(mb_serial_opts_t *ser_opts, void **in_out_obj);
mb_err_enum_t mbm_ascii_create(mb_serial_opts_t *ser_opts, void **in_out_obj);

#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

mb_err_enum_t mbm_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);

#endif

mb_err_enum_t mbm_delete(mb_base_t *inst);
mb_err_enum_t mbm_enable(mb_base_t *inst);
mb_err_enum_t mbm_disable(mb_base_t *inst);
mb_err_enum_t mbm_poll(mb_base_t *inst);

#ifdef __cplusplus
}
#endif