/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "driver/uart.h"            // for uart defines
#include "errno.h"                  // for errno
#include "sys/queue.h"              // for list
#include "esp_log.h"                // for log write
#include "string.h"                 // for strerror()

#ifdef __cplusplus
extern "C" {
#endif

#include "mb_common.h"              // for mb_base_t
#include "esp_modbus_slave.h"       // for public type defines
#include "mb_slave.h"

/* ----------------------- Defines ------------------------------------------*/
#define MB_INST_MIN_SIZE                    (1) // The minimal size of Modbus registers area in bytes
#define MB_INST_MAX_SIZE                    (65535 * 2) // The maximum size of Modbus area in bytes

#define MB_CONTROLLER_NOTIFY_QUEUE_SIZE     (CONFIG_FMB_CONTROLLER_NOTIFY_QUEUE_SIZE) // Number of messages in parameter notification queue
#define MB_CONTROLLER_NOTIFY_TIMEOUT        (pdMS_TO_TICKS(CONFIG_FMB_CONTROLLER_NOTIFY_TIMEOUT)) // notification timeout

/**
 * @brief Modbus area descriptor list item
 */
typedef struct mb_descr_entry_s {
    uint16_t start_offset;                  /*!< Modbus start address for area descriptor */
    mb_param_type_t type;                   /*!< Type of storage area descriptor */
    mb_param_access_t access;               /*!< Area access type */
    void *p_data;                           /*!< Instance address for storage area descriptor */
    size_t size;                            /*!< Instance size for area descriptor (bytes) */
    LIST_ENTRY(mb_descr_entry_s) entries;   /*!< The Modbus area descriptor entry */
} mb_descr_entry_t;

/**
 * @brief Modbus controller handler structure
 */
typedef struct {
    mb_port_type_t port_type;                           /*!< port type */
    mb_communication_info_t comm_opts;                  /*!< communication info */
    TaskHandle_t task_handle;                           /*!< task handle */
    EventGroupHandle_t event_group_handle;              /*!< controller event group */
    QueueHandle_t notification_queue_handle;            /*!< controller notification queue */
    LIST_HEAD(mbs_area_descriptors_, mb_descr_entry_s) area_descriptors[MB_PARAM_COUNT]; /*!< register area descriptors */
} mb_slave_options_t;

typedef mb_event_group_t (*iface_check_event_fp)(void *, mb_event_group_t);          /*!< Interface method check_event */
typedef esp_err_t (*iface_get_param_info_fp)(void *, mb_param_info_t*, uint32_t);    /*!< Interface method get_param_info */
typedef esp_err_t (*iface_mbs_set_descriptor_fp)(void *, mb_register_area_descriptor_t); /*!< Interface method set_descriptor */

/**
 * @brief Request mode for parameter to use in data dictionary
 */
typedef struct
{
    mb_base_t *mb_base;
    mb_slave_options_t opts;                /*!< Modbus slave options */
    bool is_active;                         /*!< Modbus controller interface is active */

    // Functional pointers to internal static functions of the implementation (public interface methods)
    iface_create_fp create;                     /*!< Interface factory method */
    iface_method_default_fp delete;             /*!< Interface method delete */
    iface_method_default_fp start;              /*!< Interface method start */
    iface_method_default_fp stop;               /*!< Interface method start */
    iface_check_event_fp check_event;           /*!< Interface method check_event */
    iface_get_param_info_fp get_param_info;     /*!< Interface method get_param_info */
    iface_mbs_set_descriptor_fp set_descriptor;     /*!< Interface method set_descriptor */
} mbs_controller_iface_t;

#ifdef __cplusplus
}
#endif
