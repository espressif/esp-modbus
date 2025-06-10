/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <sys/queue.h>              // for list
#include "freertos/FreeRTOS.h"      // for task creation and queue access
#include "freertos/task.h"          // for task api access
#include "freertos/event_groups.h"  // for event groups
#include "freertos/semphr.h"        // for semaphore
#include "freertos/queue.h"         // for queue api access
#include "driver/uart.h"            // for UART types
#include "errno.h"                  // for errno
#include "esp_log.h"                // for log write
#include "string.h"                 // for strerror()
#include "esp_modbus_common.h"      // for common types
#include "esp_modbus_master.h"      // for public master types

#include "mb_common.h"              // for mb_base_t
#include "mb_utils.h"
#include "mb_master.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------- Defines ------------------------------------------*/

// Set the maximum resource waiting time, the actual time of resouce release
// will be dependent on response time set by timer + convertion time if the command is received
#define MB_MAX_RESP_DELAY_MS (3000)

/**
 * @brief Modbus controller handler structure
 */
typedef struct {
    mb_port_type_t port_type;                           /*!< Modbus port type */
    mb_communication_info_t comm_opts;                  /*!< Modbus communication info */
    uint8_t *reg_buffer_ptr;                            /*!< Modbus data buffer pointer */
    uint16_t reg_buffer_size;                           /*!< Modbus data buffer size */
    TaskHandle_t task_handle;                           /*!< Modbus task handle */
    EventGroupHandle_t event_group_handle;              /*!< Modbus controller event group */
    SemaphoreHandle_t mbm_sema;                         /*!< Modbus controller semaphore */
    const mb_parameter_descriptor_t *param_descriptor_table; /*!< Modbus controller parameter description table */
    size_t mbm_param_descriptor_size;                   /*!< Modbus controller parameter description table size */
} mb_master_options_t;

typedef esp_err_t (*iface_get_cid_info_fp)(void *, uint16_t, const mb_parameter_descriptor_t **);           /*!< Interface get_cid_info method */
typedef esp_err_t (*iface_get_parameter_fp)(void *, uint16_t, uint8_t *, uint8_t *);                        /*!< Interface get_parameter method */
typedef esp_err_t (*iface_get_parameter_with_fp)(void *, uint16_t, uint8_t, uint8_t *, uint8_t *);          /*!< Interface get_parameter_with method */
typedef esp_err_t (*iface_send_request_fp)(void *, mb_param_request_t*, void *);                            /*!< Interface send_request method */
typedef esp_err_t (*iface_mbm_set_descriptor_fp)(void *, const mb_parameter_descriptor_t*, const uint16_t); /*!< Interface set_descriptor method */
typedef esp_err_t (*iface_set_parameter_fp)(void *, uint16_t, uint8_t *, uint8_t *);                        /*!< Interface set_parameter method */
typedef esp_err_t (*iface_set_parameter_with_fp)(void *, uint16_t, uint8_t, uint8_t *, uint8_t *);          /*!< Interface set_parameter_with method */

/**
 * @brief Modbus controller interface structure
 */
typedef struct {
    mb_base_t *mb_base;
    // Master object interface options
    mb_master_options_t opts;
    bool is_active;                                 /*!< Interface is active */

    // Public interface methods
    iface_create_fp create;                         /*!< Interface constructor */
    iface_method_default_fp delete;                 /*!< Interface method delete */
    iface_method_default_fp start;                  /*!< Interface method start */
    iface_method_default_fp stop;                   /*!< Interface method stop */
    iface_get_cid_info_fp get_cid_info;             /*!< Interface get_cid_info method */
    iface_get_parameter_fp get_parameter;           /*!< Interface get_parameter method */
    iface_get_parameter_with_fp get_parameter_with; /*!< Interface get_parameter_with method */
    iface_send_request_fp send_request;             /*!< Interface send_request method */
    iface_mbm_set_descriptor_fp set_descriptor;     /*!< Interface set_descriptor method */
    iface_set_parameter_fp set_parameter;           /*!< Interface set_parameter method */
    iface_set_parameter_with_fp set_parameter_with; /*!< Interface set_parameter_with method */
} mbm_controller_iface_t;

#ifdef __cplusplus
}
#endif
