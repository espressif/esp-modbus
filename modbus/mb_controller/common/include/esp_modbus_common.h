/*
 * SPDX-FileCopyrightText: 2020-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <inttypes.h>

#include "driver/uart.h"                    // for UART types
#include "sdkconfig.h"

#if CONFIG_FMB_EXT_TYPE_SUPPORT
#include "mb_endianness_utils.h"
#endif

#include "port_common.h"

#if __has_include("esp_check.h")
#include "esp_check.h"
#include "esp_log.h"

#define MB_RETURN_ON_FALSE(a, err_code, tag, format, ...) ESP_RETURN_ON_FALSE(a, err_code, tag, format __VA_OPT__(,) __VA_ARGS__)

#else

// if cannot include esp_check then use custom check macro

#define MB_RETURN_ON_FALSE(a, err_code, tag, format, ...) do {                                         \
        if (!(a)) {                                                                                    \
            ESP_LOGE(tag, "%s(%d): " format, __FUNCTION__, __LINE__ __VA_OPT__(,) __VA_ARGS__);        \
            return err_code;                                                                           \
        }                                                                                              \
} while(0)

#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MB_SLAVE_ADDR_PLACEHOLDER           (0xFF)
#define MB_CONTROLLER_STACK_SIZE            (CONFIG_FMB_CONTROLLER_STACK_SIZE)  // Stack size for Modbus controller
#define MB_CONTROLLER_PRIORITY              (CONFIG_FMB_PORT_TASK_PRIO - 1)     // priority of MB controller task
#define MB_PORT_TASK_AFFINITY               (CONFIG_FMB_PORT_TASK_AFFINITY)

// Default port defines
#define MB_PAR_INFO_TOUT                    (10) // Timeout for get parameter info
#define MB_PARITY_NONE                      (UART_PARITY_DISABLE)
#define MB_SECTION(lock)                    CRITICAL_SECTION(lock) {}

// The Macros below handle the endianness while transfer N byte data into buffer
#define _XFER_4_RD(dst, src) { \
    *(uint8_t *)(dst)++ = *(uint8_t *)(src + 1); \
    *(uint8_t *)(dst)++ = *(uint8_t *)(src + 0); \
    *(uint8_t *)(dst)++ = *(uint8_t *)(src + 3); \
    *(uint8_t *)(dst)++ = *(uint8_t *)(src + 2); \
    (src) += 4; \
}

#define _XFER_2_RD(dst, src) { \
    *(uint8_t *)(dst)++ = *(uint8_t *)(src + 1); \
    *(uint8_t *)(dst)++ = *(uint8_t *)(src + 0); \
    (src) += 2; \
}

#define _XFER_4_WR(dst, src) { \
    *(uint8_t *)(dst + 1) = *(uint8_t *)(src)++; \
    *(uint8_t *)(dst + 0) = *(uint8_t *)(src)++; \
    *(uint8_t *)(dst + 3) = *(uint8_t *)(src)++; \
    *(uint8_t *)(dst + 2) = *(uint8_t *)(src)++ ; \
}

#define _XFER_2_WR(dst, src) { \
    *(uint8_t *)(dst + 1) = *(uint8_t *)(src)++; \
    *(uint8_t *)(dst + 0) = *(uint8_t *)(src)++; \
}

#define mb_err_var esp_err##__func__##__line__
#define esp_err_var mb_error##__func__##__line__
#define MB_ERR_TO_ESP_ERR(error_code) (__extension__(           \
{                                                               \
    mb_err_enum_t mb_err_var = (mb_err_enum_t)error_code;       \
    esp_err_t esp_err_var = ESP_FAIL;                           \
    switch(mb_err_var) {                                        \
        case MB_ENOERR:                                         \
            esp_err_var = ESP_OK;                               \
            break;                                              \
        case MB_ENOREG:                                         \
            esp_err_var = ESP_ERR_NOT_SUPPORTED;                \
            break;                                              \
        case MB_ETIMEDOUT:                                      \
            esp_err_var = ESP_ERR_TIMEOUT;                      \
            break;                                              \
        case MB_EINVAL:                                         \
            esp_err_var = ESP_ERR_INVALID_ARG;                  \
            break;                                              \
        case MB_EILLFUNC:                                       \
            esp_err_var = ESP_ERR_INVALID_RESPONSE;             \
            break;                                              \
        case MB_ERECVDATA:                                      \
            esp_err_var = ESP_ERR_INVALID_RESPONSE;             \
            break;                                              \
        case MB_EBUSY:                                          \
        case MB_EILLSTATE:                                      \
        case MB_EPORTERR:                                       \
        case MB_ENORES:                                         \
        case MB_ENOCONN:                                        \
            esp_err_var = ESP_ERR_INVALID_STATE;                \
            break;                                              \
        default:                                                \
            ESP_LOGE(TAG, "%s: Incorrect return code (%x) ", __FUNCTION__, (int)mb_err_var); \
            esp_err_var = ESP_FAIL;                             \
            break;                                              \
    }                                                           \
    (esp_err_var);                                              \
}                                                               \
))

/**
 * @brief Types of actual Modbus implementation
 */
typedef enum
{
    MB_PORT_SERIAL_MASTER = 0x00,   /*!< Modbus port type serial master. */
    MB_PORT_SERIAL_SLAVE,           /*!< Modbus port type serial slave. */
    MB_PORT_TCP_MASTER,             /*!< Modbus port type TCP master. */
    MB_PORT_TCP_SLAVE,              /*!< Modbus port type TCP slave. */
    MB_PORT_COUNT,                  /*!< Modbus port count. */
    MB_PORT_INACTIVE = 0xFF
} mb_port_type_t;

/**
 * @brief Event group for parameters notification
 */
typedef enum
{
    MB_EVENT_NO_EVENTS = 0x00,
    MB_EVENT_HOLDING_REG_WR = BIT0,         /*!< Modbus Event Write Holding registers. */
    MB_EVENT_HOLDING_REG_RD = BIT1,         /*!< Modbus Event Read Holding registers. */
    MB_EVENT_INPUT_REG_RD = BIT3,           /*!< Modbus Event Read Input registers. */
    MB_EVENT_COILS_WR = BIT4,               /*!< Modbus Event Write Coils. */
    MB_EVENT_COILS_RD = BIT5,               /*!< Modbus Event Read Coils. */
    MB_EVENT_DISCRETE_RD = BIT6,            /*!< Modbus Event Read Discrete bits. */
    MB_EVENT_STACK_STARTED = BIT7,          /*!< Modbus Event Stack started */
    MB_EVENT_STACK_CONNECTED = BIT8         /*!< Modbus Event Stack started */
} mb_event_group_t;

/**
 * @brief Type of Modbus parameter
 */
typedef enum {
    MB_PARAM_HOLDING = 0x00,            /*!< Modbus Holding register. */
    MB_PARAM_INPUT,                     /*!< Modbus Input register. */
    MB_PARAM_COIL,                      /*!< Modbus Coils. */
    MB_PARAM_DISCRETE,                  /*!< Modbus Discrete bits. */
    MB_PARAM_COUNT,
    MB_PARAM_CUSTOM,                    /*!< Modbus custom commands (is not counted in area descriptors). */
    MB_PARAM_UNKNOWN = 0xFF
} mb_param_type_t;

typedef enum _mb_comm_mode mb_mode_type_t;

typedef struct mb_base_t mb_base_t;

/*!
 * \brief Modbus TCP type of address for communication.
 */
typedef enum _addr_type_enum mb_tcp_addr_type_t;

/*!
 * \brief Modbus TCP communication options structure.
 */
typedef struct port_tcp_opts_s mb_tcp_opts_t;

/*!
 * \brief Modbus serial communication options structure.
 */
typedef struct port_serial_opts_s mb_serial_opts_t;

/*!
 * \brief Modbus common communication options structure.
 */
typedef struct port_common_opts_s mb_common_opts_t;

/**
 * @brief Device communication structure to setup Modbus controller
 */
typedef union 
{   
    mb_comm_mode_t mode;            /*!< mode option to check the communication object type*/
    mb_common_opts_t common_opts;   /*!< Common options for communication object. */
#if (CONFIG_FMB_COMM_MODE_TCP_EN)
    mb_tcp_opts_t tcp_opts;         /*!< tcp options for communication object */
#endif
#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)
    mb_serial_opts_t ser_opts;      /*!< serial options for communication object */
#endif
} mb_communication_info_t;

/**
 * common interface method types
 */
typedef esp_err_t (*iface_create_fp)(mb_communication_info_t*, void **);    /*!< Interface method create */
typedef esp_err_t (*iface_method_default_fp)(void *ctx);                    /*!< Interface method default prototype */

/**
 * @brief Modbus controller common interface structure
 */
typedef struct {
    mb_base_t *mb_base;      /*!< base object pointer */
} mb_controller_common_t;

/**
 * @brief The function registers the new function handler for specified command 
 *        and allows to override the existing handler for the the controller object.
 * 
 * @param[in] ctx context pointer to the controller object (master or slave)
 * @param[in] func_code the function code for the handler
 * @param[in] phandler the pointer to function handler being used for command
 *
 * @return
 *     - esp_err_t ESP_OK - the function handler is correctly set the handler
 *     - esp_err_t ESP_ERR_INVALID_ARG - invalid argument of function or parameter descriptor
 *     - esp_err_t ESP_ERR_INVALID_STATE - can not register non-existent handler or can not
 *     - esp_err_t ESP_ERR_NOT_FOUND - the requested slave is not found (not connected or not configured)
*/
esp_err_t mbc_set_handler(void *ctx, uint8_t func_code, mb_fn_handler_fp phandler);

/**
 * @brief The function gets function handler for specified command from the controller object handler table.
 * 
 * @param[in] ctx context pointer to the controller object (master or slave)
 * @param[in] func_code the function code for the handler
 * @param[out] phandler the pointer to function handler being returned
 *
 * @return
 *     - esp_err_t ESP_OK - the function handler is returned
 *     - esp_err_t ESP_ERR_INVALID_ARG - invalid argument of function or parameter descriptor
 *       esp_err_t ESP_ERR_INVALID_STATE - can not register non-existent handler or incorrect configuration
*/
esp_err_t mbc_get_handler(void *ctx, uint8_t func_code, mb_fn_handler_fp *phandler);

/**
 * @brief The function deletes function handler for specified command from the controller object command handler table.
 * 
 * @param[in] ctx context pointer to the controller object (master or slave)
 * @param[in] func_code the function code for the handler
 *
 * @return
 *     - esp_err_t ESP_OK - the function handler is deleted
 *     - esp_err_t ESP_ERR_INVALID_ARG - invalid argument of function or parameter descriptor
 *       esp_err_t ESP_ERR_INVALID_STATE - can not register non-existent handler or incorrect configuration
*/
esp_err_t mbc_delete_handler(void *ctx, uint8_t func_code);

/**
 * @brief The function gets the number of registered function handlers for the controller object.
 * 
 * @param[in] ctx context pointer to the controller object (master or slave)
 * @param[out] pcount the pointer to returned counter
 * 
 * @return
 *     - esp_err_t ESP_OK - the function handler is returned in the 
 *     - esp_err_t ESP_ERR_INVALID_ARG - invalid argument of function or parameter descriptor
 *       esp_err_t ESP_ERR_INVALID_STATE - can not register non-existent handler or incorrect configuration
*/
esp_err_t mbc_get_handler_count(void *ctx, uint16_t *pcount);

#ifdef __cplusplus
}
#endif

