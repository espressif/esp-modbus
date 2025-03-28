/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <inttypes.h>
#include "sdkconfig.h" // for KConfig options

#if __has_include("esp_idf_version.h")
#include "esp_idf_version.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------- Defines ------------------------------------------*/
/*! \defgroup modbus_cfg Modbus Configuration
 *
 * Most modules in the protocol stack are completly optional and can be
 * excluded. This is specially important if target resources are very small
 * and program memory space should be saved.<br>
 *
 * All of these settings are available in the file <code>mbconfig.h</code>
 */
/*! \addtogroup modbus_cfg
 *  @{
 */
/*! \brief If Modbus Master ASCII support is enabled. */
#define MB_MASTER_ASCII_ENABLED                 (CONFIG_FMB_COMM_MODE_ASCII_EN)
/*! \brief If Modbus Master RTU support is enabled. */
#define MB_MASTER_RTU_ENABLED                   (CONFIG_FMB_COMM_MODE_RTU_EN)
/*! \brief If Modbus Master TCP support is enabled. */
#define MB_MASTER_TCP_ENABLED                   (CONFIG_FMB_COMM_MODE_TCP_EN)
/*! \brief If Modbus Slave ASCII support is enabled. */
#define MB_SLAVE_ASCII_ENABLED                  (CONFIG_FMB_COMM_MODE_ASCII_EN)
/*! \brief If Modbus Slave RTU support is enabled. */
#define MB_SLAVE_RTU_ENABLED                    (CONFIG_FMB_COMM_MODE_RTU_EN)
/*! \brief If Modbus Slave TCP support is enabled. */
#define MB_TCP_ENABLED                          (CONFIG_FMB_COMM_MODE_TCP_EN)

#if (!CONFIG_FMB_COMM_MODE_ASCII_EN && !CONFIG_FMB_COMM_MODE_RTU_EN && !MB_MASTER_TCP_ENABLED && !MB_TCP_ENABLED)
#error "None of Modbus communication mode is enabled. Please enable one of (ASCII, RTU, TCP) mode in Kconfig."
#endif

#ifdef ESP_IDF_VERSION

#if (ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0))
// Features supported from v5.0
#define MB_TIMER_SUPPORTS_ISR_DISPATCH_METHOD 1
#endif

#endif

#define MB_TIMER_USE_ISR_DISPATCH_METHOD        (CONFIG_FMB_TIMER_USE_ISR_DISPATCH_METHOD)

/*! \brief The option is required for correct UART initialization to place handler into IRAM.
 */
#if CONFIG_UART_ISR_IN_IRAM
#define MB_PORT_SERIAL_ISR_FLAG                 (ESP_INTR_FLAG_IRAM)
#else
#define MB_PORT_SERIAL_ISR_FLAG                 (ESP_INTR_FLAG_LOWMED)
#endif

/*! \brief The option represents the serial buffer size for RTU and ASCI.
 */
#define MB_BUFFER_SIZE                          (CONFIG_FMB_BUFFER_SIZE)

/*! \brief The option is required for support of RTU over TCP.
 */
#define MB_TCP_UID_ENABLED                      (CONFIG_FMB_TCP_UID_ENABLED)

/*! \brief The option defines the queue size for event queue.
 */
#define MB_EVENT_QUEUE_SIZE                     (CONFIG_FMB_QUEUE_LENGTH)

/*! \brief This option defines the number of data bits per ASCII character.
 *
 * A parity bit is added before the stop bit which keeps the actual byte size at 10 bits.
 */
#if CONFIG_FMB_SERIAL_ASCII_BITS_PER_SYMB
#define MB_ASCII_BITS_PER_SYMB                  (CONFIG_FMB_SERIAL_ASCII_BITS_PER_SYMB)
#endif

/*! \brief The character timeout value for Modbus ASCII.
 *
 * The character timeout value is not fixed for Modbus ASCII and is therefore
 * a configuration option. It should be set to the maximum expected delay
 * time of the network.
 */
#if CONFIG_FMB_SERIAL_ASCII_TIMEOUT_RESPOND_MS
#define MB_ASCII_TIMEOUT_MS                     (CONFIG_FMB_SERIAL_ASCII_TIMEOUT_RESPOND_MS)
#else
#define MB_ASCII_TIMEOUT_MS 1000
#endif

/*! \brief Timeout to wait in ASCII prior to enabling transmitter.
 *
 * If defined the function calls vMBPortSerialDelay with the argument
 * MB_ASCII_TIMEOUT_WAIT_BEFORE_SEND_MS to allow for a delay before
 * the serial transmitter is enabled. This is required because some
 * targets are so fast that there is no time between receiving and
 * transmitting the frame. If the master is to slow with enabling its
 * receiver then he will not receive the response correctly.
 */
#ifndef MB_ASCII_TIMEOUT_WAIT_BEFORE_SEND_MS
#define MB_ASCII_TIMEOUT_WAIT_BEFORE_SEND_MS    (0)
#endif

/*! \brief Maximum number of Modbus functions codes the protocol stack
 *    should support.
 *
 * The maximum number of supported Modbus functions must be greater than
 * the sum of all enabled functions in this file and custom function
 * handlers. If set to small adding more functions will fail.
 */
#define MB_FUNC_HANDLERS_MAX                    (CONFIG_FMB_FUNC_HANDLERS_MAX)

/*! \brief Number of bytes which should be allocated for the <em>Report Slave ID
 *    </em>command.
 *
 * This number limits the maximum size of the additional segment in the
 * report slave id function. See eMBSetSlaveID(  ) for more information on
 * how to set this value. It is only used if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
 * is set to <code>1</code>.
 */
#define MB_FUNC_OTHER_REP_SLAVEID_BUF           (CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE)

/*! \brief If the <em>Report Slave ID</em> function should be enabled. */
#define MB_FUNC_OTHER_REP_SLAVEID_ENABLED       (CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT)

/*! \brief If the <em>Read Input Registers</em> function should be enabled. */
#define MB_FUNC_READ_INPUT_ENABLED              (1)

/*! \brief If the <em>Read Holding Registers</em> function should be enabled. */
#define MB_FUNC_READ_HOLDING_ENABLED            (1)

/*! \brief If the <em>Write Single Register</em> function should be enabled. */
#define MB_FUNC_WRITE_HOLDING_ENABLED           (1)

/*! \brief If the <em>Write Multiple registers</em> function should be enabled. */
#define MB_FUNC_WRITE_MULTIPLE_HOLDING_ENABLED  (1)

/*! \brief If the <em>Read Coils</em> function should be enabled. */
#define MB_FUNC_READ_COILS_ENABLED              (1)

/*! \brief If the <em>Write Coils</em> function should be enabled. */
#define MB_FUNC_WRITE_COIL_ENABLED              (1)

/*! \brief If the <em>Write Multiple Coils</em> function should be enabled. */
#define MB_FUNC_WRITE_MULTIPLE_COILS_ENABLED    (1)

/*! \brief If the <em>Read Discrete Inputs</em> function should be enabled. */
#define MB_FUNC_READ_DISCRETE_INPUTS_ENABLED    (1)

/*! \brief If the <em>Read/Write Multiple Registers</em> function should be enabled. */
#define MB_FUNC_READWRITE_HOLDING_ENABLED       (1)

/*! @} */


#if MB_MASTER_RTU_ENABLED || MB_MASTER_ASCII_ENABLED || MB_MASTER_TCP_ENABLED
/*! \brief If master send a broadcast frame, the master will wait time of convert to delay,
 * then master can send other frame */
#define MB_MASTER_DELAY_MS_CONVERT              (CONFIG_FMB_MASTER_DELAY_MS_CONVERT)
/*! \brief If master send a frame which is not broadcast,the master will wait sometime for slave.
 * And if slave is not respond in this time,the master will process this timeout error.
 * Then master can send other frame */
#define MB_MASTER_TIMEOUT_MS_RESPOND            (CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND)
/*! \brief The total slaves in Modbus Master system.
 * \note : The slave ID must be continuous from 1.*/
#define MB_MASTER_TOTAL_SLAVE_NUM               (247)
#define MB_MASTER_MIN_TIMEOUT_MS_RESPOND        (50)

#endif

#ifdef __cplusplus
}
#endif
