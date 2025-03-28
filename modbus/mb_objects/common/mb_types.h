/*
 * FreeModbus Libary: A portable Modbus implementation for Modbus ASCII/RTU.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#pragma once

#include "stdbool.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------- Type definitions ---------------------------------*/

/*! \ingroup modbus
 * \brief Modbus serial transmission modes (RTU/ASCII/TCP/UDP).
 *
 * Modbus serial supports two transmission modes. Either ASCII or RTU. RTU
 * is faster but has more hardware requirements and requires a network with
 * a low jitter. ASCII is slower and more reliable on slower links (E.g. modems)
 * The TCP or UDP mode is used for communication over ethernet. 
 */
typedef enum _mb_comm_mode
{
    MB_RTU,                     /*!< RTU transmission mode. */
    MB_ASCII,                   /*!< ASCII transmission mode. */
    MB_TCP,                     /*!< TCP mode. */
    MB_UDP                      /*!< UDP mode. */
} mb_comm_mode_t;

/*! \ingroup modbus
 * \brief If register should be written or read.
 *
 * This value is passed to the callback functions which support either
 * reading or writing register values. Writing means that the application
 * registers should be updated and reading means that the modbus protocol
 * stack needs to know the current register values.
 *
 * \see mbs_reg_holding_cb(), mbs_reg_coils_cb(), mbs_reg_holding_cb() and
 *   mbs_reg_input_cb().
 */
typedef enum
{
    MB_REG_READ = 0x0001,   /*!< Read register values and pass to protocol stack. */
    MB_REG_WRITE = 0x0002,  /*!< Update register values. */
} mb_reg_mode_enum_t;

/*! \ingroup modbus
 * \brief Event types used by all function in the protocol stack.
 */
typedef enum _mb_event_enum {
    EV_TRANS_START = 0x0001,                    /*!< Start of transaction. */
    EV_READY = 0x0002,                          /*!< Startup finished. */
    EV_FRAME_RECEIVED = 0x0004,                 /*!< Frame received. */
    EV_EXECUTE = 0x0008,                        /*!< Execute function. */
    EV_FRAME_TRANSMIT = 0x0010,                 /*!< Transmission started . */
    EV_FRAME_SENT = 0x0020,                     /*!< Frame sent. */
    EV_ERROR_PROCESS = 0x0040,                  /*!< Error process state. */
    EV_MASTER_ERROR_RESPOND_TIMEOUT = 0x0080,   /*!< Request respond timeout. */
    EV_MASTER_ERROR_RECEIVE_DATA = 0x0100,      /*!< Request receive data error. */
    EV_MASTER_ERROR_EXECUTE_FUNCTION = 0x0200,  /*!< Request execute function error. */
    EV_MASTER_PROCESS_SUCCESS = 0x0400          /*!< Master error process. */
} mb_event_enum_t;

/*! \ingroup modbus
 * \brief Modbus exception types used in the stack.
 */
typedef enum _mb_exception_enum
{
    MB_EX_NONE = 0x00,
    MB_EX_ILLEGAL_FUNCTION = 0x01,
    MB_EX_ILLEGAL_DATA_ADDRESS = 0x02,
    MB_EX_ILLEGAL_DATA_VALUE = 0x03,
    MB_EX_SLAVE_DEVICE_FAILURE = 0x04,
    MB_EX_ACKNOWLEDGE = 0x05,
    MB_EX_SLAVE_BUSY = 0x06,
    MB_EX_MEMORY_PARITY_ERROR = 0x08,
    MB_EX_GATEWAY_PATH_FAILED = 0x0A,
    MB_EX_GATEWAY_TGT_FAILED = 0x0B,
    MB_EX_CRITICAL = 0xFF
} mb_exception_t;

typedef mb_exception_t (*mb_fn_handler_fp)(void *, uint8_t *frame_ptr, uint16_t *len_buf);

/*! \ingroup modbus
 * \brief Error event type
 */
typedef enum _mb_err_event_enum {
    EV_ERROR_INIT,             /*!< No error, initial state. */
    EV_ERROR_RESPOND_TIMEOUT,  /*!< Slave respond timeout. */
    EV_ERROR_RECEIVE_DATA,     /*!< Receive frame data error. */
    EV_ERROR_EXECUTE_FUNCTION, /*!< Execute function error. */
    EV_ERROR_OK                /*!< No error, processing completed. */
} mb_err_event_t;

typedef struct _mb_event_t {
    mb_event_enum_t event;      /*!< event itself. */
    uint64_t trans_id;          /*!< unique transaction id */
    uint16_t length;            /*!< length of data accociated with the event */ 
    void *pdata;                /*!< data accociated with the event */
    mb_err_event_t type;        /*!< error type accociated with the event */
    uint64_t post_ts;           /*!< timestamp of event posted */
    uint64_t get_ts;            /*!< timestamp of event receved */
} mb_event_t;

/*! \ingroup modbus
 * \brief Errorcodes used by all function in the protocol stack.
 */
typedef enum
{
    MB_ENOERR,                  /*!< no error. */
    MB_ENOREG,                  /*!< illegal register address. */
    MB_EINVAL,                  /*!< illegal argument. */
    MB_EPORTERR,                /*!< porting layer error. */
    MB_ENORES,                  /*!< insufficient resources. */
    MB_EIO,                     /*!< I/O error. */
    MB_EILLSTATE,               /*!< protocol stack in illegal state. */
    MB_ERECVDATA,               /*!< receive data error. */
    MB_ETIMEDOUT,               /*!< timeout error occurred. */
    MB_EILLFUNC,                /*!< illegal MB function. */
    MB_EBUSY,                   /*!< master is busy now. */
    MB_ENOCONN                  /*!< peer is not connected. */
} mb_err_enum_t;

/*! \ingroup modbus
 *  \brief TimerMode is Master 3 kind of Timer modes.
 */
typedef enum
{
	MB_TMODE_T35,                   /*!< Master receive frame T3.5 timeout. */
	MB_TMODE_RESPOND_TIMEOUT,       /*!< Master wait respond for slave. */
	MB_TMODE_CONVERT_DELAY          /*!< Master sent broadcast , then delay sometime.*/
} mb_timer_mode_enum_t;

#ifdef __cplusplus
}
#endif

