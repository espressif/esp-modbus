/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdint.h>
#include "mb_func.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------- Defines ------------------------------------------*/
#define MB_ADDRESS_BROADCAST    ( 0 )   /*! Modbus broadcast address. */
#define MB_ADDRESS_MIN          ( 1 )   /*! Smallest possible slave address. */
#define MB_ADDRESS_MAX          ( 247 ) /*! Biggest possible slave address. */

typedef enum _mb_commands_enum 
{
    MB_FUNC_NONE                        = (  0 ),
    MB_FUNC_READ_COILS                  = (  1 ),
    MB_FUNC_READ_DISCRETE_INPUTS        = (  2 ),
    MB_FUNC_WRITE_SINGLE_COIL           = (  5 ),
    MB_FUNC_WRITE_MULTIPLE_COILS        = ( 15 ),
    MB_FUNC_READ_HOLDING_REGISTER       = (  3 ),
    MB_FUNC_READ_INPUT_REGISTER         = (  4 ),
    MB_FUNC_WRITE_REGISTER              = (  6 ),
    MB_FUNC_WRITE_MULTIPLE_REGISTERS    = ( 16 ),
    MB_FUNC_READWRITE_MULTIPLE_REGISTERS= ( 23 ),
    MB_FUNC_DIAG_READ_EXCEPTION         = (  7 ),
    MB_FUNC_DIAG_DIAGNOSTIC             = (  8 ),
    MB_FUNC_DIAG_GET_COM_EVENT_CNT      = ( 11 ),
    MB_FUNC_DIAG_GET_COM_EVENT_LOG      = ( 12 ),
    MB_FUNC_OTHER_REPORT_SLAVEID        = ( 17 ),
    MB_FUNC_ERROR                       = ( 0x80 )
} mb_commands_t;

/* ----------------------- Type definitions ---------------------------------*/

typedef struct
{
    uint8_t func_code;
    mb_fn_handler_fp handler;
} mb_fn_handler_t;

#ifdef __cplusplus
}
#endif
