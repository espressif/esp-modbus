/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <string.h>

#include "mb_config.h"
#include "mb_types.h"
#include "mb_frame.h"
#include "mb_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum _mb_comm_mode mb_mode_type_t;
typedef struct mb_port_base_t mb_port_base_t;

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

mb_err_enum_t mb_port_ser_create(mb_serial_opts_t *ser_opts, mb_port_base_t **port_obj);
bool mb_port_ser_recv_data(mb_port_base_t *inst, uint8_t **pp_ser_frame, uint16_t *p_ser_length);
bool mb_port_ser_send_data(mb_port_base_t *inst, uint8_t *p_ser_frame, uint16_t ser_length);
void mb_port_ser_enable(mb_port_base_t *inst);
void mb_port_ser_disable(mb_port_base_t *inst);
void mb_port_ser_delete(mb_port_base_t *inst);

#endif

#ifdef __cplusplus
}
#endif
