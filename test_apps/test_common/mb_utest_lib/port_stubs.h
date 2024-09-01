/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "esp_log.h"
#include "mb_common.h"
#include "mb_port_types.h"
#include "sdkconfig.h"

// Serial port function wrappers

bool __wrap_mb_port_event_get(mb_port_base_t *inst, mb_event_t *pevent);
bool __wrap_mb_port_event_post(mb_port_base_t *inst, mb_event_t event);
extern bool __real_mb_port_event_get(mb_port_base_t *inst, mb_event_t *pevent);
extern bool __real_mb_port_event_post(mb_port_base_t *inst, mb_event_t event);

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

extern void __real_mb_port_ser_enable(mb_port_base_t *inst);
extern void __real_mb_port_ser_disable(mb_port_base_t *inst);
extern bool __real_mb_port_ser_send_data(mb_port_base_t *inst, uint8_t *p_ser_frame, uint16_t ser_length);
extern bool __real_mb_port_ser_recv_data(mb_port_base_t *inst, uint8_t **pp_ser_frame, uint16_t *p_ser_length);
extern void __real_mb_port_ser_delete(mb_port_base_t *inst);

mb_err_enum_t __wrap_mb_port_ser_create(mb_serial_opts_t *ser_opts, mb_port_base_t **in_out_obj);
void __wrap_mb_port_ser_enable(mb_port_base_t *inst);
void __wrap_mb_port_ser_disable(mb_port_base_t *inst);
bool __wrap_mb_port_ser_send_data(mb_port_base_t *inst, uint8_t *p_ser_frame, uint16_t ser_length);
bool __wrap_mb_port_ser_recv_data(mb_port_base_t *inst, uint8_t **pp_ser_frame, uint16_t *p_ser_length);
void __wrap_mb_port_ser_delete(mb_port_base_t *inst);

#endif

// TCP port function wrappers

mb_err_enum_t __wrap_mbm_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **in_out_obj);
void __wrap_mbm_port_tcp_delete(mb_port_base_t *inst);

bool __wrap_mbm_port_tcp_send_data(mb_port_base_t *inst, uint8_t address, uint8_t *pframe, uint16_t length);
bool __wrap_mbm_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength);
void __wrap_mbm_port_tcp_enable(mb_port_base_t *inst);
void __wrap_mbm_port_tcp_disable(mb_port_base_t *inst);
void __wrap_mbm_port_tcp_set_conn_cb(mb_port_base_t *inst, void *conn_fp, void *arg);
mb_uid_info_t *__wrap_mbm_port_tcp_get_slave_info(mb_port_base_t *inst, uint8_t uid, mb_sock_state_t exp_state);
//bool __wrap_mbm_port__expired(void *inst);

extern void __real_mbm_port_tcp_enable(mb_port_base_t *inst);
extern void __real_mbm_port_tcp_disable(mb_port_base_t *inst);
extern void __real_mbm_port_tcp_set_conn_cb(mb_port_base_t *inst, void *conn_fp, void *arg);
extern mb_uid_info_t *__real_mbm_port_tcp_get_slave_info(mb_port_base_t *inst, uint8_t uid, mb_sock_state_t exp_state);
extern bool __real_mbm_port_tcp_send_data(mb_port_base_t *inst, uint8_t address, uint8_t *pframe, uint16_t length);
extern bool __real_mbm_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength);

mb_err_enum_t __wrap_mbs_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **in_out_obj);
void __wrap_mbs_port_tcp_delete(mb_port_base_t *inst);
bool __wrap_mbs_port_tcp_send_data(mb_port_base_t *inst, uint8_t *pframe, uint16_t length);
bool __wrap_mbs_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength);
void __wrap_mbs_port_tcp_enable(mb_port_base_t *inst);
void __wrap_mbs_port_tcp_disable(mb_port_base_t *inst);

mb_err_enum_t __real_mbs_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **in_out_obj);
extern void __real_mbs_port_tcp_delete(mb_port_base_t *inst);
extern bool __real_mbs_port_tcp_send_data(mb_port_base_t *inst, uint8_t *pframe, uint16_t length);
extern bool __real_mbs_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength);
extern void __real_mbs_port_tcp_enable(mb_port_base_t *inst);
extern void __real_mbs_port_tcp_disable(mb_port_base_t *inst);