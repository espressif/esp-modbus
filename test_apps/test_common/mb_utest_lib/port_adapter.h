/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
#pragma once

#include <sdkconfig.h>
#include "esp_log.h"
#include "mb_common.h"
#include <sys/queue.h>

#include "port_tcp_utils.h"
#include "port_common.h"

typedef enum
{
    MB_QUEUE_FLAG_EMPTY = 0x0000,
    MB_QUEUE_FLAG_SENT = 0x0001,
    MB_QUEUE_FLAG_RECV = 0x0002,
    MB_QUEUE_FLAG_CONNECTED = 0x0004
} mb_queue_flags_t;

#define MB_QUEUE_FLAGS (MB_QUEUE_FLAG_SENT | MB_QUEUE_FLAG_RECV | MB_QUEUE_FLAG_CONNECTED)

typedef struct _uid_info mb_uid_info_t;

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)
mb_err_enum_t mb_port_adapter_ser_create(mb_serial_opts_t *ser_opts, mb_port_base_t **in_out_obj);
#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)
mb_err_enum_t mb_port_adapter_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **in_out_obj);
#endif

void mb_port_adapter_delete(mb_port_base_t *inst);
void mb_port_adapter_set_response_time(mb_port_base_t *inst, uint64_t resp_time);
int mb_port_adapter_get_rx_buffer(mb_port_base_t *inst, uint8_t **ppfame, int *plength);

bool mb_port_adapter_send_data(mb_port_base_t *inst, uint8_t address, uint8_t *pframe, uint16_t length);
bool mb_port_adapter_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength);
void mb_port_adapter_enable(mb_port_base_t *inst);
void mb_port_adapter_disable(mb_port_base_t *inst);
void mb_port_adapter_tcp_set_conn_cb(mb_port_base_t *inst, void *conn_fp, void *arg);
void mb_port_adapter_tcp_set_conn_time(mb_port_base_t *inst, void *conn_fp, void *arg);
mb_uid_info_t *mb_port_adapter_get_slave_info(mb_port_base_t *inst, uint8_t slave_addr, mb_sock_state_t exp_state);
