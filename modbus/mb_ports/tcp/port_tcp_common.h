/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <string.h>
#include "mb_config.h"
#include "mb_common.h"
#include "sdkconfig.h" // for KConfig options

#ifdef __cplusplus
extern "C" {
#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

#define MB_TCP_PORT_MAX_CONN            (CONFIG_FMB_TCP_PORT_MAX_CONN)
#define MB_TCP_DEFAULT_PORT             (CONFIG_FMB_TCP_PORT_DEFAULT)
#define MB_FRAME_QUEUE_SZ               (20)
#define MB_TCP_CHECK_ALIVE_TOUT_MS      (20) // check alive timeout in mS
#define MB_RECONNECT_TIME_MS            (CONFIG_FMB_TCP_CONNECTION_TOUT_SEC * 1000UL)
#define MB_EVENT_SEND_RCV_TOUT_MS       (500)

#define MB_TCP_MBAP_GET_FIELD(buffer, field) ((uint16_t)((buffer[field] << 8U) | buffer[field + 1]))
#define MB_TCP_MBAP_SET_FIELD(buffer, field, val) { \
    buffer[(field)] = (uint8_t)((val) >> 8U);       \
    buffer[(field) + 1] = (uint8_t)((val) & 0xFF);  \
}

#define MB_NODE_FMT(fmt) "node #%d, socket(#%d)(%s)" fmt

mb_err_enum_t mbm_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **port_obj);
void mbm_port_tcp_delete(mb_port_base_t *inst);
void mbm_port_tcp_enable(mb_port_base_t *inst);
void mbm_port_tcp_disable(mb_port_base_t *inst);
bool mbm_port_tcp_send_data(mb_port_base_t *inst, uint8_t address, uint8_t *pframe, uint16_t length);
bool mbm_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength);
bool mbm_port_tcp_add_slave_info(mb_port_base_t *inst, const uint16_t index, const char *ip_str, uint8_t uid);

mb_err_enum_t mbs_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **port_obj);
void mbs_port_tcp_delete(mb_port_base_t *inst);
void mbs_port_tcp_enable(mb_port_base_t *inst);
void mbs_port_tcp_disable(mb_port_base_t *inst);
bool mbs_port_tcp_send_data(mb_port_base_t *inst, uint8_t *pframe, uint16_t length);
bool mbs_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength);

#endif

#ifdef __cplusplus
}
#endif