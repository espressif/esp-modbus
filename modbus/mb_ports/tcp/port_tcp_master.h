/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_event.h"          // for esp event loop

#include "mb_common.h"
#include "mb_frame.h"

#include "port_tcp_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

typedef enum _mb_sock_state mb_sock_state_t;
typedef struct _uid_info mb_uid_info_t;

void mbm_port_tcp_set_conn_cb(mb_port_base_t *inst, void *conn_fp, void *arg);
mb_uid_info_t *mbm_port_tcp_get_slave_info(mb_port_base_t *inst, uint8_t uid, mb_sock_state_t exp_state);

MB_EVENT_HANDLER(mbm_on_ready);
MB_EVENT_HANDLER(mbm_on_open);
MB_EVENT_HANDLER(mbm_on_resolve);
MB_EVENT_HANDLER(mbm_on_connect);
MB_EVENT_HANDLER(mbm_on_send_data);
MB_EVENT_HANDLER(mbm_on_recv_data);
MB_EVENT_HANDLER(mbm_on_error);
MB_EVENT_HANDLER(mbm_on_close);
MB_EVENT_HANDLER(mbm_on_timeout);

#endif

#ifdef __cplusplus
}
#endif
