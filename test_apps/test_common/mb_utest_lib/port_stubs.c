/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include "esp_timer.h"
#include "esp_log.h"
#include "esp_err.h"

#include "mb_common.h"
#include "esp_modbus_common.h"
#include "mbc_slave.h"

#include "mb_common.h"
#include "port_common.h"
#include "mb_config.h"
#include "port_serial_common.h"
#include "port_tcp_common.h"
#include "port_adapter.h"
#include "port_stubs.h"

#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

static __attribute__((unused)) const char *TAG = "port_stub";

#if (CONFIG_MB_PORT_ADAPTER_EN)

// The workaround to statically link whole test library
__attribute__((unused)) bool mb_test_include_stub_impl = true;

// Below are function wrappers to substitute actual port object with the adapter object for test purpose

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

mb_err_enum_t __wrap_mb_port_ser_create(mb_serial_opts_t *ser_opts, mb_port_base_t **in_out_obj)
{
    return mb_port_adapter_ser_create(ser_opts, in_out_obj);
}

void __wrap_mb_port_ser_delete(mb_port_base_t *inst)
{
    mb_port_adapter_delete(inst);
}

bool __wrap_mb_port_ser_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength)
{
    return mb_port_adapter_recv_data(inst, ppframe, plength);
}

bool __wrap_mb_port_ser_send_data(mb_port_base_t *inst, uint8_t *pframe, uint16_t length)
{
    return mb_port_adapter_send_data(inst, 0, pframe, length);
}

void __wrap_mb_port_ser_enable(mb_port_base_t *inst)
{
    mb_port_adapter_enable(inst);
}

void __wrap_mb_port_ser_disable(mb_port_base_t *inst)
{
    mb_port_adapter_disable(inst);
}

#endif

IRAM_ATTR
bool __wrap_mb_port_event_get(mb_port_base_t *inst, mb_event_t *pevent)
{
    bool result = __real_mb_port_event_get(inst, pevent);
    ESP_LOGD(TAG, "%s, get event:%x.", inst->descr.parent_name, pevent->event);
    return result;
}

IRAM_ATTR
bool __wrap_mb_port_event_post(mb_port_base_t *inst, mb_event_t event)
{
    bool result = __real_mb_port_event_post(inst, event);
    return result;
}

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

// Below are the TCP port function wrappers to exchange the port layer to TCP adapter
mb_err_enum_t __wrap_mbm_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **in_out_obj)
{
    ESP_LOGD(TAG, "master tcp adapter installed.");
    return mb_port_adapter_tcp_create(tcp_opts, in_out_obj);
}

bool __wrap_mbm_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength)
{
    return mb_port_adapter_recv_data(inst, ppframe, plength);
}

bool __wrap_mbm_port_tcp_send_data(mb_port_base_t *inst, uint8_t address, uint8_t *pframe, uint16_t length)
{
    return mb_port_adapter_send_data(inst, address, pframe, length);
}

void __wrap_mbm_port_tcp_delete(mb_port_base_t *inst)
{
    mb_port_adapter_delete(inst);
}

void __wrap_mbm_port_tcp_enable(mb_port_base_t *inst)
{
    ESP_LOGD(TAG, "adapter master tcp enable port.");
}

void __wrap_mbm_port_tcp_disable(mb_port_base_t *inst)
{
    ESP_LOGD(TAG, "adapter master tcp disable port.");
}

void __wrap_mbm_port_tcp_set_conn_cb(mb_port_base_t *inst, void *conn_fp, void *arg)
{
    ESP_LOGD(TAG, "adapter set connection callback.");
    mb_port_adapter_tcp_set_conn_cb(inst, conn_fp, arg);
}

mb_uid_info_t *__wrap_mbm_port_tcp_get_slave_info(mb_port_base_t *inst, uint8_t slave_addr, mb_sock_state_t exp_state)
{
    ESP_LOGD(TAG, "adapter get slave #%d info.", slave_addr);
    return mb_port_adapter_get_slave_info(inst, slave_addr, exp_state);
}

// Wrappers for modbus slave tcp

mb_err_enum_t __wrap_mbs_port_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **in_out_obj)
{
    ESP_LOGD(TAG, "install slave tcp adapter.");
    return mb_port_adapter_tcp_create(tcp_opts, in_out_obj);
}

bool __wrap_mbs_port_tcp_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength)
{
    return mb_port_adapter_recv_data(inst, ppframe, plength);
}

bool __wrap_mbs_port_tcp_send_data(mb_port_base_t *inst, uint8_t *pframe, uint16_t length)
{
    return mb_port_adapter_send_data(inst, 0, pframe, length);
}

void __wrap_mbs_port_tcp_delete(mb_port_base_t *inst)
{
    mb_port_adapter_delete(inst);
}

void __wrap_mbs_port_tcp_enable(mb_port_base_t *inst)
{
    ESP_LOGD(TAG, "adapter slave tcp enable port.");
}

void __wrap_mbs_port_tcp_disable(mb_port_base_t *inst)
{
    ESP_LOGD(TAG, "adapter slave tcp disable port.");
}

#endif

#endif // CONFIG_MB_PORT_ADAPTER_EN

#ifdef __cplusplus
}
#endif