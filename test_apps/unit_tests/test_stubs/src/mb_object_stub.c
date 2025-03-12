/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mb_config.h"
#include "mb_common.h"
#include "mb_proto.h"
#include "mb_func.h"
#include "mb_master.h"
#include "transport_common.h"
#include "port_common.h"
#include "ascii_transport.h"
#include "rtu_transport.h"
#include "tcp_transport.h"

static const char *TAG = "mb_object.master.stub";

#if (MB_MASTER_ASCII_ENABLED || MB_MASTER_RTU_ENABLED || MB_MASTER_TCP_ENABLED)

typedef struct
{
    mb_base_t base;
    uint16_t pdu_snd_len;
    uint8_t dst_addr;
    uint8_t snd_buf[MB_BUFFER_SIZE];
} mb_object_t;


mb_err_enum_t mb_delete(mb_base_t *inst);
mb_err_enum_t mb_enable(mb_base_t *inst);
mb_err_enum_t mb_disable(mb_base_t *inst);
mb_err_enum_t mb_poll(mb_base_t *inst);

static void mb_set_pdu_send_length(mb_base_t *inst, uint16_t length);
static uint16_t mb_get_pdu_send_length(mb_base_t *inst);
static void mb_set_dest_addr(mb_base_t *inst, uint8_t dest_addr);
static uint8_t mb_get_dest_addr(mb_base_t *inst);
static void mb_get_pdu_send_buf(mb_base_t *inst, uint8_t **pbuf);

//mb_err_enum_t mb_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

mb_err_enum_t mb_stub_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj)
{
    MB_RETURN_ON_FALSE((tcp_opts && in_out_obj), MB_EINVAL, TAG, "invalid options for the instance.");
    mb_err_enum_t ret = MB_ENOERR;
    mb_object_t *mb_obj = NULL;
    mb_obj = (mb_object_t *)calloc(1, sizeof(mb_object_t));
    MB_GOTO_ON_FALSE((mb_obj), MB_EILLSTATE, error, TAG, "no mem for mb master instance.");
    CRITICAL_SECTION_INIT(mb_obj->base.lock);
    ESP_LOGW(TAG, "Create fake mb_base object.");
    mb_obj->base.delete = mb_delete;
    mb_obj->base.enable = mb_enable;
    mb_obj->base.disable = mb_disable;
    mb_obj->base.poll = mb_poll;
    mb_obj->base.set_dest_addr = mb_set_dest_addr;
    mb_obj->base.get_dest_addr = mb_get_dest_addr;
    mb_obj->base.set_send_len = mb_set_pdu_send_length;
    mb_obj->base.get_send_len = mb_get_pdu_send_length;
    mb_obj->base.get_send_buf = mb_get_pdu_send_buf;
    mb_obj->base.descr.parent = *in_out_obj;
    mb_obj->base.descr.is_master = true;
    mb_obj->base.descr.obj_name = (char *)TAG;
    mb_obj->base.descr.inst_index = mb_port_get_inst_counter_inc();
    *in_out_obj = (void *)mb_obj;
    return MB_ENOERR;

error:
    CRITICAL_SECTION_CLOSE(mb_obj->base.lock);
    free(mb_obj);
    mb_port_get_inst_counter_dec();
    ESP_LOGW(TAG, "Delete fake mb_base object.");
    return ret;
}
#endif

#if (MB_MASTER_ASCII_ENABLED || MB_MASTER_RTU_ENABLED) 

typedef struct port_serial_opts_s mb_serial_opts_t;

mb_err_enum_t mb_stub_serial_create(mb_serial_opts_t *ser_opts, void **in_out_obj)
{
    MB_RETURN_ON_FALSE((ser_opts && in_out_obj), MB_EINVAL, TAG, "invalid options for the instance.");
    mb_err_enum_t ret = MB_ENOERR;
    mb_object_t *mb_obj = NULL;
    mb_obj = (mb_object_t *)calloc(1, sizeof(mb_object_t));
    MB_GOTO_ON_FALSE((mb_obj), MB_EILLSTATE, error, TAG, "no mem for mb master instance.");
    CRITICAL_SECTION_INIT(mb_obj->base.lock);
    ESP_LOGW(TAG, "Create fake mb_base object.");
    mb_obj->base.delete = mb_delete;
    mb_obj->base.enable = mb_enable;
    mb_obj->base.disable = mb_disable;
    mb_obj->base.poll = mb_poll;
    mb_obj->base.set_dest_addr = mb_set_dest_addr;
    mb_obj->base.get_dest_addr = mb_get_dest_addr;
    mb_obj->base.set_send_len = mb_set_pdu_send_length;
    mb_obj->base.get_send_len = mb_get_pdu_send_length;
    mb_obj->base.get_send_buf = mb_get_pdu_send_buf;
    mb_obj->base.descr.parent = *in_out_obj;
    mb_obj->base.descr.is_master = true;
    mb_obj->base.descr.obj_name = (char *)TAG;
    mb_obj->base.descr.inst_index = mb_port_get_inst_counter_inc();
    *in_out_obj = (void *)mb_obj;
    return MB_ENOERR;

error:
    CRITICAL_SECTION_CLOSE(mb_obj->base.lock);
    free(mb_obj);
    mb_port_get_inst_counter_dec();
    ESP_LOGW(TAG, "Delete fake mb_base object.");
    return ret;
}

#endif

mb_err_enum_t mb_delete(mb_base_t *inst)
{
    mb_object_t *mb_obj = __containerof(inst, mb_object_t, base);
    CRITICAL_SECTION_CLOSE(mb_obj->base.lock);
    free(mb_obj);
    mb_port_get_inst_counter_dec();
    ESP_LOGW(TAG, "Delete fake mb_base object.");
    return MB_ENOERR;
}

mb_err_enum_t mb_enable(mb_base_t *inst)
{
    ESP_LOGW(TAG, "Enable fake mb_base object.");
    mb_err_enum_t status = MB_ENOERR;
    return status;
}

mb_err_enum_t mb_disable(mb_base_t *inst)
{
    mb_err_enum_t status = MB_ENOERR;
    ESP_LOGW(TAG, "Disable fake mb_base object.");
    return status;
}

static void mb_get_pdu_send_buf(mb_base_t *inst, uint8_t **pbuf)
{
    mb_object_t *mb_obj = __containerof(inst, mb_object_t, base);
    if (pbuf) {
        *pbuf = mb_obj->snd_buf;
    }
}

// __attribute__((unused))
// static void mb_get_pdu_recv_buf(mb_base_t *inst, uint8_t **pbuf)
// {
//     //mb_object_t *mb_obj = __containerof(inst, mb_object_t, base);
// }

static void mb_set_pdu_send_length(mb_base_t *inst, uint16_t length)
{
    mb_object_t *mb_obj = __containerof(inst, mb_object_t, base);
    mb_obj->pdu_snd_len = length;
}

__attribute__((unused))
static uint16_t mb_get_pdu_send_length(mb_base_t *inst)
{
    mb_object_t *mb_obj = __containerof(inst, mb_object_t, base);
    return mb_obj->pdu_snd_len;
}

static void mb_set_dest_addr(mb_base_t *inst, uint8_t dest_addr)
{
    mb_object_t *mb_obj = __containerof(inst, mb_object_t, base);
    mb_obj->dst_addr = dest_addr;
}

static uint8_t mb_get_dest_addr(mb_base_t *inst)
{
    mb_object_t *mb_obj = __containerof(inst, mb_object_t, base);
    return mb_obj->dst_addr;
}

mb_err_enum_t mb_poll(mb_base_t *inst)
{
    mb_err_enum_t status = MB_ENOERR;
    ESP_LOGW(TAG, "Poll function called of fake mb_base object.");
    vTaskDelay(1);
    return status;
}

#endif
