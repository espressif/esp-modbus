/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdint.h>

#include "mb_config.h"
#include "mb_common.h"
#include "mb_port_types.h"

#include "sdkconfig.h"

/* Common definitions */

#ifdef __cplusplus
extern "C" {
#endif

#define MB_PDU_REQ_READ_ADDR_OFF                (MB_PDU_DATA_OFF + 0)
#define MB_PDU_REQ_READ_REGCNT_OFF              (MB_PDU_DATA_OFF + 2)
#define MB_PDU_REQ_READ_SIZE                    (4)
#define MB_PDU_FUNC_READ_REGCNT_MAX             (0x007D)
#define MB_PDU_FUNC_READ_BYTECNT_OFF            (MB_PDU_DATA_OFF + 0)
#define MB_PDU_FUNC_READ_VALUES_OFF             (MB_PDU_DATA_OFF + 1)
#define MB_PDU_FUNC_READ_SIZE_MIN               (1)

#define MB_PDU_REQ_WRITE_ADDR_OFF               (MB_PDU_DATA_OFF + 0)
#define MB_PDU_REQ_WRITE_VALUE_OFF              (MB_PDU_DATA_OFF + 2)
#define MB_PDU_REQ_WRITE_SIZE                   (4)
#define MB_PDU_FUNC_WRITE_ADDR_OFF              (MB_PDU_DATA_OFF + 0)
#define MB_PDU_FUNC_WRITE_VALUE_OFF             (MB_PDU_DATA_OFF + 2)
#define MB_PDU_FUNC_WRITE_SIZE                  (4)

#define MB_PDU_REQ_WRITE_MUL_ADDR_OFF           (MB_PDU_DATA_OFF + 0)
#define MB_PDU_REQ_WRITE_MUL_REGCNT_OFF         (MB_PDU_DATA_OFF + 2)
#define MB_PDU_REQ_WRITE_MUL_BYTECNT_OFF        (MB_PDU_DATA_OFF + 4)
#define MB_PDU_REQ_WRITE_MUL_VALUES_OFF         (MB_PDU_DATA_OFF + 5)
#define MB_PDU_REQ_WRITE_MUL_SIZE_MIN           (5)
#define MB_PDU_REQ_WRITE_MUL_REGCNT_MAX         (0x0078)
#define MB_PDU_FUNC_WRITE_MUL_ADDR_OFF          (MB_PDU_DATA_OFF + 0)
#define MB_PDU_FUNC_WRITE_MUL_REGCNT_OFF        (MB_PDU_DATA_OFF + 2)
#define MB_PDU_FUNC_WRITE_MUL_SIZE              (4)

#define MB_PDU_REQ_READWRITE_READ_ADDR_OFF      (MB_PDU_DATA_OFF + 0)
#define MB_PDU_REQ_READWRITE_READ_REGCNT_OFF    (MB_PDU_DATA_OFF + 2)
#define MB_PDU_REQ_READWRITE_WRITE_ADDR_OFF     (MB_PDU_DATA_OFF + 4)
#define MB_PDU_REQ_READWRITE_WRITE_REGCNT_OFF   (MB_PDU_DATA_OFF + 6)
#define MB_PDU_REQ_READWRITE_WRITE_BYTECNT_OFF  (MB_PDU_DATA_OFF + 8)
#define MB_PDU_REQ_READWRITE_WRITE_VALUES_OFF   (MB_PDU_DATA_OFF + 9)
#define MB_PDU_REQ_READWRITE_SIZE_MIN           (9)
#define MB_PDU_FUNC_READWRITE_READ_BYTECNT_OFF  (MB_PDU_DATA_OFF + 0)
#define MB_PDU_FUNC_READWRITE_READ_VALUES_OFF   (MB_PDU_DATA_OFF + 1)
#define MB_PDU_FUNC_READWRITE_SIZE_MIN          (1)

#define MB_PDU_REQ_READ_ADDR_OFF (MB_PDU_DATA_OFF + 0)
#define MB_PDU_REQ_READ_COILCNT_OFF (MB_PDU_DATA_OFF + 2)
#define MB_PDU_REQ_READ_SIZE (4)
#define MB_PDU_FUNC_READ_COILCNT_OFF (MB_PDU_DATA_OFF + 0)
#define MB_PDU_FUNC_READ_VALUES_OFF (MB_PDU_DATA_OFF + 1)
#define MB_PDU_FUNC_READ_SIZE_MIN (1)

#define MB_PDU_REQ_READ_ADDR_OFF            (MB_PDU_DATA_OFF + 0)
#define MB_PDU_REQ_READ_DISCCNT_OFF         (MB_PDU_DATA_OFF + 2)
#define MB_PDU_REQ_READ_SIZE                (4)
#define MB_PDU_FUNC_READ_DISCCNT_OFF        (MB_PDU_DATA_OFF + 0)
#define MB_PDU_FUNC_READ_VALUES_OFF         (MB_PDU_DATA_OFF + 1)
#define MB_PDU_FUNC_READ_SIZE_MIN           (1)
#define MB_PDU_REQ_WRITE_MUL_COILCNT_OFF    (MB_PDU_DATA_OFF + 2)

typedef struct mb_base_t mb_base_t;             /*!< Type of modbus object */
typedef struct mb_port_base_t mb_port_base_t;

bool mb_port_event_get(mb_port_base_t *inst, mb_event_t *event);
bool mb_port_event_post(mb_port_base_t *inst, mb_event_t event);
bool mb_port_event_res_take(mb_port_base_t *inst, uint32_t timeout);
void mb_port_event_res_release(mb_port_base_t *inst);
mb_err_enum_t mb_port_event_wait_req_finish(mb_port_base_t *inst);

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

typedef struct port_serial_opts_s mb_serial_opts_t;

mb_err_enum_t mbs_rtu_create(mb_serial_opts_t *ser_opts, void **in_out_obj);
mb_err_enum_t mbs_ascii_create(mb_serial_opts_t *ser_opts, void **in_out_obj);

mb_err_enum_t mbm_rtu_create(mb_serial_opts_t *ser_opts, void **in_out_obj);
mb_err_enum_t mbm_ascii_create(mb_serial_opts_t *ser_opts, void **in_out_obj);


#endif

mb_err_enum_t mbs_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);

mb_err_enum_t mbs_delete(mb_base_t *inst);
mb_err_enum_t mbs_enable(mb_base_t *inst);
mb_err_enum_t mbs_disable(mb_base_t *inst);
mb_err_enum_t mbs_poll(mb_base_t *inst);
mb_err_enum_t mbs_set_slv_id(mb_base_t *inst, uint8_t slv_id, bool is_running, uint8_t const *slv_idstr, uint16_t slv_idstr_len);

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

typedef struct port_tcp_opts_s mb_tcp_opts_t;

mb_err_enum_t mbm_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);

#endif

mb_err_enum_t mbm_delete(mb_base_t *inst);
mb_err_enum_t mbm_enable(mb_base_t *inst);
mb_err_enum_t mbm_disable(mb_base_t *inst);
mb_err_enum_t mbm_poll(mb_base_t *inst);

#ifdef __cplusplus
}
#endif