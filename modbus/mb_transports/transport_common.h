/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "mb_types.h"
#include "port_common.h"
#include "mb_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mb_trans_base_t mb_trans_base_t;  /*!< Type of moddus transport object */
typedef struct _obj_descr obj_descr_t;

typedef void (*mb_frm_start_fp)(mb_trans_base_t *transport);
typedef void (*mb_frm_stop_fp)(mb_trans_base_t *transport);
typedef mb_err_enum_t (*mb_frm_rcv_fp)(mb_trans_base_t *transport, uint8_t *rcv_addr_buf, uint8_t **frame_ptr_buf, uint16_t *len_buf);
typedef mb_err_enum_t (*mb_frm_snd_fp)(mb_trans_base_t *transport, uint8_t slv_addr, const uint8_t *frame_ptr, uint16_t len);
typedef void (*mb_get_rx_frm_fp) (mb_trans_base_t *transport, uint8_t **frame_ptr_buf);
typedef void (*mb_get_tx_frm_fp) (mb_trans_base_t *transport, uint8_t **frame_ptr_buf);
typedef bool (*mb_get_fp)(mb_trans_base_t *inst);

struct mb_trans_base_t
{
    obj_descr_t descr;

    _lock_t lock;
    mb_port_base_t *port_obj;

    mb_frm_start_fp frm_start;
    mb_frm_stop_fp frm_stop;
    mb_get_fp frm_delete;
    mb_frm_snd_fp frm_send;
    mb_frm_rcv_fp frm_rcv;
    mb_get_rx_frm_fp get_rx_frm;
    mb_get_rx_frm_fp get_tx_frm;
    mb_get_fp frm_is_bcast;
}; //!< Transport methods

#ifdef __cplusplus
}
#endif