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

mb_err_enum_t mbm_rq_read_inp_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_num, uint32_t tout);
mb_err_enum_t mbm_rq_write_holding_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_data, uint32_t tout);
mb_err_enum_t mbm_rq_write_multi_holding_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_wr_addr, uint16_t *data_ptr, uint32_t tout);
mb_err_enum_t mbm_rq_read_holding_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t reg_addr, uint16_t reg_num, uint32_t tout);
mb_err_enum_t mbm_rq_rw_multi_holding_reg(mb_base_t *inst, uint8_t snd_addr, uint16_t rd_reg_addr, 
                                            uint16_t rd_reg_num, uint16_t *data_ptr, uint16_t wr_reg_addr, uint16_t wr_reg_num, uint32_t tout);
mb_err_enum_t mbm_rq_read_discrete_inputs(mb_base_t *inst, uint8_t snd_addr, uint16_t discrete_addr, uint16_t discrete_num, uint32_t tout);
mb_err_enum_t mbm_rq_read_coils(mb_base_t *inst, uint8_t snd_addr, uint16_t coil_addr, uint16_t coil_num, uint32_t tout);
mb_err_enum_t mbm_rq_write_coil(mb_base_t *inst, uint8_t snd_addr, uint16_t coil_addr, uint16_t coil_data, uint32_t tout);
mb_err_enum_t mbm_rq_write_multi_coils(mb_base_t *inst, uint8_t snd_addr, uint16_t coil_addr, uint16_t coil_num, uint8_t *data_ptr, uint32_t tout);

#if MB_FUNC_OTHER_REP_SLAVEID_BUF
mb_exception_t mb_fn_report_slv_id(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#if MB_FUNC_READ_INPUT_ENABLED
mb_exception_t mbs_fn_read_input_reg(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#if MB_FUNC_READ_HOLDING_ENABLED
mb_exception_t mbs_fn_read_holding_reg(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#if MB_FUNC_WRITE_HOLDING_ENABLED
mb_exception_t mbs_fn_write_holding_reg(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_WRITE_MULTIPLE_HOLDING_ENABLED
mb_exception_t mbs_fn_write_multi_holding_reg(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_READ_COILS_ENABLED
mb_exception_t mbs_fn_read_coils(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#if MB_FUNC_WRITE_COIL_ENABLED
mb_exception_t mbs_fn_write_coil(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_WRITE_MULTIPLE_COILS_ENABLED
mb_exception_t mbs_fn_write_multi_coils(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_READ_DISCRETE_INPUTS_ENABLED
mb_exception_t mbs_fn_read_discrete_inp(mb_base_t *inst, uint8_t *frame_ptr, uint16_t *len_buf);
#endif

#if MB_FUNC_READWRITE_HOLDING_ENABLED
mb_exception_t mbs_fn_rw_multi_holding_reg(mb_base_t *inst, uint8_t *frame_ptr,uint16_t *len_buf);
#endif

#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

typedef struct port_tcp_opts_s mb_tcp_opts_t;

mb_err_enum_t mbs_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);

mb_err_enum_t mbs_delete(mb_base_t *inst);
mb_err_enum_t mbs_enable(mb_base_t *inst);
mb_err_enum_t mbs_disable(mb_base_t *inst);
mb_err_enum_t mbs_poll(mb_base_t *inst);
mb_err_enum_t mbs_set_slv_id(mb_base_t *inst, uint8_t slv_id, bool is_running, uint8_t const *slv_idstr, uint16_t slv_idstr_len);

mb_err_enum_t mbm_tcp_create(mb_tcp_opts_t *tcp_opts, void **in_out_obj);
mb_uid_info_t *mbm_port_tcp_get_slave_info(mb_port_base_t *inst, uint8_t slave_addr, mb_sock_state_t exp_state);

#endif

mb_err_enum_t mbm_delete(mb_base_t *inst);
mb_err_enum_t mbm_enable(mb_base_t *inst);
mb_err_enum_t mbm_disable(mb_base_t *inst);
mb_err_enum_t mbm_poll(mb_base_t *inst);

#ifdef __cplusplus
}
#endif