/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "mb_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mb_base_t mb_base_t;  /*!< Type of modbus object */

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
mb_err_enum_t mbm_rq_custom(mb_base_t *inst, uint8_t uid, uint8_t fc, uint8_t *buf, uint16_t buf_size, uint32_t tout);

#if MB_FUNC_OTHER_REP_SLAVEID_ENABLED
mb_err_enum_t mbm_rq_report_slave_id(mb_base_t *inst, uint8_t slave_addr, uint32_t timeout);
mb_exception_t mbm_fn_report_slave_id(mb_base_t *inst, uint8_t * pframe, uint16_t *usLen);

/*! \ingroup modbus_registers
 * \brief The common callback function used to transfer common data as bytes from command buffer in little endian format.
 *
 * \param pdata A pointer to data in command buffer to be transferred.
 * \param address Unused for this function == 0.
 * \param bytes Number of bytes the callback function must supply.
 *
 * \return The function must return one of the following error codes:
 *   - mb_err_enum_t::MB_ENOERR If no error occurred. In this case a normal
 *       Modbus response is sent.
 *   - mb_err_enum_t::MB_ENOREG if can not map the data of the registers
 *   - mb_err_enum_t::MB_EILLSTATE if can not procceed with data transfer due to critical error
 *   - mb_err_enum_t::MB_EINVAL if value data can not be transferred
 */
mb_err_enum_t mbc_reg_common_cb(mb_base_t *inst, uint8_t *pdata, uint16_t address, uint16_t bytes);
#endif

// The function to register custom function handler for master
mb_err_enum_t mbm_set_handler(mb_base_t *inst, uint8_t func_code, mb_fn_handler_fp phandler);

// The helper function to get custom function handler for master
mb_err_enum_t mbm_get_handler(mb_base_t *inst, uint8_t func_code, mb_fn_handler_fp *phandler);

// The helper function to delete custom function handler for master
mb_err_enum_t mbm_delete_handler(mb_base_t *inst, uint8_t func_code);

// The helper function to get count of handlers for master
mb_err_enum_t mbm_get_handler_count(mb_base_t *inst, uint16_t *pcount);

#ifdef __cplusplus
}
#endif