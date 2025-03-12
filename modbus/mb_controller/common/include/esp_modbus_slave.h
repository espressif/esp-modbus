/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

// Public interface header for slave
#include <stdint.h>                 // for standard int types definition
#include <stddef.h>                 // for NULL and std defines
#include "soc/soc.h"                // for BITN definitions
#include "freertos/FreeRTOS.h"      // for task creation and queues access
#include "freertos/event_groups.h"  // for event groups
#include "esp_modbus_common.h"      // for common types

#ifdef __cplusplus
extern "C" {
#endif

#define REG_SIZE(type, nregs) ((type == MB_PARAM_INPUT) || (type == MB_PARAM_HOLDING)) ? (nregs >> 1) : (nregs << 3)

#define MB_SLAVE_ASSERT(con) do { \
        if (!(con)) { ESP_LOGE(TAG, "assert errno:%d, errno_str: !(%s)", errno, strerror(errno)); assert(0 && #con); } \
    } while (0)

#define MB_SLAVE_GET_IFACE(pctx) (__extension__( \
{ \
    MB_SLAVE_ASSERT((pctx)); \
    ((mbs_controller_iface_t*)pctx); \
} \
))

#define MB_SLAVE_GET_OPTS(pctx) (&MB_SLAVE_GET_IFACE(pctx)->opts)

#define MB_SLAVE_IS_ACTIVE(pctx) ((bool)(MB_SLAVE_GET_IFACE(pctx)->is_active))

#define MB_SLAVE_GET_IFACE_FROM_BASE(pinst) (__extension__( \
{ \
    MB_SLAVE_ASSERT(pinst); \
    mb_base_t *pbase = (mb_base_t*)pinst; \
    MB_RETURN_ON_FALSE(pbase->descr.parent, MB_EILLSTATE, TAG, "Slave interface is not correctly initialized."); \
    ((mbs_controller_iface_t*)pbase->descr.parent); \
} \
))

/**
 * @brief Parameter access event information type
 */
typedef struct {
    uint32_t time_stamp;                    /*!< Timestamp of Modbus Event (uS)*/
    uint16_t mb_offset;                     /*!< Modbus register offset */
    mb_event_group_t type;                  /*!< Modbus event type */
    uint8_t *address;                       /*!< Modbus data storage address */
    size_t size;                            /*!< Modbus event register size (number of registers)*/
} mb_param_info_t;

/**
 * @brief Area access type modificator
 */
typedef enum {
    MB_ACCESS_RW = 0x0000,
    MB_ACCESS_RO = 0x0001,
    MB_ACCESS_WO = 0x0002
} mb_param_access_t;

/**
 * @brief Parameter storage area descriptor
 */
typedef struct {
    uint16_t start_offset;                  /*!< Modbus start address for area descriptor */
    mb_param_type_t type;                   /*!< Type of storage area descriptor */
    mb_param_access_t access;               /*!< Area access type */
    void *address;                          /*!< Instance address for storage area descriptor */
    size_t size;                            /*!< Instance size for area descriptor (bytes) */
} mb_register_area_descriptor_t;

/**
 * @brief Initialize Modbus Slave controller and stack for TCP port
 *
 * @param[out] ctx context pointer of the initialized modbus interface
 * @param[in] config - pointer to configuration structure for the slave
 * 
 * @return
 *     - ESP_OK                 Success
 *     - ESP_ERR_NO_MEM         Parameter error
 *     - ESP_ERR_NOT_SUPPORTED  Port type not supported
 *     - ESP_ERR_INVALID_STATE  Initialization failure
 */
esp_err_t mbc_slave_create_tcp(mb_communication_info_t *config, void **ctx);

/**
 * @brief Initialize Modbus Slave controller and stack for Serial port
 *
 * @param[out] ctx context pointer of the initialized modbus interface
 * @param[in] config - pointer to configuration structure for the slave
 * 
 * @return
 *     - ESP_OK                 Success
 *     - ESP_ERR_NO_MEM         Parameter error
 *     - ESP_ERR_NOT_SUPPORTED  Port type not supported
 *     - ESP_ERR_INVALID_STATE  Initialization failure
 */
esp_err_t mbc_slave_create_serial(mb_communication_info_t *config, void **ctx);

/**
 * @brief Initialize Modbus Slave controller interface handle
 *
 * @param[in] ctx - pointer to slave interface data structure
 */
void mbc_slave_init_iface(void *ctx);

/**
 * @brief Deletes Modbus controller and stack engine
 *
 * @param[in] ctx context pointer of the initialized modbus interface
 *
 * @return
 *     - ESP_OK   Success
 *     - ESP_ERR_INVALID_STATE Parameter error
 */
esp_err_t mbc_slave_delete(void *ctx);

/**
 * @brief Critical section lock function for parameter access
 *
 * @param[in] ctx pointer to slave handle (modbus interface)
 * @return
 *     - ESP_OK                 Success
 *     - ESP_ERR_INVALID_STATE  Initialization failure
 */
esp_err_t mbc_slave_lock(void *ctx);

/**
 * @brief Critical section unlock for parameter access
 *
 * @param[in] ctx pointer to slave handle (modbus interface)
 * @return
 *     - ESP_OK                 Success
 *     - ESP_ERR_INVALID_STATE  Initialization failure
 */
esp_err_t mbc_slave_unlock(void *ctx);

/**
 * @brief Start of Modbus communication stack
 *
 * @param[in] ctx context pointer of the initialized modbus interface
 *
 * @return
 *     - ESP_OK   Success
 *     - ESP_ERR_INVALID_ARG Modbus stack start error
 */
esp_err_t mbc_slave_start(void *ctx);

/**
 * @brief Stop of Modbus communication stack
 *
 * @param[in] ctx context pointer of the initialized modbus interface
 *
 * @return
 *     - ESP_OK   Success
 *     - ESP_ERR_INVALID_ARG Modbus stack stop error
 */
esp_err_t mbc_slave_stop(void *ctx);

/**
 * @brief Wait for specific event on parameter change.
 *
 * @param[in] ctx context pointer of the initialized modbus interface
 * @param group Group event bit mask to wait for change
 *
 * @return
 *     - mb_event_group_t event bits triggered
 */
mb_event_group_t mbc_slave_check_event(void *ctx, mb_event_group_t group);

/**
 * @brief Get parameter information
 *
 * @param[in] ctx context pointer of the initialized modbus interface *
 * @param[out] reg_info parameter info structure
 * @param[in] timeout Timeout in milliseconds to read information from
 *                    parameter queue
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_ERR_TIMEOUT Can not get data from parameter queue
 *                       or queue overflow
 */
esp_err_t mbc_slave_get_param_info(void *ctx, mb_param_info_t *reg_info, uint32_t timeout);

/**
 * @brief Set Modbus area descriptor
 *
 * @param[in] ctx context pointer of the initialized modbus interface *
 * @param descr_data Modbus registers area descriptor structure
 *
 * @return
 *     - ESP_OK: The appropriate descriptor is set
 *     - ESP_ERR_INVALID_ARG: The argument is incorrect
 */
esp_err_t mbc_slave_set_descriptor(void *ctx, mb_register_area_descriptor_t descr_data);

// The support of <0x11 - Report Slave ID> command is intentionally included for TCP slave as well!
#if CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT
/**
 * @brief Set Modbus slave identificator
 *
 * @param[in] ctx context pointer of the initialized modbus interface
 * @param[in] uid - unit identifier (short slave address) for Modbus slave
 * @param[in] is_running - Modbus slave running status
 * @param[in] pdata - pointer to data buffer for extended context (vendor specific)
 * @param[in] data_len - length of data buffer (the length of the extended context)
 *
 * @return
 *     - ESP_OK: The appropriate identificator is set
 *     - ESP_ERR_INVALID_ARG: The argument is incorrect
 */
esp_err_t mbc_set_slave_id(void *ctx, uint8_t uid, bool is_running, uint8_t const *pdata, uint8_t data_len);

/*! \brief Get slave identificator from the modbus object.
 *
 * This function is used to get the Slave ID array for modbus object.
 *
 * \param ctx - context pointer of the initialized modbus interface
 * \param pdata - the pointer to store object ID array from the modbus object
 * \param[in/out] pdata_len - in: length of the allocated pdata array,
 *                            out: returns the actual length of object id.
 * returns the modbus error code = ESP_OK, if set correctly,
 *           ESP_ERR_INVALID_RESPONSE - if the object ID is not set,
 *           ESP_ERR_INVALID_STATE - no space to store object ID in the pdata buffer,
 *           or incorrect arguments are provided
 */
esp_err_t mbc_get_slave_id(void *ctx, uint8_t const *pdata, uint8_t *pdata_len);
#endif

/**
 * @brief Holding register read/write callback function
 *
 * @param[in] inst the pointer of the initialized modbus base
 * @param[in] reg_buffer input buffer of registers
 * @param[in] address - start address of register
 * @param[in] n_regs - number of registers
 * @param[in] mode - parameter access mode (MB_REG_READ, MB_REG_WRITE)
 *
 * @return
 *     - MB_ENOERR: Read write is successful
 *     - MB_ENOREG: The argument is incorrect
 */
mb_err_enum_t mbc_reg_holding_slave_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t address, uint16_t n_regs, mb_reg_mode_enum_t mode) __attribute__ ((weak));

/**
 * @brief Input register read/write callback function
 *
 * @param[in] inst the pointer of the initialized modbus base
 * @param[in] reg_buffer input buffer of registers
 * @param[in] address - start address of register
 * @param[in] n_regs - number of registers
 *
 * @return
 *     - MB_ENOERR: Read write is successful
 *     - MB_ENOREG: The argument is incorrect
 */
mb_err_enum_t mbc_reg_input_slave_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t address, uint16_t n_regs) __attribute__ ((weak));

/**
 * @brief Discrete register read/write callback function
 *
 * @param[in] inst the pointer of the initialized modbus base
 * @param[in] reg_buffer input buffer of registers
 * @param[in] address - start address of register
 * @param[in] n_discrete - number of discrete registers
 *
 * @return
 *     - MB_ENOERR: Read write is successful
 *     - MB_ENOREG: The argument is incorrect
 */
mb_err_enum_t mbc_reg_discrete_slave_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t address, uint16_t n_discrete) __attribute__ ((weak));

/**
 * @brief Coil register read/write callback function
 *
 * @param[in] inst the pointer of the initialized modbus base
 * @param[in] reg_buffer input buffer of registers
 * @param[in] address - start address of register
 * @param[in] n_coils - number of discrete registers
 * @param[in] mode - parameter access mode (MB_REG_READ, MB_REG_WRITE)
 *
 * @return
 *     - MB_ENOERR: Read write is successful
 *     - MB_ENOREG: The argument is incorrect
 */
mb_err_enum_t mbc_reg_coils_slave_cb(mb_base_t *inst, uint8_t *reg_buffer, uint16_t address, uint16_t n_coils, mb_reg_mode_enum_t mode) __attribute__ ((weak));

#ifdef __cplusplus
}
#endif
