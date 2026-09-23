/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "driver/uart.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_modbus_common.h"
#include "mbcontroller.h"
#include "mb_types.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "sdkconfig.h"

#if __has_include("esp_mac.h")
#include "esp_mac.h"
#endif

#define MB_TCP_PORT_NUMBER          (CONFIG_FMB_TCP_PORT_DEFAULT)
#define MB_PORT_NUM                 (CONFIG_MB_UART_PORT_NUM)
#define MB_DEV_SPEED                (CONFIG_MB_UART_BAUD_RATE)
#define MB_GATEWAY_TCP_UID          (CONFIG_MB_GATEWAY_TCP_UID)
#define MB_GATEWAY_MAX_REGS         (CONFIG_MB_GATEWAY_MAX_REGISTERS)
#define MB_GATEWAY_MAX_COILS_CFG    (CONFIG_MB_GATEWAY_MAX_COILS)
#define MB_GATEWAY_SERIAL_UID_MAX   (247)

#define MB_PDU_FUNC_OFF             (0)
#define MB_PDU_DATA_OFF             (1)
#define MB_PDU_ADDR_OFF             (1)
#define MB_PDU_QTY_OFF              (3)
#define MB_PDU_BYTE_COUNT_OFF       (5)
#define MB_PDU_VALUES_OFF           (6)
#define MB_PDU_RW_READ_START_OFF    (1)
#define MB_PDU_RW_READ_COUNT_OFF    (3)
#define MB_PDU_RW_WRITE_START_OFF   (5)
#define MB_PDU_RW_WRITE_COUNT_OFF   (7)
#define MB_PDU_RW_BYTE_COUNT_OFF    (9)

#define MB_PDU_READ_REQ_LEN         (5)
#define MB_PDU_WRITE_SINGLE_LEN     (5)
#define MB_PDU_WRITE_MULTI_MIN_LEN  (6)
#define MB_PDU_RW_MULTI_MIN_LEN     (10)

#define MB_MAX_READ_REGS            (125)
#define MB_MAX_WRITE_REGS           (123)
#define MB_MAX_RW_WRITE_REGS        (121)
#define MB_MAX_COILS                (2000)
#define MB_MAX_DISCRETE_INPUTS      (2000)
#define MB_MAX_READ_BYTES           ((MB_MAX_COILS + 7) / 8)
#define MB_MAX_CYCLE_TIMEOUT_MS     (CONFIG_MB_MAX_CYCLE_TIMEOUT_MS)

/**
 * @brief The function command entry type to keep supported handlers.
 *
 * `handler` it is the gateway's own handler that gets installed for `func_code`.
 * `saved_handler` is filled in at runtime by
 * install_gateway_handler() with handler was registered for
 * `func_code` before the override, so restore_gateway_handler() can put it
 * back (or remove the entry entirely if there was none).
 */
typedef struct mb_command_entry_s {
    uint8_t func_code;
    mb_fn_handler_fp handler;
    mb_fn_handler_fp saved_handler;
} mb_command_entry_t;

static const char *TAG = "MB_TCP2SERIAL_GATEWAY";
static void *tcp_slave_handle = NULL;
static void *serial_master_handle = NULL;

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
static SemaphoreHandle_t mb_service_semaphore = NULL; // is used for self test
#endif

static mb_exception_t forward_read_bits(void *inst, uint8_t *frame_ptr, uint16_t *len);
static mb_exception_t forward_read_registers(void *inst, uint8_t *frame_ptr, uint16_t *len);
static mb_exception_t forward_write_single(void *inst, uint8_t *frame_ptr, uint16_t *len);
static mb_exception_t forward_write_multiple_coils(void *inst, uint8_t *frame_ptr, uint16_t *len);
static mb_exception_t forward_write_multiple_registers(void *inst, uint8_t *frame_ptr, uint16_t *len);
static mb_exception_t forward_readwrite_multiple_registers(void *inst, uint8_t *frame_ptr, uint16_t *len);

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
static mb_exception_t unsupported_fc_test_handler(void *inst, uint8_t *frame_ptr, uint16_t *len);
#endif

// Each function code is forwarded straight to its own handler below
// The helper `mbc_set_handler()` is called once per entry with
// `handler`, so esp-modbus routes each function code directly to the
// matching forward_* function.
static mb_command_entry_t gateway_handlers[] = {
    { .func_code = MB_FUNC_READ_COILS, .handler = forward_read_bits },
    { .func_code = MB_FUNC_READ_DISCRETE_INPUTS, .handler = forward_read_bits },
    { .func_code = MB_FUNC_READ_HOLDING_REGISTER, .handler = forward_read_registers },
    { .func_code = MB_FUNC_READ_INPUT_REGISTER, .handler = forward_read_registers },
    { .func_code = MB_FUNC_WRITE_SINGLE_COIL, .handler = forward_write_single },
    { .func_code = MB_FUNC_WRITE_REGISTER, .handler = forward_write_single },
    { .func_code = MB_FUNC_WRITE_MULTIPLE_COILS, .handler = forward_write_multiple_coils },
    { .func_code = MB_FUNC_WRITE_MULTIPLE_REGISTERS, .handler = forward_write_multiple_registers },
    { .func_code = MB_FUNC_READWRITE_MULTIPLE_REGISTERS, .handler = forward_readwrite_multiple_registers },
#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
    // Test-only (CI): This unknown command handler just signals the main thread to complete the test.
    { .func_code = 0x41, .handler = unsupported_fc_test_handler },
#endif
};

static uint16_t byte_count_for_bits(uint16_t bit_count)
{
    return (uint16_t)((bit_count + 7) / 8);
}

static uint16_t gateway_get_u16_be(const uint8_t *buf, size_t offset)
{
    return (uint16_t)(((uint16_t)buf[offset] << 8U) | (uint16_t)buf[offset + 1]);
}

static void gateway_pdu_be_to_reg_buffer(uint8_t *dst, const uint8_t *src, uint16_t reg_count)
{
    /* The master register callback buffer is host-order byte layout. */
    for (uint16_t i = 0; i < reg_count; ++i) {
        dst[(i * 2) + 0] = src[(i * 2) + 1];
        dst[(i * 2) + 1] = src[(i * 2) + 0];
    }
}

static void gateway_reg_buffer_to_pdu_be(uint8_t *dst, const uint8_t *src, uint16_t reg_count)
{
    /* TCP response PDUs must carry register values in Modbus big-endian order. */
    for (uint16_t i = 0; i < reg_count; ++i) {
        dst[(i * 2) + 0] = src[(i * 2) + 1];
        dst[(i * 2) + 1] = src[(i * 2) + 0];
    }
}

static mb_exception_t esp_err_to_mb_exception(esp_err_t err)
{
    switch (err) {
    case ESP_OK:
        return MB_EX_NONE;
    case ESP_ERR_TIMEOUT:
    case ESP_ERR_NOT_FOUND:
        return MB_EX_GATEWAY_TGT_FAILED;
    case ESP_ERR_NOT_SUPPORTED:
        return MB_EX_ILLEGAL_FUNCTION;
    case ESP_ERR_INVALID_ARG:
        return MB_EX_ILLEGAL_DATA_VALUE;
    default:
        return MB_EX_GATEWAY_PATH_FAILED;
    }
}

static mb_exception_t get_downstream_uid(uint8_t *uid)
{
    esp_err_t err = mbc_slave_get_request_uid(tcp_slave_handle, uid);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get request UID: %s.", esp_err_to_name(err));
        return MB_EX_SLAVE_DEVICE_FAILURE;
    }
    if (*uid == 0 || *uid > MB_GATEWAY_SERIAL_UID_MAX) {
        ESP_LOGW(TAG, "Unsupported downstream UID %u.", (unsigned)*uid);
        return MB_EX_ILLEGAL_DATA_ADDRESS;
    }
    return MB_EX_NONE;
}

static mb_exception_t forward_read_registers(void *inst, uint8_t *frame_ptr, uint16_t *len)
{
    if (frame_ptr && len && *len != MB_PDU_READ_REQ_LEN) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t uid = 0;
    mb_exception_t exception = get_downstream_uid(&uid);
    if (exception != MB_EX_NONE) {
        return exception;
    }

    const uint8_t func_code = frame_ptr[MB_PDU_FUNC_OFF];
    const uint16_t reg_start = gateway_get_u16_be(frame_ptr, MB_PDU_ADDR_OFF);
    const uint16_t reg_count = gateway_get_u16_be(frame_ptr, MB_PDU_QTY_OFF);
    if (reg_count == 0 || reg_count > MB_MAX_READ_REGS || reg_count > MB_GATEWAY_MAX_REGS) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t response_data[MB_MAX_READ_REGS * 2] = {0};
    mb_param_request_t request = {
        .slave_addr = uid,
        .command = func_code,
        .reg_start = reg_start,
        .reg_size = reg_count,
    };

    esp_err_t err = mbc_master_send_request(serial_master_handle, &request, response_data);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%p, Forward read registers failed, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s.",
                 tcp_slave_handle, (unsigned)uid, func_code, reg_start, reg_count, esp_err_to_name(err));
        vTaskDelay(pdMS_TO_TICKS(CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND >> 1));
        return esp_err_to_mb_exception(err);
    }
    frame_ptr[MB_PDU_FUNC_OFF] = func_code;
    frame_ptr[MB_PDU_DATA_OFF] = (uint8_t)(reg_count * 2);
    ESP_LOGI(TAG, "%p, Forward read registers success, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s",
             tcp_slave_handle, request.slave_addr, (int)func_code, reg_start, reg_count, esp_err_to_name(err) );
    gateway_reg_buffer_to_pdu_be(&frame_ptr[MB_PDU_DATA_OFF + 1], response_data, reg_count);
    *len = (uint16_t)(2 + (reg_count * 2));
    return MB_EX_NONE;
}

static mb_exception_t forward_read_bits(void *inst, uint8_t *frame_ptr, uint16_t *len)
{
    if (frame_ptr && len && *len != MB_PDU_READ_REQ_LEN) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t uid = 0;
    mb_exception_t exception = get_downstream_uid(&uid);
    if (exception != MB_EX_NONE) {
        return exception;
    }

    const uint8_t func_code = frame_ptr[MB_PDU_FUNC_OFF];
    const uint16_t bit_start = gateway_get_u16_be(frame_ptr, MB_PDU_ADDR_OFF);
    const uint16_t bit_count = gateway_get_u16_be(frame_ptr, MB_PDU_QTY_OFF);
    const uint16_t max_bits = (func_code == MB_FUNC_READ_COILS) ? MB_MAX_COILS : MB_MAX_DISCRETE_INPUTS;
    if (bit_count == 0 || bit_count > max_bits || bit_count > MB_GATEWAY_MAX_COILS_CFG) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t response_data[MB_MAX_READ_BYTES] = {0};
    mb_param_request_t request = {
        .slave_addr = uid,
        .command = func_code,
        .reg_start = bit_start,
        .reg_size = bit_count,
    };

    esp_err_t err = mbc_master_send_request(serial_master_handle, &request, response_data);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%p, Forward read bits failed, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s.",
                 tcp_slave_handle, (unsigned)uid, func_code, bit_start, bit_count, esp_err_to_name(err));
        // Makes a "cooldown" timeout to repair from possible race condition after expired slave response
        vTaskDelay(pdMS_TO_TICKS(CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND >> 1));
        return esp_err_to_mb_exception(err);
    }

    const uint16_t byte_count = byte_count_for_bits(bit_count);
    frame_ptr[MB_PDU_FUNC_OFF] = func_code;
    frame_ptr[MB_PDU_DATA_OFF] = (uint8_t)byte_count;
    memcpy(&frame_ptr[MB_PDU_DATA_OFF + 1], response_data, byte_count);
    ESP_LOGI(TAG, "%p, Forward read bits success, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s",
             tcp_slave_handle, request.slave_addr, (int)func_code, bit_start, bit_count, esp_err_to_name(err) );
    *len = (uint16_t)(2 + byte_count);
    return MB_EX_NONE;
}

static mb_exception_t forward_write_single(void *inst, uint8_t *frame_ptr, uint16_t *len)
{
    if (frame_ptr && len && *len != MB_PDU_WRITE_SINGLE_LEN) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t uid = 0;
    mb_exception_t exception = get_downstream_uid(&uid);
    if (exception != MB_EX_NONE) {
        return exception;
    }

    const uint8_t func_code = frame_ptr[MB_PDU_FUNC_OFF];
    uint16_t value = gateway_get_u16_be(frame_ptr, MB_PDU_QTY_OFF);
    if ((func_code == MB_FUNC_WRITE_SINGLE_COIL) && (value != 0x0000) && (value != 0xFF00)) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }
    mb_param_request_t request = {
        .slave_addr = uid,
        .command = func_code,
        .reg_start = gateway_get_u16_be(frame_ptr, MB_PDU_ADDR_OFF),
        .reg_size = 1,
    };

    esp_err_t err = mbc_master_send_request(serial_master_handle, &request, &value);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%p, Forward single register write failed, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s.",
                 tcp_slave_handle, (unsigned)uid, func_code, request.reg_start, 1, esp_err_to_name(err));
        vTaskDelay(pdMS_TO_TICKS(CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND >> 1));
        return esp_err_to_mb_exception(err);
    }
    ESP_LOGI(TAG, "%p, Forward single register write success, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s",
             tcp_slave_handle, request.slave_addr, (int)func_code, request.reg_start, 1, esp_err_to_name(err) );
    *len = MB_PDU_WRITE_SINGLE_LEN;
    return MB_EX_NONE;
}

static mb_exception_t forward_write_multiple_coils(void *inst, uint8_t *frame_ptr, uint16_t *len)
{
    if (frame_ptr && len && *len < MB_PDU_WRITE_MULTI_MIN_LEN) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t uid = 0;
    mb_exception_t exception = get_downstream_uid(&uid);
    if (exception != MB_EX_NONE) {
        return exception;
    }

    const uint8_t func_code = frame_ptr[MB_PDU_FUNC_OFF];
    const uint16_t coil_count = gateway_get_u16_be(frame_ptr, MB_PDU_QTY_OFF);
    const uint8_t byte_count = frame_ptr[MB_PDU_BYTE_COUNT_OFF];
    if (coil_count == 0 || coil_count > MB_MAX_COILS || coil_count > MB_GATEWAY_MAX_COILS_CFG ||
            byte_count != byte_count_for_bits(coil_count) || *len != (uint16_t)(MB_PDU_WRITE_MULTI_MIN_LEN + byte_count)) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    mb_param_request_t request = {
        .slave_addr = uid,
        .command = MB_FUNC_WRITE_MULTIPLE_COILS,
        .reg_start = gateway_get_u16_be(frame_ptr, MB_PDU_ADDR_OFF),
        .reg_size = coil_count,
    };

    esp_err_t err = mbc_master_send_request(serial_master_handle, &request, &frame_ptr[MB_PDU_VALUES_OFF]);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%p, Forward multiple coils write failed, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s.",
                 tcp_slave_handle, (unsigned)uid, func_code, request.reg_start, request.reg_size, esp_err_to_name(err));
        vTaskDelay(pdMS_TO_TICKS(CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND >> 1));
        return esp_err_to_mb_exception(err);
    }
    ESP_LOGI(TAG, "%p, Forward multiple coils write success, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s",
             tcp_slave_handle, request.slave_addr, (int)func_code, request.reg_start, request.reg_size, esp_err_to_name(err) );
    *len = MB_PDU_WRITE_SINGLE_LEN;
    return MB_EX_NONE;
}

static mb_exception_t forward_write_multiple_registers(void *inst, uint8_t *frame_ptr, uint16_t *len)
{
    if (frame_ptr && len && *len < MB_PDU_WRITE_MULTI_MIN_LEN) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t uid = 0;
    mb_exception_t exception = get_downstream_uid(&uid);
    if (exception != MB_EX_NONE) {
        return exception;
    }

    const uint8_t func_code = frame_ptr[MB_PDU_FUNC_OFF];
    const uint16_t reg_count = gateway_get_u16_be(frame_ptr, MB_PDU_QTY_OFF);
    const uint8_t byte_count = frame_ptr[MB_PDU_BYTE_COUNT_OFF];
    if (reg_count == 0 || reg_count > MB_MAX_WRITE_REGS || reg_count > MB_GATEWAY_MAX_REGS ||
            byte_count != (uint8_t)(reg_count * 2) || *len != (uint16_t)(MB_PDU_WRITE_MULTI_MIN_LEN + byte_count)) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t register_data[MB_MAX_WRITE_REGS * 2] = {0};
    gateway_pdu_be_to_reg_buffer(register_data, &frame_ptr[MB_PDU_VALUES_OFF], reg_count);

    mb_param_request_t request = {
        .slave_addr = uid,
        .command = MB_FUNC_WRITE_MULTIPLE_REGISTERS,
        .reg_start = gateway_get_u16_be(frame_ptr, MB_PDU_ADDR_OFF),
        .reg_size = reg_count,
    };

    esp_err_t err = mbc_master_send_request(serial_master_handle, &request, register_data);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%p, Forward multiple registers write failed, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s.",
                 tcp_slave_handle, (unsigned)uid, func_code, request.reg_start, request.reg_size, esp_err_to_name(err));
        vTaskDelay(pdMS_TO_TICKS(CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND >> 1));
        return esp_err_to_mb_exception(err);
    }
    ESP_LOGI(TAG, "%p, Forward multiple registers write success, UID: %u, fc: 0x%02x, addr: %u, count: %u, %s",
             tcp_slave_handle, request.slave_addr, (int)func_code, request.reg_start, request.reg_size, esp_err_to_name(err) );
    *len = MB_PDU_WRITE_SINGLE_LEN;
    return MB_EX_NONE;
}

static mb_exception_t forward_readwrite_multiple_registers(void *inst, uint8_t *frame_ptr, uint16_t *len)
{
    if (frame_ptr && len && *len < MB_PDU_RW_MULTI_MIN_LEN) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t uid = 0;
    mb_exception_t exception = get_downstream_uid(&uid);
    if (exception != MB_EX_NONE) {
        return exception;
    }

    const uint16_t read_start = gateway_get_u16_be(frame_ptr, MB_PDU_RW_READ_START_OFF);
    const uint16_t read_count = gateway_get_u16_be(frame_ptr, MB_PDU_RW_READ_COUNT_OFF);
    const uint16_t write_start = gateway_get_u16_be(frame_ptr, MB_PDU_RW_WRITE_START_OFF);
    const uint16_t write_count = gateway_get_u16_be(frame_ptr, MB_PDU_RW_WRITE_COUNT_OFF);
    const uint8_t byte_count = frame_ptr[MB_PDU_RW_BYTE_COUNT_OFF];

    if (read_count == 0 || read_count > MB_MAX_READ_REGS || read_count > MB_GATEWAY_MAX_REGS ||
            write_count == 0 || write_count > MB_MAX_RW_WRITE_REGS || write_count > MB_GATEWAY_MAX_REGS ||
            byte_count != (uint8_t)(write_count * 2) || *len != (uint16_t)(MB_PDU_RW_MULTI_MIN_LEN + byte_count)) {
        return MB_EX_ILLEGAL_DATA_VALUE;
    }

    uint8_t register_data[MB_MAX_READ_REGS * 2] = {0};
    gateway_pdu_be_to_reg_buffer(register_data, &frame_ptr[MB_PDU_RW_MULTI_MIN_LEN], write_count);

    mb_param_request_t request = {
        .slave_addr = uid,
        .command = MB_FUNC_READWRITE_MULTIPLE_REGISTERS,
        .reg_start = read_start,
        .reg_size = read_count,
        .wr_rd_multi_reg_func = {
            .wr_reg_start = write_start,
            .wr_reg_size = write_count,
        },
    };

    esp_err_t err = mbc_master_send_request(serial_master_handle, &request, register_data);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%p, Forward registers read/write failed, uid=%u addr_rd=%u/%u, addr_wr=%u/%u, %s.",
                 tcp_slave_handle, (unsigned)uid, read_start, read_count, write_start, write_count, esp_err_to_name(err));
        vTaskDelay(pdMS_TO_TICKS(CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND >> 1));
        return esp_err_to_mb_exception(err);
    }

    frame_ptr[MB_PDU_FUNC_OFF] = MB_FUNC_READWRITE_MULTIPLE_REGISTERS;
    frame_ptr[MB_PDU_DATA_OFF] = (uint8_t)(read_count * 2);
    gateway_reg_buffer_to_pdu_be(&frame_ptr[MB_PDU_DATA_OFF + 1], register_data, read_count);
    ESP_LOGI(TAG, "%p, Forward registers read/write success, uid=%u addr_rd=%u/%u, addr_wr=%u/%u, %s.",
             tcp_slave_handle, (unsigned)uid, read_start, read_count, write_start, write_count, esp_err_to_name(err));
    *len = (uint16_t)(2 + (read_count * 2));
    return MB_EX_NONE;
}

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
// No real gateway function uses this function code (see gateway_handlers[]); it exists
// purely so the CI self-test has a request it can send to trigger a clean exit.
static mb_exception_t unsupported_fc_test_handler(void *inst, uint8_t *frame_ptr, uint16_t *len)
{
    const uint8_t func_code = (frame_ptr && len && *len) ? frame_ptr[MB_PDU_FUNC_OFF] : 0;
    ESP_LOGW(TAG, "Function %u is not supported, exit.", (unsigned)func_code);
    (void)xSemaphoreGive(mb_service_semaphore);
    return MB_EX_ILLEGAL_FUNCTION;
}
#endif

static esp_err_t install_gateway_handler(mb_command_entry_t *entry)
{
    if (!entry || !entry->func_code || entry->func_code >= MB_FUNC_ERROR || !entry->handler) {
        ESP_LOGE(TAG, "Incorrect function entry pointer.");
        return ESP_ERR_INVALID_ARG;
    }
    // Save standard handler registered for this function code
    // (if any) so restore_gateway_handler() can put it back later.
    esp_err_t err = mbc_get_handler(tcp_slave_handle, entry->func_code, &entry->saved_handler);
    if (err != ESP_OK) {
        entry->saved_handler = NULL;
    }
    err = mbc_set_handler(tcp_slave_handle, entry->func_code, entry->handler);
    ESP_RETURN_ON_ERROR(err, TAG, "Cannot set function handler (%u).", entry->func_code);
    ESP_LOGW(TAG, "Override the standard function (%u) handler %p with %p",
             entry->func_code, entry->saved_handler, entry->handler);
    return ESP_OK;
}

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
static esp_err_t restore_gateway_handler(mb_command_entry_t *entry)
{
    if (!entry || !entry->func_code || entry->func_code >= MB_FUNC_ERROR) {
        ESP_LOGE(TAG, "Incorrect function entry pointer.");
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err;
    if (entry->saved_handler) {
        err = mbc_set_handler(tcp_slave_handle, entry->func_code, entry->saved_handler);
    } else {
        // No handler was registered for this function code before,
        // so there is nothing to restore, just remove the gateway's own handler.
        err = mbc_delete_handler(tcp_slave_handle, entry->func_code);
    }
    ESP_RETURN_ON_ERROR(err, TAG, "Cannot restore function handler (%u).", entry->func_code);
    ESP_LOGW(TAG, "Restore the standard function (%u) handler %p with %p",
             entry->func_code, entry->handler, entry->saved_handler);
    return ESP_OK;
}
#endif

static esp_err_t init_services(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_RETURN_ON_ERROR(nvs_flash_erase(), TAG, "Erase NVS failed.");
        err = nvs_flash_init();
    }
    ESP_RETURN_ON_ERROR(err, TAG, "Init NVS failed.");
    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "init netif");
    ESP_RETURN_ON_ERROR(esp_event_loop_create_default(), TAG, "Create event loop failed.");
    ESP_RETURN_ON_ERROR(example_connect(), TAG, "Connect to network failed.");
#if CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_RETURN_ON_ERROR(esp_wifi_set_ps(WIFI_PS_NONE), TAG, "Disable Wi-Fi power save failed.");
#endif
    return ESP_OK;
}

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
static esp_err_t destroy_services(void)
{
    esp_err_t err = example_disconnect();
    ESP_RETURN_ON_ERROR(err, TAG,
                        "example_disconnect fail, returns(0x%x).", (int)err);
    err = esp_event_loop_delete_default();
    ESP_RETURN_ON_ERROR(err, TAG,
                        "esp_event_loop_delete_default fail, returns(0x%x).", (int)err);
    err = esp_netif_deinit();
    ESP_RETURN_ON_FALSE((err == ESP_OK || err == ESP_ERR_NOT_SUPPORTED), ESP_ERR_INVALID_STATE,
                        TAG, "esp_netif_deinit fail, returns(0x%x).", (int)err);
    err = nvs_flash_deinit();
    ESP_RETURN_ON_ERROR(err, TAG, "nvs_flash_deinit fail, returns(0x%x).", (int)err);
    return ESP_OK;
}
#endif

static esp_err_t init_serial_master(void)
{
    mb_communication_info_t comm = {
        .ser_opts.port = MB_PORT_NUM,
#if CONFIG_MB_COMM_MODE_ASCII
        .ser_opts.mode = MB_ASCII,
#elif CONFIG_MB_COMM_MODE_RTU
        .ser_opts.mode = MB_RTU,
#endif
        .ser_opts.baudrate = MB_DEV_SPEED,
        .ser_opts.parity = MB_PARITY_NONE,
        .ser_opts.uid = 0,
        .ser_opts.response_tout_ms = CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1,
    };
    // Make fake descriptor to start normally
    const mb_parameter_descriptor_t descriptor[] = {{0, "", "", 1, 1, 1, 1, 1, 1, 1, {}, 1}};
    esp_err_t err = mbc_master_create_serial(&comm, &serial_master_handle);
    ESP_RETURN_ON_FALSE((err == ESP_OK && serial_master_handle), ESP_ERR_INVALID_STATE, TAG, "Create serial master failed.");
    err = mbc_master_set_descriptor(serial_master_handle, &descriptor[0], 1);
    ESP_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                        "Set master descriptor fail, returns(0x%x).", (int)err);
    ESP_RETURN_ON_ERROR(uart_set_pin(MB_PORT_NUM, CONFIG_MB_UART_TXD, CONFIG_MB_UART_RXD, CONFIG_MB_UART_RTS, UART_PIN_NO_CHANGE),
                        TAG, "Set UART pins failed.");
    ESP_RETURN_ON_ERROR(uart_set_mode(MB_PORT_NUM, UART_MODE_RS485_HALF_DUPLEX), TAG, "Set RS485 mode failed.");
    ESP_RETURN_ON_ERROR(mbc_master_start(serial_master_handle), TAG, "Start serial master failed.");
    ESP_LOGI(TAG, "%p, Downstream serial master started on UART%d at %" PRIu32 " baud.",
             serial_master_handle, MB_PORT_NUM, (uint32_t)MB_DEV_SPEED);
    return ESP_OK;
}

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
static esp_err_t destroy_serial_master(void)
{
    ESP_RETURN_ON_ERROR(mbc_master_stop(serial_master_handle), TAG, "Stop SERIAL master failed.");
    ESP_RETURN_ON_FALSE(serial_master_handle, ESP_ERR_INVALID_STATE, TAG, "SERIAL master delete failed, handle is null.");
    ESP_RETURN_ON_ERROR(mbc_master_delete(serial_master_handle), TAG, "Delete SERIAL master failed.");
    serial_master_handle = NULL;
    return ESP_OK;
}
#endif

static esp_err_t init_tcp_slave(void)
{
    mb_communication_info_t comm = {
        .tcp_opts.port = MB_TCP_PORT_NUMBER,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = NULL,
        .tcp_opts.ip_netif_ptr = (void *)get_example_netif(),
        .tcp_opts.uid = MB_GATEWAY_TCP_UID,
    };

    esp_err_t err = mbc_slave_create_tcp(&comm, &tcp_slave_handle);
    ESP_RETURN_ON_FALSE((tcp_slave_handle && err == ESP_OK), ESP_ERR_INVALID_STATE, TAG, "TCP slave create failed.");
    ESP_LOGI(TAG, "%p, Modbus TCP gateway is created.", tcp_slave_handle);
    // This cycle overrides the TCP slave's standard handler for each supported function code
    // with its own small handler to translate TCP Slave onto the downstream side (Modbus Serial Master).
    for (size_t i = 0; i < sizeof(gateway_handlers) / sizeof(gateway_handlers[0]); ++i) {
        ESP_RETURN_ON_ERROR(install_gateway_handler(&gateway_handlers[i]),
                            TAG, "Install gateway handler %u, failed.", gateway_handlers[i].func_code);
    }

    ESP_RETURN_ON_ERROR(mbc_slave_start(tcp_slave_handle), TAG, "Start TCP slave failed.");
    ESP_LOGI(TAG, "%p, Modbus TCP slave started on port %u, gateway UID %u.",
             tcp_slave_handle, (unsigned)MB_TCP_PORT_NUMBER, (unsigned)MB_GATEWAY_TCP_UID);
    return ESP_OK;
}

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
static esp_err_t destroy_tcp_slave(void)
{
    ESP_RETURN_ON_ERROR(mbc_slave_stop(tcp_slave_handle), TAG, "Stop TCP slave failed.");
    for (size_t i = 0; i < sizeof(gateway_handlers) / sizeof(gateway_handlers[0]); ++i) {
        ESP_RETURN_ON_ERROR(restore_gateway_handler(&gateway_handlers[i]),
                            TAG, "Restore gateway handler %u, failed.", gateway_handlers[i].func_code);
    }
    ESP_RETURN_ON_FALSE(tcp_slave_handle, ESP_ERR_INVALID_STATE, TAG, "TCP slave delete failed, handle is null.");
    ESP_RETURN_ON_ERROR(mbc_slave_delete(tcp_slave_handle), TAG, "Delete TCP slave failed.");
    tcp_slave_handle = NULL;
    return ESP_OK;
}
#endif

void app_main(void)
{
    esp_log_level_set("mbc_serial.master", ESP_LOG_DEBUG);
    esp_log_level_set("mbc_tcp.slave", ESP_LOG_DEBUG);
    esp_log_level_set("vfs_calls", ESP_LOG_NONE);

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
    if (!mb_service_semaphore) {
        mb_service_semaphore = xSemaphoreCreateBinary();
        ESP_RETURN_ON_FALSE(mb_service_semaphore != NULL, ;, TAG, "Failed to create the Modbus service semaphore.");
        xSemaphoreTake(mb_service_semaphore, 1);
    }
#endif

    ESP_ERROR_CHECK(init_services());
    ESP_ERROR_CHECK(init_serial_master());
    ESP_ERROR_CHECK(init_tcp_slave());

    ESP_LOGI(TAG, "%p, Modbus TCP gateway is running.", tcp_slave_handle);

#if CONFIG_MB_GATEWAY_ALLOW_DESTROY_SELF_TEST
    BaseType_t status = pdFALSE;
    status = xSemaphoreTake(mb_service_semaphore, pdMS_TO_TICKS(MB_MAX_CYCLE_TIMEOUT_MS));
    if (status != pdTRUE) {
        ESP_LOGW(TAG, "Service timeout, destroy gateway.");
    }
    ESP_LOGI(TAG, "Service destroy gateway.");
    ESP_ERROR_CHECK(destroy_tcp_slave());
    ESP_ERROR_CHECK(destroy_serial_master());
    ESP_ERROR_CHECK(destroy_services());
    (void)xSemaphoreGive(mb_service_semaphore);
    vSemaphoreDelete(mb_service_semaphore);
    mb_service_semaphore = NULL;
#endif
}
