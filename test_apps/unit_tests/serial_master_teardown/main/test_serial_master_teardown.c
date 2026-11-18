/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdatomic.h>

#include "driver/uart.h"
#include "mbc_master.h"
#include "unity.h"

#define TEST_UART UART_NUM_1
#define TEST_WAIT pdMS_TO_TICKS(10000)

enum {
    UART_IDLE,
    UART_WAIT_FOR_WORKER,
    UART_HOLD_RECEIVE,
};

static atomic_int uart_stage;
static QueueHandle_t uart_events;
static SemaphoreHandle_t producer_entered;
static SemaphoreHandle_t producer_release;

static const mb_parameter_descriptor_t descriptor = {
    .param_key = "holding",
    .mb_slave_addr = 1,
    .mb_param_type = MB_PARAM_HOLDING,
    .mb_size = 1,
    .param_type = PARAM_TYPE_U16,
    .param_size = sizeof(uint16_t),
    .access = PAR_PERMS_READ,
};

esp_err_t __real_uart_driver_install(uart_port_t uart_num, int rx_buffer_size, int tx_buffer_size,
                                     int queue_size, QueueHandle_t *uart_queue, int intr_alloc_flags);
esp_err_t __wrap_uart_driver_install(uart_port_t uart_num, int rx_buffer_size, int tx_buffer_size,
                                     int queue_size, QueueHandle_t *uart_queue, int intr_alloc_flags)
{
    esp_err_t err = __real_uart_driver_install(uart_num, rx_buffer_size, tx_buffer_size,
                                               queue_size, uart_queue, intr_alloc_flags);
    if (err == ESP_OK && uart_num == TEST_UART && uart_queue) {
        uart_events = *uart_queue;
    }
    return err;
}

static void hold_producer(void)
{
    xSemaphoreGive(producer_entered);
    xSemaphoreTake(producer_release, portMAX_DELAY);
}

esp_err_t __real_uart_get_buffered_data_len(uart_port_t uart_num, size_t *size);
esp_err_t __wrap_uart_get_buffered_data_len(uart_port_t uart_num, size_t *size)
{
    if (uart_num == TEST_UART) {
        switch (atomic_exchange(&uart_stage, UART_IDLE)) {
        case UART_WAIT_FOR_WORKER:
            // Complete the worker's initial RX flush with an empty buffer.
            *size = 0;
            xSemaphoreGive(producer_entered);
            return ESP_OK;
        case UART_HOLD_RECEIVE:
            // The worker has dequeued a UART event and is about to publish it.
            hold_producer();
            *size = 8;
            return ESP_OK;
        default:
            break;
        }
    }
    return __real_uart_get_buffered_data_len(uart_num, size);
}

static void *create_master(mb_comm_mode_t mode)
{
    mb_communication_info_t config = {
        .ser_opts.port = TEST_UART,
        .ser_opts.mode = mode,
        .ser_opts.baudrate = 115200,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1,
        .ser_opts.parity = UART_PARITY_DISABLE,
    };
    void *controller = NULL;
    TEST_ESP_OK(mbc_master_create_serial(&config, &controller));
    TEST_ESP_OK(mbc_master_set_descriptor(controller, &descriptor, 1));
    return controller;
}

static void verify_delete_waits_for_producer(void *controller)
{
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(producer_entered, TEST_WAIT));
    const TickType_t started = xTaskGetTickCount();
    TEST_ESP_ERR(ESP_ERR_TIMEOUT, mbc_master_delete(controller));
    const TickType_t elapsed = xTaskGetTickCount() - started;
    TEST_ASSERT_UINT_WITHIN(pdMS_TO_TICKS(100),
                            pdMS_TO_TICKS(CONFIG_FMB_SERIAL_MASTER_DELETE_TIMEOUT_MS), elapsed);
    TEST_ASSERT_TRUE(uart_is_driver_installed(TEST_UART));
    TEST_ESP_ERR(ESP_ERR_INVALID_STATE, mbc_master_start(controller));

    xSemaphoreGive(producer_release);
    TEST_ESP_OK(mbc_master_delete(controller));
    TEST_ASSERT_FALSE(uart_is_driver_installed(TEST_UART));
}

static void test_delete_waits_for_uart_event(void)
{
    atomic_store(&uart_stage, UART_WAIT_FOR_WORKER);
    void *controller = create_master(MB_RTU);
    TEST_ASSERT_NOT_NULL(uart_events);
    TEST_ESP_OK(mbc_master_start(controller));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(producer_entered, TEST_WAIT));

    const uart_event_t event = {.type = UART_DATA, .size = 8, .timeout_flag = true};
    atomic_store(&uart_stage, UART_HOLD_RECEIVE);
    TEST_ASSERT_EQUAL(pdTRUE, xQueueSend(uart_events, &event, TEST_WAIT));
    verify_delete_waits_for_producer(controller);
}

#ifdef MB_HAVE_ESP_TIMER_STOP_BLOCKING
static bool hold_timer_callback(void *arg)
{
    (void)arg;
    hold_producer();
    return false;
}
#endif

static void test_delete_waits_for_timer_callback(void)
{
#ifdef MB_HAVE_ESP_TIMER_STOP_BLOCKING
    void *controller = create_master(MB_ASCII);
    mb_port_base_t *port = ((mbm_controller_iface_t *)controller)->mb_base->port_obj;

    // Use the real ESP Timer dispatcher and hold the Modbus alarm callback.
    port->cb.tmr_expired = hold_timer_callback;
    mb_port_timer_delay(port, 1);
    verify_delete_waits_for_producer(controller);
#else
    TEST_IGNORE_MESSAGE("ESP-IDF does not expose esp_timer_stop_blocking");
#endif
}

void setUp(void)
{
    atomic_store(&uart_stage, UART_IDLE);
    uart_events = NULL;
    producer_entered = xSemaphoreCreateBinary();
    producer_release = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(producer_entered);
    TEST_ASSERT_NOT_NULL(producer_release);
}

void tearDown(void)
{
    vSemaphoreDelete(producer_release);
    vSemaphoreDelete(producer_entered);
}

void app_main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_delete_waits_for_uart_event);
    RUN_TEST(test_delete_waits_for_timer_callback);
    UNITY_END();
}
