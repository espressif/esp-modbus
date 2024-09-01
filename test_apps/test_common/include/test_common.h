/*
 * SPDX-FileCopyrightText: 2018-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "unity.h"
#include "unity_test_runner.h"

#include "mbcontroller.h" // for common Modbus defines
#include "esp_log.h"

#include "sdkconfig.h"

#define STR(fieldname) ((const char *)(fieldname))
#define OPTS(min_val, max_val, step_val)               \
{                                                      \
    .opt1 = min_val, .opt2 = max_val, .opt3 = step_val \
}

// Enumeration of modbus slave addresses accessed by master device
enum
{
    MB_DEVICE_ADDR1 = 1,
    MB_DEVICE_ADDR2 = 200
};

// Enumeration of all supported CIDs for device (used in parameter definition table)
enum {
    CID_DEV_REG0 = 0,
    CID_DEV_REG1,
    CID_DEV_REG2,
    CID_DEV_REG3,
    CID_DEV_REG_COUNT
};

// Enumeration of predefined test values
enum {
    TEST_REG_VAL1 = 0x1111,
    TEST_REG_VAL2 = 0x2222,
    TEST_REG_VAL3 = 0x3333,
    TEST_REG_VAL4 = 0x4444
};

typedef struct task_entry_s {
    TaskHandle_t task_handle;
    SemaphoreHandle_t task_sema_handle;
    void *inst_handle;
    LIST_ENTRY(task_entry_s) entries;
} task_entry_t;

/**
 * @brief Start, stop helpers for common test module
 *
 */
void test_common_start();
void test_common_stop();

/**
 * @brief Helper test functions for multi instance modbus master - slave test
 *
 */
// TaskHandle_t test_common_slave_serial_create(mb_communication_info_t *pconfig);

TaskHandle_t test_common_slave_serial_create(mb_communication_info_t *pconfig, uint32_t priority);
TaskHandle_t test_common_master_serial_create(mb_communication_info_t *pconfig,uint32_t priority, const mb_parameter_descriptor_t *pdescr, uint16_t descr_size);
TaskHandle_t test_common_slave_tcp_create(mb_communication_info_t *pconfig, uint32_t priority);
TaskHandle_t test_common_master_tcp_create(mb_communication_info_t *pconfig, uint32_t priority, const mb_parameter_descriptor_t *pdescr, uint16_t descr_size);
TaskHandle_t test_common_start_busy_task(uint32_t priority);

/**
 * @brief The test helper function to check memory leak
 *
 */
void test_common_check_leak(size_t before_free, size_t after_free, const char *type, size_t warn_threshold, size_t critical_threshold);

// Slave setup register area helper
void test_common_slave_setup_start(void *mbs_handle);
// Helper function to read characteristic from slave
esp_err_t test_common_read_modbus_parameter(void *handle, uint16_t cid, uint16_t *par_data);
// Helper function to write  characteristic into slave
esp_err_t test_common_write_modbus_parameter(void *handle, uint16_t cid, uint16_t *par_data);

/**
 * @brief The test helper functions to work with test tasks
 *
 */
void test_common_task_notify_start(TaskHandle_t task_handle, uint32_t value);
void test_common_task_start(TaskHandle_t task_handle, uint32_t value);
int test_common_task_start_all(uint32_t value);
bool test_common_task_wait_done(TaskHandle_t task_handle, TickType_t timeout_ticks);
bool test_common_task_wait_done_delete(TaskHandle_t task_handle, TickType_t task_timeout_ticks);
int test_common_task_wait_done_delete_all(TickType_t task_timeout_tick);
void test_common_task_delete(TaskHandle_t task_handle);
void test_common_task_delete_all();
void *test_common_task_get_instance(TaskHandle_t task_handle);


