/*
 * SPDX-FileCopyrightText: 2018-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/queue.h"

#include "port_adapter.h"
#include "mb_common.h"
#include "mbc_slave.h"
#include "mbc_master.h"

#include "test_common.h"
#include "esp_heap_caps.h"

#include "sdkconfig.h"

#ifdef CONFIG_HEAP_TRACING
#include "esp_heap_trace.h"
#endif

#define TEST_TASK_PRIO_MASTER       (CONFIG_MB_TEST_MASTER_TASK_PRIO)
#define TEST_TASK_PRIO_SLAVE        (CONFIG_MB_TEST_SLAVE_TASK_PRIO)
#define TEST_TASK_STACK_SIZE        (5120)
#define TEST_TASK_CYCLE_COUNTER     (CONFIG_MB_TEST_COMM_CYCLE_COUNTER)
#define TEST_BUSY_TASK_PRIO         (20)

#define TEST_REG_START_AREA0        (0x0000)
#define TEST_READ_MASK              (MB_EVENT_HOLDING_REG_RD |\
                                        MB_EVENT_INPUT_REG_RD |\
                                        MB_EVENT_DISCRETE_RD |\
                                        MB_EVENT_COILS_RD)
#define TEST_WRITE_MASK             (MB_EVENT_HOLDING_REG_WR | MB_EVENT_COILS_WR)
#define TEST_READ_WRITE_MASK        (TEST_WRITE_MASK | TEST_READ_MASK)
#define TEST_BUSY_COUNT             (150000)
#define TEST_PAR_INFO_GET_TOUT      (10)
#define TEST_SEND_TIMEOUT           (200 / portTICK_PERIOD_MS)
#define TEST_TASK_START_TIMEOUT     (10000 / portTICK_PERIOD_MS)
#define TEST_NOTIF_SEND_TOUT        (400 / portTICK_PERIOD_MS)
#define TEST_NOTIF_SIZE             (20)
#define TEST_ALLOW_PROC_FAIL        (5) // percentage of allowed failures due to desynchronization
#define TEST_TASK_TICK_TIME         (50 / portTICK_PERIOD_MS)

#define TAG "TEST_COMMON"

typedef enum {
    RT_HOLDING_RD,
    RT_HOLDING_WR
} mb_access_t;

static uint16_t holding_registers[16] = {0};
static uint16_t input_registers[8] = {0};
static uint16_t coil_registers[10] = {0};

const uint16_t holding_registers_counter = (sizeof(holding_registers) / sizeof(holding_registers[0]));
const uint16_t input_registers_counter = (sizeof(input_registers) / sizeof(input_registers[0]));
const uint16_t coil_registers_counter = (sizeof(coil_registers) / sizeof(coil_registers[0]));

static int test_error_counter = 0;
static int test_good_counter = 0;

static size_t before_free_8bit = 0;
static size_t before_free_32bit = 0;

// Heap memory leak traicing
#ifdef CONFIG_HEAP_TRACING
#define NUM_RECORDS 500
static heap_trace_record_t trace_record[NUM_RECORDS];
#endif

#define CHECK_PAR_VALUE(par, err, value, expected)                                                                              \
    do                                                                                                                          \
    {                                                                                                                           \
        if ((err != ESP_OK) || (((uint16_t)value) != ((uint16_t)expected)))                                                     \
        {                                                                                                                       \
            ESP_LOGE(TAG, "CHAR #%u, value: 0x%" PRIx16 ", expected: 0x%" PRIx16 ", error = %d.",                               \
                            (unsigned)par, ((uint16_t)value), ((uint16_t)expected), (int)err);                                  \
            TEST_ASSERT((++test_error_counter * 100 / (TEST_TASK_CYCLE_COUNTER * CID_DEV_REG_COUNT)) <= TEST_ALLOW_PROC_FAIL);  \
        }                                                                                                                       \
        else                                                                                                                    \
        {                                                                                                                       \
            ESP_LOGI(TAG, "CHAR #%u, value is ok.", (unsigned)par);                                                             \
            test_good_counter++;                                                                                                \
        }                                                                                                                       \
    } while (0)

// The linked list of test tasks instances
LIST_HEAD(task_entry, task_entry_s) s_task_list;

static portMUX_TYPE s_list_spinlock = portMUX_INITIALIZER_UNLOCKED;

static void task_entry_remove(task_entry_t *task_entry)
{
        portENTER_CRITICAL(&s_list_spinlock);
        LIST_REMOVE(task_entry, entries);
        portEXIT_CRITICAL(&s_list_spinlock);
        ESP_LOGD(TAG, "Delete task 0x%" PRIx32, (uint32_t)task_entry->task_handle);
        vTaskDelete(task_entry->task_handle);
        vSemaphoreDelete(task_entry->task_sema_handle);
        free(task_entry);
}

static bool task_wait_done_and_remove(task_entry_t *task_entry, TickType_t tout_ticks)
{
    bool is_done = false;
    if (task_entry && task_entry->task_handle && task_entry->task_sema_handle) {
        if ((xSemaphoreTake(task_entry->task_sema_handle, tout_ticks) == pdTRUE)) {
            ESP_LOGI(TAG, "Test task 0x%" PRIx32 ", done successfully.", (uint32_t)task_entry->task_handle);
            is_done = true;
        } else {
            ESP_LOGE(TAG, "Could not complete task 0x%" PRIx32 " after timeout, force kill the task.",
                        (uint32_t)task_entry->task_handle);
            is_done = false;
        }
        vTaskDelay(1); // Let the lower priority task to suspend or delete itself
        task_entry_remove(task_entry);
    }
    return (is_done);
}

static void test_task_add_entry(TaskHandle_t task_handle, void *pinst)
{
    TEST_ASSERT_TRUE(task_handle);
    task_entry_t *new_entry = (task_entry_t*) calloc(1, sizeof(task_entry_t));
    TEST_ASSERT_TRUE(new_entry);
    portENTER_CRITICAL(&s_list_spinlock);
    new_entry->task_handle = task_handle;
    new_entry->task_sema_handle = xSemaphoreCreateBinary();
    new_entry->inst_handle = pinst;
    LIST_INSERT_HEAD(&s_task_list, new_entry, entries);
    portEXIT_CRITICAL(&s_list_spinlock);
    xSemaphoreTake(new_entry->task_sema_handle, 1);
}

static task_entry_t *test_task_find_entry(TaskHandle_t task_handle)
{
    TEST_ASSERT_NOT_NULL(task_handle);
    
    task_entry_t *it, *pfound = NULL;
    if (LIST_EMPTY(&s_task_list)) {
        return NULL;
    }

    portENTER_CRITICAL(&s_list_spinlock);
    LIST_FOREACH(it, &s_task_list, entries) {
        if (it->task_handle == task_handle) {
            pfound = it;
            break;
        }
    }
    portEXIT_CRITICAL(&s_list_spinlock);
    return pfound;
}

static void test_common_task_notify_done(TaskHandle_t task_handle)
{
    task_entry_t *it = test_task_find_entry(task_handle);
    if (it) { 
        xSemaphoreGive(it->task_sema_handle);
    }
}

static void test_busy_task(void *phandle)
{
    spinlock_t spin_lock;
    SPIN_LOCK_INIT(spin_lock);
    ESP_EARLY_LOGW(TAG, "test task");
    while(1) {
        SPIN_LOCK_ENTER(spin_lock);
        for (int i = 0; i < TEST_BUSY_COUNT; i++){
            ;
        }
        SPIN_LOCK_EXIT(spin_lock);
        vTaskDelay(1);
    }
}

void test_common_task_start(TaskHandle_t task_handle, uint32_t value)
{
    // Directly notify the task waiting to start loop
    test_common_task_notify_start(task_handle, value);
}

int test_common_task_start_all(uint32_t value)
{
    task_entry_t *it = NULL;
    if (LIST_EMPTY(&s_task_list)) {
        return 0;
    }
    int task_count = 0;
    LIST_FOREACH(it, &s_task_list, entries) {
        test_common_task_notify_start(it->task_handle, value);
        task_count++;
    }
    return task_count;
}

bool test_common_task_wait_done(TaskHandle_t task_handle, TickType_t timeout_ticks)
{
    task_entry_t *it = test_task_find_entry(task_handle);
    if (it && (xSemaphoreTake(it->task_sema_handle, timeout_ticks) == pdTRUE)) {
        return true;
    }
    return false;
}

bool test_common_task_wait_done_delete(TaskHandle_t task_handle, TickType_t task_timeout_ticks)
{
    task_entry_t *it = test_task_find_entry(task_handle);
    return task_wait_done_and_remove(it, task_timeout_ticks);
}

int test_common_task_wait_done_delete_all(TickType_t task_timeout_tick)
{
    task_entry_t *it, *ptmp = NULL;
    int task_count = 0;
    if (LIST_EMPTY(&s_task_list)) {
        return 0;
    }
    LIST_FOREACH_SAFE(it, &s_task_list, entries, ptmp) {
        task_wait_done_and_remove(it, task_timeout_tick);
        task_count++;
    }
    return task_count;
}

void test_common_task_delete(TaskHandle_t task_handle)
{
    task_entry_t *it = test_task_find_entry(task_handle);
    if (it) {
        task_entry_remove(it);
    }
}

void test_common_task_delete_all()
{
    task_entry_t *it = NULL;
    while ((it = LIST_FIRST(&s_task_list))) {
        task_entry_remove(it);
    }
}

void *test_common_task_get_instance(TaskHandle_t task_handle)
{
    task_entry_t *it = test_task_find_entry(task_handle);
    if (it) { 
        return it->inst_handle;
    }
    return NULL;
}

// Start the high priority task to mimic the case when the modbus
// tasks do not get time quota from RTOS.
TaskHandle_t test_common_start_busy_task(uint32_t priority)
{
    TaskHandle_t busy_task_handle = NULL;
    if (!priority) {
        priority = TEST_BUSY_TASK_PRIO;
    }

    TEST_ASSERT_TRUE(xTaskCreatePinnedToCore(test_busy_task, "busy_task",
                                            TEST_TASK_STACK_SIZE,
                                            NULL, priority,
                                            &busy_task_handle, MB_PORT_TASK_AFFINITY));
    test_task_add_entry(busy_task_handle, NULL);
    return busy_task_handle;
}

void test_common_start()
{
#ifdef CONFIG_HEAP_TRACING
    ESP_ERROR_CHECK( heap_trace_init_standalone(trace_record, NUM_RECORDS) );
#endif

    before_free_8bit = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    before_free_32bit = heap_caps_get_free_size(MALLOC_CAP_32BIT);

#ifdef CONFIG_HEAP_TRACING
    ESP_ERROR_CHECK( heap_trace_start(HEAP_TRACE_LEAKS) );
#endif
    LIST_INIT(&s_task_list);
}

void test_common_stop()
{
    //vQueueDelete(tasks_done_queue);
    holding_registers[CID_DEV_REG_COUNT] = 0;
    test_error_counter = 0;
    test_good_counter = 0;

    /* check if unit test has caused heap corruption in any heap */
    TEST_ASSERT_MESSAGE(heap_caps_check_integrity(MALLOC_CAP_INVALID, true), "The test has corrupted the heap");

#ifdef CONFIG_HEAP_TRACING
    ESP_ERROR_CHECK( heap_trace_stop() );
    heap_trace_dump();
#endif
    size_t after_free_8bit = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t after_free_32bit = heap_caps_get_free_size(MALLOC_CAP_32BIT);
    test_common_check_leak(before_free_8bit, after_free_8bit, "8BIT", 
                            CONFIG_MB_TEST_LEAK_WARN_LEVEL, CONFIG_MB_TEST_LEAK_CRITICAL_LEVEL);
    test_common_check_leak(before_free_32bit, after_free_32bit, "32BIT", 
                            CONFIG_MB_TEST_LEAK_WARN_LEVEL, CONFIG_MB_TEST_LEAK_CRITICAL_LEVEL);
}

static uint32_t test_common_task_wait_start(TickType_t timeout_ticks)
{
    static uint32_t notify_value = 0;

    if (xTaskNotifyWait(0, 0, &notify_value, timeout_ticks) == pdTRUE) {
        ESP_LOGD(TAG, "Task: 0x%" PRIx32 ", get notify value = %u", 
                        (uint32_t)xTaskGetCurrentTaskHandle(), (unsigned)notify_value);
        return pdTRUE;
    }
    return 0;
}

void test_common_task_notify_start(TaskHandle_t task_handle, uint32_t value)
{
    ESP_LOGD(TAG, "Notify task start 0x%" PRIx32, (uint32_t)task_handle);
    TEST_ASSERT_EQUAL_INT(xTaskNotify(task_handle, value, eSetValueWithOverwrite), pdTRUE);
}

void test_common_check_leak(size_t before_free,
                            size_t after_free,
                            const char *type,
                            size_t warn_threshold,
                            size_t critical_threshold)
{
    int free_delta = (int)after_free - (int)before_free;
    printf("MALLOC_CAP_%s usage: Free memory delta: %d Leak threshold: -%u \n",
           type,
           free_delta,
           critical_threshold);

    if (free_delta > 0) {
        return; // free memory went up somehow
    }

    size_t leaked = (size_t)(free_delta * -1);
    if (leaked <= warn_threshold) {
        return;
    }

    printf("MALLOC_CAP_%s %s leak: Before %u bytes free, After %u bytes free (delta %u)\n",
           type,
           leaked <= critical_threshold ? "potential" : "critical",
           before_free, after_free, leaked);
    fflush(stdout);
    TEST_ASSERT_MESSAGE(leaked <= critical_threshold, "The test leaked too much memory");
}

// Helper function to read one characteristic from slave
esp_err_t test_common_read_modbus_parameter(void *handle, uint16_t cid, uint16_t *par_data)
{
    const mb_parameter_descriptor_t *param_descriptor = NULL;

    esp_err_t err = mbc_master_get_cid_info(handle, cid, &param_descriptor);
    if ((err != ESP_ERR_NOT_FOUND) && (param_descriptor != NULL))
    {
        uint8_t type = 0;
        err = mbc_master_get_parameter(handle, cid, (uint8_t *)par_data, &type);
        if (err == ESP_OK)
        {
            ESP_LOGI(TAG, "%p, CHAR #%u %s (%s) value = (0x%04x) parameter read successful.",
                     handle,
                     param_descriptor->cid,
                     param_descriptor->param_key,
                     param_descriptor->param_units,
                     *(uint16_t *)par_data);
        }
        else
        {
            ESP_LOGE(TAG, "%p, CHAR #%u (%s) read fail, err = 0x%x (%s).",
                     handle,
                     param_descriptor->cid,
                     param_descriptor->param_key,
                     (int)err,
                     (char *)esp_err_to_name(err));
        }
    }
    return err;
}

// Helper function to write one characteristic to slave
esp_err_t write_modbus_parameter(void *handle, uint16_t cid, uint16_t *par_data)
{
    const mb_parameter_descriptor_t *param_descriptor = NULL;

    esp_err_t err = mbc_master_get_cid_info(handle, cid, &param_descriptor);
    if ((err != ESP_ERR_NOT_FOUND) && (param_descriptor != NULL))
    {
        uint8_t type = 0; // type of parameter from dictionary
        err = mbc_master_set_parameter(handle, cid, (uint8_t *)par_data, &type);
        if (err == ESP_OK)
        {
            ESP_LOGI(TAG, "%p, CHAR #%u %s (%s) value = (0x%04x), write successful.",
                     handle,
                     param_descriptor->cid,
                     param_descriptor->param_key,
                     param_descriptor->param_units,
                     *(uint16_t *)par_data);
        }
        else
        {
            ESP_LOGE(TAG, "%p, CHAR #%u (%s) write fail, err = 0x%x (%s).",
                     handle,
                     param_descriptor->cid,
                     param_descriptor->param_key,
                     (int)err,
                     (char *)esp_err_to_name(err));
        }
    }
    return err;
}

// This is user function to read and write modbus holding registers
static void test_master_task(void *arg)
{
    void *mbm_handle = arg;
    //mbm_controller_iface_t *pctrl_obj = ((mbm_controller_iface_t *)mbm_handle);

    static mb_access_t req_type = RT_HOLDING_RD;
    esp_err_t err = ESP_FAIL;
    uint16_t cycle_counter = 0;

    // Wait task start notification during timeout
    test_common_task_wait_start(TEST_TASK_START_TIMEOUT);

    holding_registers[CID_DEV_REG0] = TEST_REG_VAL1;
    holding_registers[CID_DEV_REG1] = TEST_REG_VAL2;
    holding_registers[CID_DEV_REG2] = TEST_REG_VAL3;
    holding_registers[CID_DEV_REG3] = TEST_REG_VAL4;
    holding_registers[CID_DEV_REG_COUNT] = cycle_counter;
    write_modbus_parameter(mbm_handle, CID_DEV_REG0, &holding_registers[CID_DEV_REG0]);
    write_modbus_parameter(mbm_handle, CID_DEV_REG1, &holding_registers[CID_DEV_REG1]);
    write_modbus_parameter(mbm_handle, CID_DEV_REG2, &holding_registers[CID_DEV_REG2]);
    write_modbus_parameter(mbm_handle, CID_DEV_REG3, &holding_registers[CID_DEV_REG3]);
    for (cycle_counter = 0; cycle_counter <= TEST_TASK_CYCLE_COUNTER; cycle_counter++)
    {
        switch (req_type)
        {
            case RT_HOLDING_RD:
                err = test_common_read_modbus_parameter(mbm_handle, CID_DEV_REG0, &holding_registers[CID_DEV_REG0]);
                CHECK_PAR_VALUE(CID_DEV_REG0, err, holding_registers[CID_DEV_REG0], TEST_REG_VAL1);

                err = test_common_read_modbus_parameter(mbm_handle, CID_DEV_REG1, &holding_registers[CID_DEV_REG1]);
                CHECK_PAR_VALUE(CID_DEV_REG1, err, holding_registers[CID_DEV_REG1], TEST_REG_VAL2);

                err = test_common_read_modbus_parameter(mbm_handle, CID_DEV_REG2, &holding_registers[CID_DEV_REG2]);
                CHECK_PAR_VALUE(CID_DEV_REG2, err, holding_registers[CID_DEV_REG2], TEST_REG_VAL3);

                err = test_common_read_modbus_parameter(mbm_handle, CID_DEV_REG3, &holding_registers[CID_DEV_REG3]);
                CHECK_PAR_VALUE(CID_DEV_REG3, err, holding_registers[CID_DEV_REG3], TEST_REG_VAL4);
                req_type = RT_HOLDING_WR;
                break;

            case RT_HOLDING_WR:
                err = write_modbus_parameter(mbm_handle, CID_DEV_REG0, &holding_registers[CID_DEV_REG0]);
                CHECK_PAR_VALUE(CID_DEV_REG0, err, holding_registers[CID_DEV_REG0], TEST_REG_VAL1);

                err = write_modbus_parameter(mbm_handle, CID_DEV_REG1, &holding_registers[CID_DEV_REG1]);
                CHECK_PAR_VALUE(CID_DEV_REG1, err, holding_registers[CID_DEV_REG1], TEST_REG_VAL2);

                err = write_modbus_parameter(mbm_handle, CID_DEV_REG2, &holding_registers[CID_DEV_REG2]);
                CHECK_PAR_VALUE(CID_DEV_REG2, err, holding_registers[CID_DEV_REG2], TEST_REG_VAL3);

                err = write_modbus_parameter(mbm_handle, CID_DEV_REG3, &holding_registers[CID_DEV_REG3]);
                CHECK_PAR_VALUE(CID_DEV_REG3, err, holding_registers[CID_DEV_REG3], TEST_REG_VAL4);
                req_type = RT_HOLDING_RD;
                break;

            default:
                break;
        }
        if (holding_registers[CID_DEV_REG_COUNT] >= TEST_TASK_CYCLE_COUNTER) {
            ESP_LOGI(TAG, "Stop master: %p.", mbm_handle);
            break;
        } else {
            write_modbus_parameter(mbm_handle, CID_DEV_REG_COUNT, &cycle_counter);
            vTaskDelay(TEST_TASK_TICK_TIME); // Let the IDLE task to trigger
        }
    }
    ESP_LOGI(TAG, "Destroy master, inst: %p.", mbm_handle);
    TEST_ESP_OK(mbc_master_delete(mbm_handle));
    test_common_task_notify_done(xTaskGetCurrentTaskHandle());
    vTaskSuspend(NULL);
}

static void test_slave_task(void *arg)
{
    void *mbs_handle = arg;
    mbs_controller_iface_t *pctrl_obj = ((mbs_controller_iface_t *)mbs_handle);
    mb_param_info_t reg_info;                    // keeps the Modbus registers access information

    test_common_task_wait_start(TEST_TASK_START_TIMEOUT);

    while(1) {
        // Get parameter information from parameter queue
        esp_err_t err = mbc_slave_get_param_info(mbs_handle, &reg_info, TEST_PAR_INFO_GET_TOUT);
        const char *rw_str = (reg_info.type & TEST_READ_MASK) ? "READ" : "WRITE";

        // Filter events and process them accordingly
        if ((err != ESP_ERR_TIMEOUT) && (reg_info.type & TEST_READ_WRITE_MASK))
        {
            // Get parameter information from parameter queue
            ESP_LOGI("SLAVE", "OBJ %p, %s (%" PRIu32 " us), SL: %u, REG:%u, TYPE:%u, INST_ADDR:0x%" PRIx32 "(0x%" PRIx16 "), SIZE:%u",
                     (void *)pctrl_obj->mb_base->descr.parent,
                     rw_str,
                     (uint32_t)reg_info.time_stamp,
                     (unsigned)pctrl_obj->opts.comm_opts.common_opts.uid,
                     (unsigned)reg_info.mb_offset,
                     (unsigned)reg_info.type,
                     (uint32_t)reg_info.address,
                     *(uint16_t *)reg_info.address,
                     (unsigned)reg_info.size);
        }
        vTaskDelay(TEST_TASK_TICK_TIME); // Let IDLE task to trigger
        if (holding_registers[CID_DEV_REG_COUNT] >= TEST_TASK_CYCLE_COUNTER) {
            ESP_LOGD(TAG, "Stop slave: %p.", mbs_handle);
            vTaskDelay(TEST_TASK_TICK_TIME); // Let master to get response from slave prior to close
            break;
        }
    }
    ESP_LOGI(TAG, "Destroy slave, inst: %p.", mbs_handle);
    TEST_ESP_OK(mbc_slave_delete(mbs_handle));
    ESP_LOGD(TAG, "Notify task done, inst: %p.", xTaskGetCurrentTaskHandle());
    test_common_task_notify_done(xTaskGetCurrentTaskHandle());
    vTaskDelay(10);
    vTaskSuspend(NULL);
}

void test_common_slave_setup_start(void *mbs_handle)
{
    TEST_ASSERT_TRUE(mbs_handle);
    mb_register_area_descriptor_t reg_area;

    reg_area.type = MB_PARAM_HOLDING;
    reg_area.start_offset = TEST_REG_START_AREA0;
    reg_area.address = (void *)&holding_registers[CID_DEV_REG0];
    reg_area.size = holding_registers_counter << 1;
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));

    reg_area.type = MB_PARAM_INPUT;
    reg_area.start_offset = TEST_REG_START_AREA0;
    reg_area.address = (void *)&input_registers[CID_DEV_REG0];
    reg_area.size = input_registers_counter << 1;
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));

    reg_area.type = MB_PARAM_COIL;
    reg_area.start_offset = TEST_REG_START_AREA0;
    reg_area.address = (void *)&coil_registers[CID_DEV_REG0];
    reg_area.size = coil_registers_counter;
    TEST_ESP_OK(mbc_slave_set_descriptor(mbs_handle, reg_area));
    TEST_ESP_OK(mbc_slave_start(mbs_handle));
}

#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)

TaskHandle_t test_common_master_serial_create(mb_communication_info_t *pconfig,
                                                uint32_t priority, 
                                                const mb_parameter_descriptor_t *pdescr,
                                                uint16_t descr_size)
{
    if (!pconfig || !pdescr) {
        ESP_LOGI(TAG, "invalid master configuration.");
    }

    void *mbm_handle = NULL;
    TaskHandle_t master_task_handle = NULL;

    TEST_ESP_OK(mbc_master_create_serial(pconfig, &mbm_handle));
    mbm_controller_iface_t *pbase = mbm_handle;

    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, pdescr, descr_size));
    ESP_LOGI(TAG, "%p, modbus master stack is initialized", mbm_handle);

    TEST_ESP_OK(mbc_master_start(mbm_handle));
    ESP_LOGI(TAG, "%p, modbus master start...", mbm_handle) ;

    if (priority) {
        priority = TEST_TASK_PRIO_MASTER;
    }
    
    char* port_name = pbase->mb_base->descr.parent_name;
    TEST_ASSERT_TRUE(xTaskCreatePinnedToCore(test_master_task, port_name,
                                             TEST_TASK_STACK_SIZE,
                                             mbm_handle, priority,
                                             &master_task_handle, MB_PORT_TASK_AFFINITY));
    test_task_add_entry(master_task_handle, mbm_handle);
    return master_task_handle;
}

TaskHandle_t test_common_slave_serial_create(mb_communication_info_t *pconfig, uint32_t priority)
{
    if (!pconfig) {
        ESP_LOGI(TAG, "invalid slave configuration.");
    }

    void *mbs_handle = NULL;
    TaskHandle_t slave_task_handle = NULL;

    TEST_ESP_OK(mbc_slave_create_serial(pconfig, &mbs_handle));

    mbs_controller_iface_t *pbase = mbs_handle;

    test_common_slave_setup_start(mbs_handle);

    if (priority) {
        priority = TEST_TASK_PRIO_SLAVE;
    }

    TEST_ASSERT_TRUE(xTaskCreatePinnedToCore(test_slave_task, pbase->mb_base->descr.parent_name,
                                             TEST_TASK_STACK_SIZE,
                                             mbs_handle, priority,
                                             &slave_task_handle, MB_PORT_TASK_AFFINITY));
    test_task_add_entry(slave_task_handle, mbs_handle);
    return slave_task_handle;
}

#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

TaskHandle_t test_common_master_tcp_create(mb_communication_info_t *pconfig, uint32_t priority, const mb_parameter_descriptor_t *pdescr, uint16_t descr_size)
{
    if (!pconfig || !pdescr) {
        ESP_LOGI(TAG, "invalid master configuration.");
    }

    void *mbm_handle = NULL;
    TaskHandle_t master_task_handle = NULL;

    TEST_ESP_OK(mbc_master_create_tcp(pconfig, &mbm_handle));
    mbm_controller_iface_t *pbase = mbm_handle;

    TEST_ESP_OK(mbc_master_set_descriptor(mbm_handle, pdescr, descr_size));
    ESP_LOGI(TAG, "%p, modbus master stack is initialized", mbm_handle);
    
    TEST_ESP_OK(mbc_master_start(mbm_handle));
    ESP_LOGI(TAG, "%p, modbus master start...", mbm_handle) ;
    
    if (priority) {
        priority = TEST_TASK_PRIO_MASTER;
    }

    char *port_name = pbase->mb_base->descr.parent_name;
    TEST_ASSERT_TRUE(xTaskCreatePinnedToCore(test_master_task, port_name,
                                             TEST_TASK_STACK_SIZE,
                                             mbm_handle, priority,
                                             &master_task_handle, MB_PORT_TASK_AFFINITY));

    test_task_add_entry(master_task_handle, mbm_handle);
    return master_task_handle;
}

TaskHandle_t test_common_slave_tcp_create(mb_communication_info_t *pconfig, uint32_t priority)
{
    if (!pconfig) {
        ESP_LOGI(TAG, "invalid slave configuration.");
    }

    void *mbs_handle = NULL;
    TaskHandle_t slave_task_handle = NULL;

    TEST_ESP_OK(mbc_slave_create_tcp(pconfig, &mbs_handle));

    mbs_controller_iface_t *pbase = mbs_handle;
    test_common_slave_setup_start(mbs_handle);

    if (priority) {
        priority = TEST_TASK_PRIO_SLAVE;
    }

    TEST_ASSERT_TRUE(xTaskCreatePinnedToCore(test_slave_task, pbase->mb_base->descr.parent_name,
                                             TEST_TASK_STACK_SIZE,
                                             mbs_handle, priority,
                                             &slave_task_handle, MB_PORT_TASK_AFFINITY));
    test_task_add_entry(slave_task_handle, mbs_handle);
    return slave_task_handle;
}

#endif
