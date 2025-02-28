/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// mbc_tcp_slave.c
// Implementation of the Modbus controller TCP slave

#include <sys/time.h>               // for calculation of time stamp in milliseconds
#include "esp_log.h"                // for log_write
#include "sdkconfig.h"              // for KConfig values
#include "esp_modbus_common.h"      // for common defines
#include "esp_modbus_slave.h"       // for public slave interface types
#include "mbc_slave.h"              // for private slave interface types
#include "mbc_tcp_slave.h"          // for tcp slave mb controller defines
#include "port_tcp_common.h"

#include "mb_common.h"               // for mb types definition

#if MB_TCP_ENABLED

static const char *TAG = "mbc_tcp.slave";

// Modbus task function
static void modbus_tcp_slave_task(void *param)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(param);
    mbs_controller_iface_t *mbs_iface = MB_SLAVE_GET_IFACE(param);

    // Main Modbus stack processing cycle
    for (;;) {
        BaseType_t status = xEventGroupWaitBits(mbs_opts->event_group_handle,
                                                (BaseType_t)(MB_EVENT_STACK_STARTED),
                                                pdFALSE, // do not clear bits
                                                pdFALSE,
                                                portMAX_DELAY);
        // Check if stack started then poll for data
        if (status & MB_EVENT_STACK_STARTED) {
            (void)mbs_iface->mb_base->poll(mbs_iface->mb_base);
        }
    }
}

// Start Modbus controller start function
static esp_err_t mbc_tcp_slave_start(void *ctx)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    mbs_controller_iface_t *mbs_iface = MB_SLAVE_GET_IFACE(ctx);
    mb_err_enum_t status = MB_EIO;

    status = mbs_iface->mb_base->enable(mbs_iface->mb_base);
    MB_RETURN_ON_FALSE((status == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                        "mb stack enable fail, returned (0x%x).", (uint16_t)status);
    // Set the mbcontroller start flag
    EventBits_t flag = xEventGroupSetBits(mbs_opts->event_group_handle,
                                            (EventBits_t)MB_EVENT_STACK_STARTED);
    MB_RETURN_ON_FALSE((flag & MB_EVENT_STACK_STARTED),
                        ESP_ERR_INVALID_STATE, TAG, "mb stack start event set error.");
    mbs_iface->mb_base->descr.parent = ctx;
    mbs_iface->is_active = true;
    return ESP_OK;
}

// Start Modbus controller stop function
static esp_err_t mbc_tcp_slave_stop(void *ctx)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    mbs_controller_iface_t *mbs_iface = MB_SLAVE_GET_IFACE(ctx);
    mb_err_enum_t status = MB_EIO;

    status = mbs_iface->mb_base->disable(mbs_iface->mb_base);
    MB_RETURN_ON_FALSE((status == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                        "mb stack disable fail, returned (0x%x).", (uint16_t)status);
    // Clear the mbcontroller start flag
    EventBits_t flag = xEventGroupClearBits(mbs_opts->event_group_handle,
                                            (EventBits_t)MB_EVENT_STACK_STARTED);
    MB_RETURN_ON_FALSE((flag & MB_EVENT_STACK_STARTED),
                        ESP_ERR_INVALID_STATE, TAG, "mb stack start event set error.");
    mbs_iface->mb_base->descr.parent = NULL;
    mbs_iface->is_active = false;
    return ESP_OK;
}

// Blocking function to get event on parameter group change for application task
static mb_event_group_t mbc_tcp_slave_check_event(void *ctx, mb_event_group_t group)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    MB_SLAVE_ASSERT(mbs_opts->event_group_handle);
    BaseType_t status = xEventGroupWaitBits(mbs_opts->event_group_handle, (BaseType_t)group,
                                            pdTRUE , pdFALSE, portMAX_DELAY);
    return (mb_event_group_t)status;
}

// Function to get notification about parameter change from application task
static esp_err_t mbc_tcp_slave_get_param_info(void *ctx, mb_param_info_t *reg_info, uint32_t timeout)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    esp_err_t err = ESP_ERR_TIMEOUT;
    MB_RETURN_ON_FALSE((mbs_opts->notification_queue_handle),
                ESP_ERR_INVALID_ARG, TAG, "mb queue handle is invalid.");
    MB_RETURN_ON_FALSE(reg_info, ESP_ERR_INVALID_ARG, TAG, "mb register information is invalid.");
    BaseType_t status = xQueueReceive(mbs_opts->notification_queue_handle,
                                        reg_info, pdMS_TO_TICKS(timeout));
    if (status == pdTRUE) {
        err = ESP_OK;
    }
    return err;
}

// Modbus controller delete function
static esp_err_t mbc_tcp_slave_delete(void *ctx)
{
    mbs_controller_iface_t *mbs_iface = MB_SLAVE_GET_IFACE(ctx);
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    mb_err_enum_t mb_error = MB_ENOERR;
    
    // Check the stack started bit 
    BaseType_t status = xEventGroupWaitBits(mbs_opts->event_group_handle,
                                        (BaseType_t)(MB_EVENT_STACK_STARTED),
                                        pdFALSE,
                                        pdFALSE,
                                        MB_CONTROLLER_NOTIFY_TIMEOUT);
    if (mbs_iface->is_active || (status & MB_EVENT_STACK_STARTED)) {
        ESP_LOGV(TAG, "mb stack is active, try to disable.");
        MB_RETURN_ON_FALSE((mbc_tcp_slave_stop(ctx) == ESP_OK), 
                                ESP_ERR_INVALID_STATE, TAG, "mb stack stop failure.");
    }

    mbs_iface->is_active = false;
    vTaskDelete(mbs_opts->task_handle);
    vEventGroupDelete(mbs_opts->event_group_handle);
    vQueueDelete(mbs_opts->notification_queue_handle);
    mb_error = mbs_iface->mb_base->delete(mbs_iface->mb_base);
    MB_RETURN_ON_FALSE((mb_error == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                        "mb stack close failure returned (0x%x).", (int)mb_error);
    // free the controller will be performed in common object
    return ESP_OK;
}

esp_err_t mbc_tcp_slave_controller_create(void ** ctx)
{
    MB_RETURN_ON_FALSE((ctx), ESP_ERR_INVALID_STATE, TAG,
                            "mb stack init interface fail.");
    mbs_controller_iface_t *mbs_controller_iface = *ctx;
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    MB_RETURN_ON_FALSE((mbs_controller_iface == NULL), ESP_ERR_INVALID_STATE, TAG,
                            "mb stack is not destroyed.");
    
    mbs_controller_iface = malloc(sizeof(mbs_controller_iface_t));
    MB_GOTO_ON_FALSE((mbs_controller_iface), ESP_ERR_NO_MEM, error, 
                        TAG, "mb stack memory allocation fail.");

    mb_slave_options_t *mbs_opts = &mbs_controller_iface->opts;
    mbs_opts->port_type = MB_PORT_TCP_SLAVE; // set interface port type

    // Initialization of active context of the Modbus controller
    BaseType_t status = 0;
    // Parameter change notification queue
    mbs_opts->event_group_handle = xEventGroupCreate();
    MB_GOTO_ON_FALSE((mbs_opts->event_group_handle), ESP_ERR_NO_MEM, error, 
                        TAG, "mb event group error.");
    // Parameter change notification queue
    mbs_opts->notification_queue_handle = xQueueCreate(
                                                MB_CONTROLLER_NOTIFY_QUEUE_SIZE,
                                                sizeof(mb_param_info_t));
    MB_GOTO_ON_FALSE((mbs_opts->notification_queue_handle), ESP_ERR_NO_MEM, error, 
                        TAG, "mb notify queue creation error.");
    // Create Modbus controller task
    status = xTaskCreatePinnedToCore((void *)&modbus_tcp_slave_task,
                                        "mbc_tcp_slave",
                                        MB_CONTROLLER_STACK_SIZE,
                                        mbs_controller_iface,
                                        MB_CONTROLLER_PRIORITY,
                                        &mbs_opts->task_handle,
                                        MB_PORT_TASK_AFFINITY);
    MB_GOTO_ON_FALSE((status == pdPASS), ESP_ERR_INVALID_STATE, error, TAG, 
                        "mb controller task creation error, xTaskCreate() returns (0x%x).", (uint16_t)status);
    // The task is created but handle is incorrect
    MB_SLAVE_ASSERT(mbs_opts->task_handle);

    // Initialization of interface pointers
    mbs_controller_iface->create = mbc_tcp_slave_create;
    mbs_controller_iface->delete = mbc_tcp_slave_delete;
    mbs_controller_iface->check_event = mbc_tcp_slave_check_event;
    mbs_controller_iface->get_param_info = mbc_tcp_slave_get_param_info;
    mbs_controller_iface->set_descriptor = NULL; // Use common descriptor setter
    mbs_controller_iface->start = mbc_tcp_slave_start;
    mbs_controller_iface->stop = mbc_tcp_slave_stop;
    *ctx = mbs_controller_iface;
    return ESP_OK;

error:
    if (mbs_controller_iface) {
        if (mbs_controller_iface->opts.task_handle) {
            vTaskDelete(mbs_controller_iface->opts.task_handle);
            mbs_controller_iface->opts.task_handle = NULL;
        }
        if (mbs_controller_iface->opts.event_group_handle) {
            vEventGroupDelete(mbs_controller_iface->opts.event_group_handle);
            mbs_controller_iface->opts.event_group_handle = NULL;
        }
    }
    free(mbs_controller_iface); // free the memory allocated
    ctx = NULL;
    return ret;
}

// Initialization of Modbus controller
esp_err_t mbc_tcp_slave_create(mb_communication_info_t *config, void **ctx)
{
    MB_RETURN_ON_FALSE((ctx && config), ESP_ERR_INVALID_STATE, TAG,
                            "mb stack init interface fail.");
    mbs_controller_iface_t *mbs_controller_iface = (mbs_controller_iface_t *)*ctx;
    MB_RETURN_ON_FALSE((!mbs_controller_iface), ESP_ERR_INVALID_STATE, TAG,
                            "mb stack is not destroyed.");
    // Check communication options
    mb_tcp_opts_t tcp_opts = (mb_tcp_opts_t)config->tcp_opts;
    MB_RETURN_ON_FALSE(((tcp_opts.mode == MB_TCP) || (tcp_opts.mode == MB_UDP)),
                        ESP_ERR_INVALID_ARG, TAG, "mb transport protocol is incorrect.");
    MB_RETURN_ON_FALSE(((tcp_opts.addr_type == MB_IPV6) || (tcp_opts.addr_type == MB_IPV4)),
                        ESP_ERR_INVALID_ARG, TAG, "mb ip address type is incorrect.");
    MB_RETURN_ON_FALSE((tcp_opts.port), ESP_ERR_INVALID_ARG, TAG, "mb port is not defined.");

    esp_err_t ret = mbc_tcp_slave_controller_create((void *)&mbs_controller_iface);
    MB_GOTO_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE, error, TAG, 
                        "mbc create returns (0x%x).", (uint16_t)ret);

    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(mbs_controller_iface);
    // keep the communication options to be able to restart port driver
    mbs_opts->comm_opts = *config;

    mbs_opts->port_type = MB_PORT_TCP_SLAVE;
    tcp_opts.mode = MB_TCP; // Override mode, UDP mode is not supported
    // Keep the response time setting
    if (!tcp_opts.response_tout_ms) {
        tcp_opts.response_tout_ms = CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND;
    }
    // Set default values of communication options
    if (!tcp_opts.port) {
        mbs_opts->comm_opts.tcp_opts.port = MB_TCP_DEFAULT_PORT;
    }

    mbs_opts->comm_opts.tcp_opts = tcp_opts;
    mb_err_enum_t err = MB_ENOERR;
    void *pinst = (void *)mbs_controller_iface;

    // Initialize Modbus stack using mbcontroller parameters
    err = mbs_tcp_create(&tcp_opts, &pinst);
    MB_GOTO_ON_FALSE((err == MB_ENOERR), ESP_ERR_INVALID_STATE, error, TAG, 
                        "mbscreate returns (0x%x).", (uint16_t)err);
    mbs_controller_iface->mb_base = (mb_base_t *)pinst;
    mbs_controller_iface->mb_base->descr.is_master = false;
    
    // Configure Modbus read/write callbacks for the base modbus object
    const mb_rw_callbacks_t rw_cbs = {
        .reg_input_cb = mbc_reg_input_slave_cb,
        .reg_holding_cb = mbc_reg_holding_slave_cb,
        .reg_coils_cb = mbc_reg_coils_slave_cb,
        .reg_discrete_cb = mbc_reg_discrete_slave_cb
    };
    mbs_controller_iface->mb_base->rw_cbs = rw_cbs;
    mbs_controller_iface->is_active = false;
    *ctx = (void *)mbs_controller_iface;
    return ESP_OK;

error:
    if (mbs_controller_iface->mb_base) {
        mbs_controller_iface->mb_base->delete(mbs_controller_iface->mb_base);
        mbs_controller_iface->mb_base = NULL;
    }
    return ret;
}

#endif //#if MB_TCP_ENABLED
