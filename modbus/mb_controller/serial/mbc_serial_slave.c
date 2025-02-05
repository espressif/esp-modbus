/*
 * SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// mbc_serial_slave.c
// Implementation of the Modbus controller serial slave

#include <sys/time.h> // for calculation of time stamp in milliseconds
#include "esp_log.h"  // for log_write

#include "esp_modbus_common.h" // for common defines
#include "esp_modbus_slave.h"  // for public slave interface types
#include "mbc_slave.h"         // for private slave interface types
#include "mbc_serial_slave.h"  // for serial slave implementation definitions

#include "mb_common.h" // for mb object types definition

#include "sdkconfig.h" // for KConfig values

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

static const char *TAG = "mbc_serial.slave";

// Modbus task function
static void mbc_ser_slave_task(void *param)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(param);
    mbs_controller_iface_t *mbs_iface = MB_SLAVE_GET_IFACE(param);

    // Main Modbus stack processing cycle
    for (;;)
    {
        BaseType_t status = xEventGroupWaitBits(mbs_opts->event_group_handle,
                                                (BaseType_t)(MB_EVENT_STACK_STARTED),
                                                pdFALSE, // do not clear bits
                                                pdFALSE,
                                                portMAX_DELAY);
        // Check if stack started then poll for data
        if (status & MB_EVENT_STACK_STARTED)
        {
            (void)mbs_iface->mb_base->poll(mbs_iface->mb_base);
        }
        // esp_task_wdt_reset();
    }
}

// Start Modbus controller start function
static esp_err_t mbc_serial_slave_start(void *ctx)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    mbs_controller_iface_t *mbs_iface = MB_SLAVE_GET_IFACE(ctx);
    mb_err_enum_t status = MB_EIO;

    status = mbs_iface->mb_base->enable(mbs_iface->mb_base);
    MB_RETURN_ON_FALSE((status == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack enable fail, returned (0x%x).", (int)status);
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
static esp_err_t mbc_serial_slave_stop(void *ctx)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    mbs_controller_iface_t *mbs_iface = MB_SLAVE_GET_IFACE(ctx);
    mb_err_enum_t status = MB_EIO;
    // Clear the mbcontroller start flag
    EventBits_t flag = xEventGroupClearBits(mbs_opts->event_group_handle,
                                            (EventBits_t)MB_EVENT_STACK_STARTED);
    MB_RETURN_ON_FALSE((flag & MB_EVENT_STACK_STARTED),
                       ESP_ERR_INVALID_STATE, TAG, "mb stack start event set error.");

    status = mbs_iface->mb_base->disable(mbs_iface->mb_base);
    MB_RETURN_ON_FALSE((status == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack disable fail, returned (0x%x).", (int)status);
    mbs_iface->mb_base->descr.parent = NULL;
    mbs_iface->is_active = false;
    return ESP_OK;
}

// Blocking function to get event on parameter group change for application task
static mb_event_group_t mbc_serial_slave_check_event(void *ctx, mb_event_group_t group)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    MB_SLAVE_ASSERT(mbs_opts->event_group_handle);
    BaseType_t status = xEventGroupWaitBits(mbs_opts->event_group_handle, (BaseType_t)group,
                                            pdTRUE, pdFALSE, portMAX_DELAY);
    return (mb_event_group_t)status;
}

// Function to get notification about parameter change from application task
static esp_err_t mbc_serial_slave_get_param_info(void *ctx, mb_param_info_t *reg_info, uint32_t timeout)
{
    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(ctx);
    esp_err_t err = ESP_ERR_TIMEOUT;
    MB_RETURN_ON_FALSE((mbs_opts->notification_queue_handle),
                       ESP_ERR_INVALID_ARG, TAG, "mb queue handle is invalid.");
    MB_RETURN_ON_FALSE((reg_info), ESP_ERR_INVALID_ARG, TAG, "mb register information is invalid.");
    BaseType_t status = xQueueReceive(mbs_opts->notification_queue_handle,
                                      reg_info, pdMS_TO_TICKS(timeout));
    if (status == pdTRUE)
    {
        err = ESP_OK;
    }
    return err;
}

// Modbus controller delete function
static esp_err_t mbc_serial_slave_delete(void *ctx)
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
    if (mbs_iface->is_active || (status & MB_EVENT_STACK_STARTED))
    {
        ESP_LOGV(TAG, "mb stack is active, try to disable.");
        if (mbc_serial_slave_stop(ctx) != ESP_OK) {
            ESP_LOGE(TAG, "mb stack stop failure.");
        }
    }

    mbs_iface->is_active = false;
    vTaskDelete(mbs_opts->task_handle);
    vEventGroupDelete(mbs_opts->event_group_handle);
    vQueueDelete(mbs_opts->notification_queue_handle);
    mbs_opts->notification_queue_handle = NULL;
    mbs_opts->event_group_handle = NULL;
    mbs_opts->task_handle = NULL;
    mb_error = mbs_iface->mb_base->delete(mbs_iface->mb_base);
    MB_RETURN_ON_FALSE((mb_error == MB_ENOERR), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack close failure returned (0x%x).", (int)mb_error);
    // free the controller will be performed in common slave object
    return ESP_OK;
}

static void mbc_serial_slave_iface_free(void *ctx)
{
    mbs_controller_iface_t *mbs_iface = (mbs_controller_iface_t *)(ctx);
    if (mbs_iface)
    {
        if (mbs_iface->opts.task_handle)
        {
            vTaskDelete(mbs_iface->opts.task_handle);
            mbs_iface->opts.task_handle = NULL;
        }
        if (mbs_iface->opts.event_group_handle)
        {
            vEventGroupDelete(mbs_iface->opts.event_group_handle);
            mbs_iface->opts.event_group_handle = NULL;
        }
        if (mbs_iface->opts.notification_queue_handle)
        {
            vQueueDelete(mbs_iface->opts.notification_queue_handle);
        }
        free(mbs_iface); // free the memory allocated for interface
    }   
}

static esp_err_t mbc_serial_slave_controller_create(void **ctx)
{
    MB_RETURN_ON_FALSE((ctx), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack init interface fail.");
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    mbs_controller_iface_t *mbs_controller_iface = malloc(sizeof(mbs_controller_iface_t));
    MB_GOTO_ON_FALSE((mbs_controller_iface), ESP_ERR_NO_MEM, error,
                     TAG, "mb stack memory allocation fail.");

    mb_slave_options_t *mbs_opts = &mbs_controller_iface->opts;
    mbs_opts->port_type = MB_PORT_SERIAL_SLAVE; // set interface port type

    // Initialization of active context of the Modbus controller
    BaseType_t status = 0;
    // Parameter change notification queue
    mbs_opts->event_group_handle = xEventGroupCreate();
    MB_GOTO_ON_FALSE((mbs_opts->event_group_handle), ESP_ERR_NO_MEM, error,
                     TAG, "mb event group error.");
    // Parameter change notification queue
    mbs_opts->notification_queue_handle = xQueueCreate(MB_CONTROLLER_NOTIFY_QUEUE_SIZE, sizeof(mb_param_info_t));
    MB_GOTO_ON_FALSE((mbs_opts->notification_queue_handle), ESP_ERR_NO_MEM, error,
                     TAG, "mb notify queue creation error.");
    // Create Modbus controller task
    status = xTaskCreatePinnedToCore((void *)&mbc_ser_slave_task,
                                     "mbc_ser_slave",
                                     MB_CONTROLLER_STACK_SIZE,
                                     mbs_controller_iface,
                                     MB_CONTROLLER_PRIORITY,
                                     &mbs_opts->task_handle,
                                     MB_PORT_TASK_AFFINITY);
    MB_GOTO_ON_FALSE((status == pdPASS), ESP_ERR_INVALID_STATE, error, TAG,
                     "mb controller task creation error");
    MB_SLAVE_ASSERT(mbs_opts->task_handle); // The task is created but handle is incorrect

    // Initialize interface function pointers
    mbs_controller_iface->create = mbc_serial_slave_create;
    mbs_controller_iface->delete = mbc_serial_slave_delete;
    mbs_controller_iface->check_event = mbc_serial_slave_check_event;
    mbs_controller_iface->get_param_info = mbc_serial_slave_get_param_info;
    mbs_controller_iface->set_descriptor = NULL; // Use common set descriptor function
    mbs_controller_iface->start = mbc_serial_slave_start;
    mbs_controller_iface->stop = mbc_serial_slave_stop;
    mbs_controller_iface->mb_base = NULL;
    *ctx = mbs_controller_iface;
    return ESP_OK;

error:
    mbc_serial_slave_iface_free((void *)mbs_controller_iface);
    return ret;
}

// Initialization of Modbus controller
esp_err_t mbc_serial_slave_create(mb_communication_info_t *config, void **ctx)
{
    mbs_controller_iface_t *mbs_controller_iface = NULL;
    MB_RETURN_ON_FALSE((ctx && config), ESP_ERR_INVALID_STATE, TAG,
                       "mb stack init interface fail.");
    MB_RETURN_ON_FALSE((!*ctx), ESP_ERR_INVALID_STATE, TAG, "mb stack is not destroyed?");
    mb_serial_opts_t *pcomm_info = &config->ser_opts;

    // Check communication options
    MB_RETURN_ON_FALSE(((pcomm_info->mode == MB_RTU) || (pcomm_info->mode == MB_ASCII)),
                       ESP_ERR_INVALID_ARG, TAG, "mb incorrect mode = (%u).",
                       (unsigned)pcomm_info->mode);
    MB_RETURN_ON_FALSE((pcomm_info->port <= UART_NUM_MAX), ESP_ERR_INVALID_ARG, TAG,
                       "mb wrong port to set = (%u).", (unsigned)pcomm_info->port);
    MB_RETURN_ON_FALSE((pcomm_info->parity <= UART_PARITY_ODD), ESP_ERR_INVALID_ARG, TAG,
                       "mb wrong parity option = (%u).", (unsigned)pcomm_info->parity);
    MB_RETURN_ON_FALSE((pcomm_info->uid <= MB_ADDRESS_MAX),
                       ESP_ERR_INVALID_ARG, TAG, "mb wrong slave address = (0x%u).",
                       (unsigned)pcomm_info->uid);

    esp_err_t ret = mbc_serial_slave_controller_create((void *)&mbs_controller_iface);
    MB_GOTO_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE, error, TAG,
                     "mbc create returns (0x%x).", (int)ret);

    mb_slave_options_t *mbs_opts = MB_SLAVE_GET_OPTS(mbs_controller_iface);
    mbs_opts->port_type = MB_PORT_SERIAL_SLAVE;
    mbs_opts->comm_opts = *config;
    mb_err_enum_t err = MB_ENOERR;
    void *pinst = (void *)mbs_controller_iface;

    // Initialize Modbus stack using mbcontroller parameters
    if (pcomm_info->mode == MB_RTU)
    {
#if (CONFIG_FMB_COMM_MODE_RTU_EN)
        err = mbs_rtu_create(pcomm_info, &pinst);
#else
        ESP_LOGE(TAG, "RTU mode is not enabled in the configuration.");
        ret = ESP_ERR_NOT_SUPPORTED;
        goto error;
#endif
    }
    else if (pcomm_info->mode == MB_ASCII)
    {
#if (CONFIG_FMB_COMM_MODE_ASCII_EN)
        err = mbs_ascii_create(pcomm_info, &pinst);
#else
        ESP_LOGE(TAG, "ASCII mode is not enabled in the configuration.");
        ret = ESP_ERR_NOT_SUPPORTED;
        goto error;
#endif // CONFIG_FMB_COMM_MODE_ASCII_EN
    }
    MB_GOTO_ON_FALSE((err == MB_ENOERR), ESP_ERR_INVALID_STATE, error, TAG,
                     "mbs create returns (0x%x).", (int)err);
    mbs_controller_iface->mb_base = (mb_base_t *)pinst;

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
    if (mbs_controller_iface) {
        if (mbs_controller_iface->mb_base) {
            mbs_controller_iface->mb_base->delete (mbs_controller_iface->mb_base);
            mbs_controller_iface->mb_base = NULL;
        }
        mbc_serial_slave_iface_free((void *)mbs_controller_iface);
        *ctx = NULL;
    }
    return ret;
}

#endif // #if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)