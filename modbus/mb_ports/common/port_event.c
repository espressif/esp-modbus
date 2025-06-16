/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "sdkconfig.h"

#include "port_common.h"
#include "mb_common.h"

static const char *TAG = "mb_port.event";

struct mb_port_event_t
{
    _Atomic(int) curr_err_type;
    SemaphoreHandle_t resource_hdl;
    EventGroupHandle_t event_group_hdl;
    QueueHandle_t event_hdl;
    _Atomic(uint64_t) curr_trans_id;
};

mb_err_enum_t mb_port_event_create(mb_port_base_t *inst)
{
    mb_port_event_t *pevent = NULL;
    mb_err_enum_t ret = MB_EILLSTATE;
    MB_RETURN_ON_FALSE((inst), MB_EILLSTATE, TAG, "mb event creation error.");
    pevent = (mb_port_event_t *)calloc(1, sizeof(mb_port_event_t));
    MB_RETURN_ON_FALSE((pevent), MB_EILLSTATE, TAG, "mb event creation error.");
    // Create modbus semaphore (mb resource).
    pevent->resource_hdl = xSemaphoreCreateBinary();
    MB_GOTO_ON_FALSE((pevent->resource_hdl), MB_EILLSTATE, error, TAG,
                            "%s, mb resource create failure.", inst->descr.parent_name);
    pevent->event_group_hdl = xEventGroupCreate();
    MB_GOTO_ON_FALSE((pevent->event_group_hdl), MB_EILLSTATE, error, TAG,
                        "%s, event group create error.", inst->descr.parent_name);
    pevent->event_hdl = xQueueCreate(MB_EVENT_QUEUE_SIZE, sizeof(mb_event_t));
    MB_GOTO_ON_FALSE((pevent->event_hdl), MB_EILLSTATE, error,  TAG, "%s, event queue create error.", inst->descr.parent_name);
    vQueueAddToRegistry(pevent->event_hdl, TAG);
    inst->event_obj = pevent;
    atomic_init(&pevent->curr_err_type, EV_ERROR_INIT);
    ESP_LOGD(TAG, "initialized object @%p", pevent);
    return MB_ENOERR;

error:
    if(pevent->event_hdl) {
        vQueueDelete(pevent->event_hdl);
        pevent->event_hdl = NULL;
    }
    if (pevent->event_group_hdl) {
        vEventGroupDelete(pevent->event_group_hdl);
        pevent->event_group_hdl = NULL;
    }
    if (pevent->resource_hdl) {
        vSemaphoreDelete(pevent->resource_hdl);
        pevent->resource_hdl = NULL;
    }
    free(inst->event_obj);
    inst->event_obj = NULL;
    return ret;
}
 
inline void mb_port_event_set_err_type(mb_port_base_t *inst, mb_err_event_t event)
{
    MB_RETURN_ON_FALSE((inst && inst->event_obj), ;, TAG, "incorrect object handle.");
    atomic_store(&(inst->event_obj->curr_err_type), event);
}

inline mb_err_event_t mb_port_event_get_err_type(mb_port_base_t *inst)
{
    MB_RETURN_ON_FALSE((inst && inst->event_obj), EV_ERROR_INIT, TAG, "incorrect object handle.");
    return atomic_load(&inst->event_obj->curr_err_type);
}

uint64_t mb_port_get_trans_id(mb_port_base_t *inst)
{
    MB_RETURN_ON_FALSE((inst && inst->event_obj), 0, TAG, "incorrect object handle.");
    return atomic_load(&(inst->event_obj->curr_trans_id));
}

bool mb_port_event_post(mb_port_base_t *inst, mb_event_t event)
{
    MB_RETURN_ON_FALSE((inst), false, TAG, "incorrect object handle for transaction %" PRIu64, event.trans_id);
    MB_RETURN_ON_FALSE((inst->event_obj && inst->event_obj->event_hdl), false, TAG, 
                            "Wrong event handle for transaction: %" PRIu64" %d, %p, %s.", 
                            event.trans_id, (int)(event.event), inst, inst->descr.parent_name);
    BaseType_t result = pdFALSE;
    mb_event_t temp_event;
    temp_event = event;
    temp_event.post_ts = esp_timer_get_time();

    if (event.event & EV_TRANS_START) {
        atomic_store(&(inst->event_obj->curr_trans_id), temp_event.post_ts);
    }
    temp_event.event = (event.event & ~EV_TRANS_START);

    if (xPortInIsrContext()) {
        BaseType_t high_prio_task_woken = pdFALSE;
        result = xQueueSendFromISR(inst->event_obj->event_hdl, 
                                    (const void*)&temp_event, &high_prio_task_woken);
        // Was the message posted successfully?
        if (result == pdPASS) {
            // If high_prio_task_woken is now set to pdTRUE
            // then a context switch should be requested.
            if (high_prio_task_woken) {
                portYIELD_FROM_ISR();
            }
            return true;
        } else {
            ESP_EARLY_LOGV(TAG, "%s, post message %x failure .", inst->descr.parent_name, temp_event.event);
            return false;
        }    
        if (high_prio_task_woken) {
            portYIELD_FROM_ISR();
        }
    } else {
        result = xQueueSend(inst->event_obj->event_hdl, (const void*)&temp_event, MB_EVENT_QUEUE_TIMEOUT_MAX);
        if (result != pdTRUE) {
            xQueueReset(inst->event_obj->event_hdl);
            ESP_LOGE(TAG, "%s, post message failure.", inst->descr.parent_name);
            return false;
        }
    }
    return true;
}

bool mb_port_event_get(mb_port_base_t *inst, mb_event_t *pevent)
{
    MB_RETURN_ON_FALSE((inst && pevent && inst->event_obj && inst->event_obj->event_hdl), false, TAG, 
                            "incorrect object handle.");
    bool event_happened = false;

    if (xQueueReceive(inst->event_obj->event_hdl, pevent, MB_EVENT_QUEUE_TIMEOUT_MAX) == pdTRUE) {
        pevent->trans_id = atomic_load(&inst->event_obj->curr_trans_id);
        pevent->get_ts = esp_timer_get_time();
        event_happened = true;
    } else {
        ESP_LOGD(TAG, "%s, get event timeout.", inst->descr.parent_name);
    }
    return event_happened;
}

bool mb_port_event_res_take(mb_port_base_t *inst, uint32_t timeout)
{
    MB_RETURN_ON_FALSE((inst && inst->event_obj && inst->event_obj->resource_hdl), false, TAG, 
                            "incorrect object handle.");
    BaseType_t status = pdTRUE;
    status = xSemaphoreTake(inst->event_obj->resource_hdl, timeout);
    ESP_LOGD(TAG, "%s, mb take resource, (%" PRIu32 " ticks).", inst->descr.parent_name, timeout);
    return status;
}

void mb_port_event_res_release(mb_port_base_t *inst)
{
    MB_RETURN_ON_FALSE((inst && inst->event_obj && inst->event_obj->resource_hdl), ;, TAG, 
                            "incorrect object handle.");
    BaseType_t status = pdFALSE;
    status = xSemaphoreGive(inst->event_obj->resource_hdl);
    if (status != pdTRUE) {
        ESP_LOGD(TAG, "%s, mb resource release.", inst->descr.parent_name);
    }
}

void mb_port_event_set_resp_flag(mb_port_base_t *inst, mb_event_enum_t event_mask)
{
    MB_RETURN_ON_FALSE((inst), ;, TAG, "incorrect object handle.");
    (void)xEventGroupSetBits(inst->event_obj->event_group_hdl, event_mask);
}

mb_err_enum_t mb_port_event_wait_req_finish(mb_port_base_t *inst)
{
    MB_RETURN_ON_FALSE((inst), MB_EINVAL, TAG, 
                            "incorrect object handle.");
    mb_err_enum_t err_status = MB_ENOERR;
    mb_event_enum_t rcv_event;
    EventBits_t bits = xEventGroupWaitBits(inst->event_obj->event_group_hdl, // The event group being tested.
                                                MB_EVENT_REQ_MASK,  // The bits within the event group to wait for.
                                                pdTRUE,             // Masked bits should be cleared before returning.
                                                pdFALSE,            // Don't wait for both bits, either bit will do.
                                                MB_EVENT_QUEUE_TIMEOUT_MAX);    // Wait forever for either bit to be set.
    rcv_event = (mb_event_enum_t)(bits);
    if (rcv_event) {
        ESP_LOGD(TAG, "%s, %s: returned event = 0x%x", inst->descr.parent_name, __func__, (int)rcv_event);
        if (!(rcv_event & MB_EVENT_REQ_MASK)) {
            // if we wait for certain event bits but get from poll subset
            ESP_LOGE(TAG, "%s, %s: incorrect event set = 0x%x", inst->descr.parent_name, __func__, (int)rcv_event);
        }
        if (MB_PORT_CHECK_EVENT(rcv_event, EV_MASTER_PROCESS_SUCCESS)) {
            err_status = MB_ENOERR;
        } else if (MB_PORT_CHECK_EVENT(rcv_event, EV_MASTER_ERROR_RESPOND_TIMEOUT)) {
            err_status = MB_ETIMEDOUT;
        } else if (MB_PORT_CHECK_EVENT(rcv_event, EV_MASTER_ERROR_RECEIVE_DATA)) {
            err_status = MB_ERECVDATA;
        } else if (MB_PORT_CHECK_EVENT(rcv_event, EV_MASTER_ERROR_EXECUTE_FUNCTION)) {
            err_status = MB_EILLFUNC;
        }
    } else {
        ESP_LOGD(TAG, "%s, %s: incorrect event or timeout, rcv_event = 0x%x", inst->descr.parent_name, __func__, (int)bits);
        err_status = MB_ETIMEDOUT;
    }
    return err_status;
}

void mb_port_event_delete(mb_port_base_t *inst)
{
    MB_RETURN_ON_FALSE((inst), ;, TAG, 
                            "incorrect event object handle.");
    if (inst->event_obj->resource_hdl) {
        vSemaphoreDelete(inst->event_obj->resource_hdl);
    }
    if (inst->event_obj->event_group_hdl) {
        vEventGroupDelete(inst->event_obj->event_group_hdl);
    }
    if(inst->event_obj->event_hdl) {
        vQueueDelete(inst->event_obj->event_hdl);
        inst->event_obj->event_hdl = NULL;
    }
    free(inst->event_obj);
    inst->event_obj = NULL;
}
