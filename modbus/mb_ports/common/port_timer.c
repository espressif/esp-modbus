/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*----------------------- Platform includes --------------------------------*/
#include <stdatomic.h>
#include "esp_idf_version.h"
#include "esp_attr.h"

#if __has_include("driver/gptimer.h")
#include "driver/gptimer.h"
#else
#include "driver/timer.h"
#endif

#include "esp_timer.h"
#include "esp_log.h"

#include "port_common.h"
#include "mb_types.h"
#include "mb_config.h"
#include "mb_common.h"

/* ----------------------- Defines ----------------------------------------*/
struct mb_port_timer_t
{
    //spinlock_t spin_lock;
    esp_timer_handle_t timer_handle;
    uint16_t t35_ticks;
    _Atomic(uint32_t) response_time_ms;
    _Atomic(bool) timer_state;
    _Atomic(uint16_t) timer_mode;
};

/* ----------------------- Static variables ---------------------------------*/
static const char *TAG = "mb_port.timer";

/* ----------------------- Start implementation -----------------------------*/
mb_timer_mode_enum_t mb_port_get_cur_timer_mode(mb_port_base_t *inst);

static void IRAM_ATTR timer_alarm_cb(void *param)
{
    mb_port_base_t *inst = (mb_port_base_t *)param;
    if (inst->cb.tmr_expired && inst->arg) {
        inst->cb.tmr_expired(inst->arg); // Timer expired callback function
    }
    atomic_store(&(inst->timer_obj->timer_state), true);
    ESP_EARLY_LOGD(TAG, "timer mode: (%d) triggered", mb_port_get_cur_timer_mode(inst));
}

mb_err_enum_t mb_port_timer_create(mb_port_base_t *inst, uint16_t t35_timer_ticks)
{
    MB_RETURN_ON_FALSE((t35_timer_ticks > 0), MB_EILLSTATE, TAG,
                       "modbus timeout discreet is incorrect.");
    // MB_RETURN_ON_FALSE((inst && !inst->timer_obj), MB_EILLSTATE, TAG,
    //                    "modbus timer is already created.");
    mb_err_enum_t ret = MB_EILLSTATE;
    inst->timer_obj = (mb_port_timer_t *)calloc(1, sizeof(mb_port_timer_t));
    MB_GOTO_ON_FALSE((inst && inst->timer_obj), MB_EILLSTATE, error, TAG, "mb timer allocation error.");
    inst->timer_obj->timer_handle = NULL;
    atomic_init(&(inst->timer_obj->timer_mode), MB_TMODE_T35);
    atomic_init(&(inst->timer_obj->timer_state), false);
    // Set default response time according to kconfig
    atomic_init(&(inst->timer_obj->response_time_ms), MB_MASTER_TIMEOUT_MS_RESPOND);
    // Save timer reload value for Modbus T35 period
    inst->timer_obj->t35_ticks = t35_timer_ticks;
    esp_timer_create_args_t timer_conf = {
        .callback = timer_alarm_cb,
        .arg = inst,
#if (MB_TIMER_SUPPORTS_ISR_DISPATCH_METHOD && MB_TIMER_USE_ISR_DISPATCH_METHOD)
        .dispatch_method = ESP_TIMER_ISR,
#else
        .dispatch_method = ESP_TIMER_TASK,
#endif
        .name = "MB_T35timer"
    };
    // Create Modbus timer
    esp_err_t err = esp_timer_create(&timer_conf, &(inst->timer_obj->timer_handle));
    MB_GOTO_ON_FALSE((err == ESP_OK), MB_EILLSTATE, error, TAG, "mb timer creation error.");
    ESP_LOGD(TAG, "initialized %s object @%p", TAG, inst->timer_obj);
    return MB_ENOERR;

error:
    if (inst && inst->timer_obj && inst->timer_obj->timer_handle)
    {
        esp_timer_delete(inst->timer_obj->timer_handle);
    }
    free(inst->timer_obj);
    inst->timer_obj = NULL;
    return ret;
}

void mb_port_timer_delete(mb_port_base_t *inst)
{
    // Delete active timer
    if (inst->timer_obj)
    {
        if (inst->timer_obj->timer_handle)
        {
            esp_timer_stop(inst->timer_obj->timer_handle);
            esp_timer_delete(inst->timer_obj->timer_handle);
        }
        free(inst->timer_obj);
        inst->timer_obj = NULL;
    }
}

void mb_port_timer_us(mb_port_base_t *inst, uint64_t timeout_us)
{
    MB_RETURN_ON_FALSE((inst && inst->timer_obj->timer_handle), ;, TAG, "timer is not initialized.");
    MB_RETURN_ON_FALSE((timeout_us > 0), ;, TAG,
                        "%s, incorrect tick value for timer = (%" PRId64 ").", inst->descr.parent_name, timeout_us);
    esp_timer_stop(inst->timer_obj->timer_handle);
    esp_timer_start_once(inst->timer_obj->timer_handle, timeout_us);
    atomic_store(&(inst->timer_obj->timer_state), false);
}


inline void mb_port_set_cur_timer_mode(mb_port_base_t *inst, mb_timer_mode_enum_t tmr_mode)
{
    atomic_store(&(inst->timer_obj->timer_mode), tmr_mode);
}

inline mb_timer_mode_enum_t mb_port_get_cur_timer_mode(mb_port_base_t *inst)
{
    return atomic_load(&(inst->timer_obj->timer_mode));
}

void mb_port_timer_enable(mb_port_base_t *inst)
{
    uint64_t tout_us = (inst->timer_obj->t35_ticks * MB_TIMER_TICK_TIME_US);

    // Set current timer mode, don't change it.
    mb_port_set_cur_timer_mode(inst, MB_TMODE_T35);
    // Set timer alarm
    mb_port_timer_us(inst, tout_us);
    ESP_LOGD(TAG, "%s, start timer (%" PRIu64 ").", inst->descr.parent_name, tout_us);
}

void mb_port_timer_convert_delay_enable(mb_port_base_t *inst)
{
    // Covert time in milliseconds into ticks
    uint64_t tout_us = (MB_MASTER_DELAY_MS_CONVERT * 1000);

    // Set current timer mode
    mb_port_set_cur_timer_mode(inst, MB_TMODE_CONVERT_DELAY);
    ESP_LOGD(TAG, "%s, convert delay enable.", inst->descr.parent_name);
    mb_port_timer_us(inst, tout_us);
}

void mb_port_timer_respond_timeout_enable(mb_port_base_t *inst)
{
    uint64_t tout_us = (inst->timer_obj->response_time_ms * 1000);

    mb_port_set_cur_timer_mode(inst, MB_TMODE_RESPOND_TIMEOUT);
    ESP_LOGD(TAG, "%s, respond enable timeout (%u).", 
                inst->descr.parent_name, (unsigned)mb_port_timer_get_response_time_ms(inst));
    mb_port_timer_us(inst, tout_us);
}

void mb_port_timer_delay(mb_port_base_t *inst, uint16_t timeout_ms)
{
    uint64_t tout_us = (timeout_ms * 1000);
    mb_port_timer_us(inst, tout_us);
}

void mb_port_timer_disable(mb_port_base_t *inst)
{
    // Disable timer alarm
    esp_err_t err = esp_timer_stop(inst->timer_obj->timer_handle);
    if (err != ESP_OK)
    {
        if (!esp_timer_is_active(inst->timer_obj->timer_handle))
        {
            ESP_EARLY_LOGD(TAG, "%s, timer stop, returns %d.", inst->descr.parent_name, (int)err);
        }
    }
}

void mb_port_timer_set_response_time(mb_port_base_t *inst, uint32_t resp_time_ms)
{
    atomic_store(&(inst->timer_obj->response_time_ms), resp_time_ms);
}

uint32_t mb_port_timer_get_response_time_ms(mb_port_base_t *inst)
{
    return atomic_load(&(inst->timer_obj->response_time_ms));
}
