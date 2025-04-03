/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <string.h>
/*----------------------- Platform includes --------------------------------*/
#include "spinlock.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/portmacro.h"

#include "mb_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MB_SER_PDU_SIZE_MIN             (3)
#define MB_TIMER_TICS_PER_MS            (20UL)                         // Define number of timer reloads per 1 mS
#define MB_TIMER_TICK_TIME_US           (1000 / MB_TIMER_TICS_PER_MS) // 50uS = one discreet for timer
#define MB_EVENT_QUEUE_TIMEOUT_MAX_MS   (3000)
#define MB_EVENT_QUEUE_TIMEOUT          (pdMS_TO_TICKS(CONFIG_FMB_EVENT_QUEUE_TIMEOUT))
#define MB_EVENT_QUEUE_TIMEOUT_MAX      (pdMS_TO_TICKS(MB_EVENT_QUEUE_TIMEOUT_MAX_MS))
#define MB_MS_TO_TICKS(time_ms)         (pdMS_TO_TICKS(time_ms))

int lock_obj(_lock_t *plock);
void unlock_obj(_lock_t *plock);

#define CRITICAL_SECTION_INIT(lock)   \
    do                                \
    {                                 \
        _lock_init((_lock_t *)&lock); \
    } while (0)

#define CRITICAL_SECTION_CLOSE(lock)   \
    do                                 \
    {                                  \
        _lock_close((_lock_t *)&lock); \
    } while (0)

#define CRITICAL_SECTION_LOCK(lock) \
    do                              \
    {                               \
        lock_obj((_lock_t *)&lock); \
    } while (0)

#define CRITICAL_SECTION_UNLOCK(lock) \
    do                                \
    {                                 \
        unlock_obj((_lock_t *)&lock); \
    } while (0)

#define CRITICAL_SECTION(lock) for (int st = lock_obj((_lock_t *)&lock); (st > 0); unlock_obj((_lock_t *)&lock), st = -1)

#define SPIN_LOCK_INIT(lock)        \
    do                              \
    {                               \
        spinlock_initialize(&lock); \
    } while (0)

#define SPIN_LOCK_ENTER(lock)                           \
    do                                                  \
    {                                                   \
        spinlock_acquire(&lock, SPINLOCK_WAIT_FOREVER); \
    } while (0)

#define SPIN_LOCK_EXIT(lock)     \
    do                           \
    {                            \
        spinlock_release(&lock); \
    } while (0)

#define MB_EVENT_REQ_MASK (EventBits_t)(EV_MASTER_PROCESS_SUCCESS |       \
                                        EV_MASTER_ERROR_RESPOND_TIMEOUT | \
                                        EV_MASTER_ERROR_RECEIVE_DATA |    \
                                        EV_MASTER_ERROR_EXECUTE_FUNCTION)

#define MB_PORT_CHECK_EVENT(event, mask) (event & mask)
#define MB_PORT_CLEAR_EVENT(event, mask) \
    do                                   \
    {                                    \
        event &= ~mask;                  \
    } while (0)

// concatenation of the two arguments
#define PP_CAT2(_1, _2) PP_CAT_(_1, _2)
#define PP_CAT_(_1, _2) _1##_2

#define PP_VA_NUM_ARGS(...) PP_VA_NUM_ARGS_(__VA_ARGS__, 4, 3, 2, 1)
#define PP_VA_NUM_ARGS_(_1, _2, _3, _4, N, ...) N

// Initialization of event structure using variadic parameters
#define EVENT(...) PP_CAT2(EVENT_, PP_VA_NUM_ARGS(__VA_ARGS__))(__VA_ARGS__)

#define EVENT_1(_1) \
    (mb_event_t) { .event = _1 }
#define EVENT_2(_1, _2) \
    (mb_event_t) { .event = _1, .length = _2 }
#define EVENT_3(_1, _2, _3) \
    (mb_event_t) { .event = _1, .length = _2, .pdata = _3 }
#define EVENT_4(_1, _2, _3, _4) \
    (mb_event_t) { .event = _1, .length = _2, .pdata = _3, .type = _4 }

typedef struct mb_port_base_t mb_port_base_t;

typedef struct
{
    mb_port_base_t *mb_base;
} mb_common_iface_t;

//((mb_port_base_t *)(((mb_common_iface_t *)pctx)->mb_base)->lock);

#define MB_OBJ_GET_LOCK(pctx) (__extension__(                  \
{                                                          \
    assert((pctx));                                        \
    mb_common_iface_t *iface = (mb_common_iface_t *)pctx;  \
    ((_lock_t)((mb_port_base_t *)(iface->mb_base))->lock); \
}))

typedef bool (*mb_port_cb_fp)(void *arg);

//!< port callback table for interrupts
typedef struct
{
    mb_port_cb_fp byte_rcvd;
    mb_port_cb_fp tx_empty;
    mb_port_cb_fp tmr_expired;
} mb_port_cb_t;

typedef struct mb_port_event_t mb_port_event_t;
typedef struct mb_port_timer_t mb_port_timer_t;
typedef struct _obj_descr obj_descr_t;

typedef struct _frame_queue_entry
{
    uint16_t tid;  /*!< Transaction identifier (TID) for slave */
    uint16_t pid;  /*!< Protocol ID field of MBAP frame */
    uint16_t uid;  /*!< Slave unit ID (UID) field for MBAP frame  */
    uint8_t *pbuf; /*!< Points to the buffer for the frame */
    uint16_t len;  /*!< Length of the frame in the buffer */
    bool check;    /*!< Checked flag */
} frame_entry_t;

struct mb_port_base_t
{
    obj_descr_t descr;
    _lock_t lock;
    mb_port_cb_t cb; //!< Port callbacks.
    void *arg;       //!< CB arg pointer.

    mb_port_event_t *event_obj;
    mb_port_timer_t *timer_obj;
};

// Port event functions
mb_err_enum_t mb_port_event_create(mb_port_base_t *port_obj);
bool mb_port_event_post(mb_port_base_t *inst, mb_event_t event);
bool mb_port_event_get(mb_port_base_t *inst, mb_event_t *event);
bool mb_port_event_res_take(mb_port_base_t *inst, uint32_t timeout);
void mb_port_event_res_release(mb_port_base_t *inst);
void mb_port_event_set_resp_flag(mb_port_base_t *inst, mb_event_enum_t event_mask);
void mb_port_event_set_err_type(mb_port_base_t *inst, mb_err_event_t event);
mb_err_event_t mb_port_event_get_err_type(mb_port_base_t *inst);
void mb_port_event_delete(mb_port_base_t *inst);
mb_err_enum_t mb_port_event_wait_req_finish(mb_port_base_t *inst);
uint64_t mb_port_get_trans_id(mb_port_base_t *inst);

// Port timer functions
mb_err_enum_t mb_port_timer_create(mb_port_base_t *inst, uint16_t t35_timer_ticks);
void mb_port_timer_disable(mb_port_base_t *inst);
void mb_port_timer_enable(mb_port_base_t *inst);
void mb_port_timer_respond_timeout_enable(mb_port_base_t *inst);
void mb_port_timer_convert_delay_enable(mb_port_base_t *inst);
void mb_port_set_cur_timer_mode(mb_port_base_t *inst, mb_timer_mode_enum_t tmr_mode);
mb_timer_mode_enum_t mb_port_get_cur_timer_mode(mb_port_base_t *inst);
void mb_port_timer_set_response_time(mb_port_base_t *inst, uint32_t resp_time_ms);
uint32_t mb_port_timer_get_response_time_ms(mb_port_base_t *inst);
void mb_port_timer_delay(mb_port_base_t *inst, uint16_t timeout_ms);
void mb_port_timer_delete(mb_port_base_t *inst);

// Common functions to track instance descriptors
void mb_port_set_inst_counter(uint32_t inst_counter);
uint32_t mb_port_get_inst_counter();
uint32_t mb_port_get_inst_counter_inc();
uint32_t mb_port_get_inst_counter_dec();

// Common queue functions
QueueHandle_t queue_create(int queue_size);
void queue_delete(QueueHandle_t queue);
void queue_flush(QueueHandle_t queue);
bool queue_is_empty(QueueHandle_t queue);
esp_err_t queue_push(QueueHandle_t queue, void *pbuf, size_t len, frame_entry_t *pframe);
ssize_t queue_pop(QueueHandle_t queue, void *pbuf, size_t len, frame_entry_t *pframe);


#ifdef __cplusplus
}
#endif