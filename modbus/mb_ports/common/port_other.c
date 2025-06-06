/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdatomic.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "sys/lock.h"

#include "port_common.h"

/* ----------------------- Variables ----------------------------------------*/
static _Atomic(uint32_t) inst_counter = 0;

/* ----------------------- Start implementation -----------------------------*/
int lock_obj(_lock_t *plock)
{
    _lock_acquire(plock);
    return 1;
}

void unlock_obj(_lock_t *plock)
{
    _lock_release(plock);
}

__attribute__((unused))
void mb_port_set_inst_counter(uint32_t counter)
{
    atomic_store(&inst_counter, counter);
}

__attribute__((unused))
uint32_t mb_port_get_inst_counter()
{
    return atomic_load(&inst_counter);
}

uint32_t mb_port_get_inst_counter_inc()
{
    return atomic_fetch_add(&inst_counter, 1);
}

uint32_t mb_port_get_inst_counter_dec()
{
    return atomic_fetch_sub(&inst_counter, 1);
}

QueueHandle_t queue_create(int queue_size)
{
    return xQueueCreate(queue_size, sizeof(frame_entry_t));
}

void queue_delete(QueueHandle_t queue)
{
    queue_flush(queue);
    vQueueDelete(queue);
}

esp_err_t queue_push(QueueHandle_t queue, void *pbuf, size_t len, frame_entry_t *pframe)
{
    frame_entry_t frame_info = {0};

    if (!queue) { // || !pbuf || (len <= 0)
        return -1;
    }

    if (pframe) {
        frame_info = *pframe;
    }

    if (pbuf && (len > 0)) {
        if (!frame_info.pbuf) {
            frame_info.pbuf = calloc(1, len);
        }
        if (!frame_info.pbuf) {
            return ESP_ERR_NO_MEM;
        }
        frame_info.len = len;
        memcpy(frame_info.pbuf, pbuf, len);
    }

    // try send to queue and check if the queue is full
    if (xQueueSend(queue, &frame_info, portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

ssize_t queue_pop(QueueHandle_t queue, void *pbuf, size_t len, frame_entry_t *pframe)
{
    TickType_t timeout = portMAX_DELAY;

    frame_entry_t frame_info = {0};

    if (xQueueReceive(queue, &frame_info, timeout) == pdTRUE) {
        if (pframe) {
            *pframe = frame_info;
        }
        if (len > frame_info.len) {
            len = frame_info.len;
        }
        // if the input buffer pointer is defined copy the data and free queued buffer,
        // otherwise just return the frame entry
        if (frame_info.pbuf && pbuf) {
            memcpy(pbuf, frame_info.pbuf, len);
            if (!pframe) {
                free(frame_info.pbuf); // must free the buffer manually!
            }
        }
    } else {
        goto err;
    }
    return len;
err:
    return -1;
}

bool queue_is_empty(QueueHandle_t queue)
{
    return (uxQueueMessagesWaiting(queue) == 0);
}

void queue_flush(QueueHandle_t queue)
{
    frame_entry_t frame_info;
    while (xQueueReceive(queue, &frame_info, 0) == pdTRUE) {
        if ((frame_info.len > 0) && frame_info.pbuf) {
            free(frame_info.pbuf);
        }
    }
}
