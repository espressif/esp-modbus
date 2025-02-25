#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include "sys/queue.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "mb_transaction.h"

static const char *TAG = "mb_transaction";

/**
 * @brief transaction list item
 */
typedef struct transaction_item {
    uint8_t *buffer;
    uint16_t len;
    int node_id;
    int msg_id;
    void *pnode;
    transaction_tick_t tick;
    _Atomic(int) state;
    STAILQ_ENTRY(transaction_item) next;
} transaction_item_t;

STAILQ_HEAD(transaction_list_t, transaction_item);

struct transaction_t {
    _lock_t lock;
    uint64_t size;
    struct transaction_list_t *list;
};

transaction_handle_t transaction_init(void)
{
    transaction_handle_t transaction = calloc(1, sizeof(struct transaction_t));
    ESP_MEM_CHECK(TAG, transaction, return NULL);
    transaction->list = calloc(1, sizeof(struct transaction_list_t));
    ESP_MEM_CHECK(TAG, transaction->list, {free(transaction); return NULL;});
    transaction->size = 0;
    CRITICAL_SECTION_INIT(transaction->lock);
    STAILQ_INIT(transaction->list);
    return transaction;
}

transaction_item_handle_t transaction_enqueue(transaction_handle_t transaction, transaction_message_handle_t message, transaction_tick_t tick)
{
    transaction_item_handle_t item = calloc(1, sizeof(transaction_item_t));
    ESP_MEM_CHECK(TAG, item, { 
        return NULL;
    });
    CRITICAL_SECTION_LOCK(transaction->lock);
    item->tick = tick;
    item->node_id = message->node_id;
    item->pnode = message->pnode;
    item->msg_id = message->msg_id;
    item->len =  message->len;
    item->state = QUEUED;
    if (!message->buffer) {
        item->buffer = heap_caps_malloc(message->len, TRANSACTION_MEMORY);
        memcpy(item->buffer, message->buffer, message->len);
    } else {
        item->buffer = message->buffer;
    }
    ESP_MEM_CHECK(TAG, item->buffer, {
        free(item);
        CRITICAL_SECTION_UNLOCK(transaction->lock);
        return NULL;
    });
    STAILQ_INSERT_TAIL(transaction->list, item, next);
    transaction->size += item->len;
    CRITICAL_SECTION_UNLOCK(transaction->lock);
    ESP_LOGD(TAG, "ENQUEUE msgid=%x, len=%d, size=%"PRIu64, message->msg_id, message->len, transaction_get_size(transaction));
    return item;
}

transaction_item_handle_t transaction_get(transaction_handle_t transaction, int msg_id)
{
    transaction_item_handle_t item;
    CRITICAL_SECTION_LOCK(transaction->lock);
    STAILQ_FOREACH(item, transaction->list, next) {
        if (item->msg_id == msg_id) {
            CRITICAL_SECTION_UNLOCK(transaction->lock);
            return item;
        }
    }
    CRITICAL_SECTION_UNLOCK(transaction->lock);
    return NULL;
}

transaction_item_handle_t transaction_get_first(transaction_handle_t transaction)
{
    transaction_item_handle_t item;
    if (STAILQ_EMPTY(transaction->list)) {
        return NULL;
    }
    
    item = STAILQ_FIRST(transaction->list); 
    if (item)
    {
        return item;
    }
    return NULL;
}

transaction_item_handle_t transaction_dequeue(transaction_handle_t transaction, pending_state_t state, transaction_tick_t *tick)
{
    transaction_item_handle_t item;
    CRITICAL_SECTION_LOCK(transaction->lock);
    STAILQ_FOREACH(item, transaction->list, next) {
        if (atomic_load(&(item->state)) == state) {
            if (tick) {
                *tick = item->tick;
            }
            CRITICAL_SECTION_UNLOCK(transaction->lock);
            return item;
        }
    }
    CRITICAL_SECTION_UNLOCK(transaction->lock);
    return NULL;
}

esp_err_t transaction_delete_item(transaction_handle_t transaction, transaction_item_handle_t item_to_delete)
{
    transaction_item_handle_t item;
    CRITICAL_SECTION_LOCK(transaction->lock);
    STAILQ_FOREACH(item, transaction->list, next) {
        if (item == item_to_delete) {
            STAILQ_REMOVE(transaction->list, item, transaction_item, next);
            transaction->size -= item->len;
            free(item->buffer);
            free(item);
            CRITICAL_SECTION_UNLOCK(transaction->lock);
            return ESP_OK;
        }
    }
    CRITICAL_SECTION_UNLOCK(transaction->lock);
    return ESP_FAIL;
}

uint8_t *transaction_item_get_data(transaction_item_handle_t item,  size_t *len, uint16_t *msg_id, int *node_id)
{
    if (item) {
        if (len) {
            *len = item->len;
        }
        if (msg_id) {
            *msg_id = item->msg_id;
        }
        if (node_id) {
            *node_id = item->node_id;
        }
        return (uint8_t *)item->buffer;
    }
    return NULL;
}

esp_err_t transaction_delete(transaction_handle_t transaction, int msg_id)
{
    transaction_item_handle_t item, tmp;
    CRITICAL_SECTION_LOCK(transaction->lock);
    STAILQ_FOREACH_SAFE(item, transaction->list, next, tmp) {
        if (item->msg_id == msg_id) {
            STAILQ_REMOVE(transaction->list, item, transaction_item, next);
            transaction->size -= item->len;
            free(item->buffer);
            free(item);
            CRITICAL_SECTION_UNLOCK(transaction->lock);
            ESP_LOGD(TAG, "DELETED msgid=%x, remain size=%"PRIu64, msg_id, transaction_get_size(transaction));
            return ESP_OK;
        }
    }
    CRITICAL_SECTION_UNLOCK(transaction->lock);
    return ESP_FAIL;
}

esp_err_t transaction_set_state(transaction_handle_t transaction, int msg_id, pending_state_t state)
{
    transaction_item_handle_t item = transaction_get(transaction, msg_id);
    if (item) {
        atomic_store(&(item->state), state);
        return ESP_OK;
    }
    return ESP_FAIL;
}

pending_state_t transaction_item_get_state(transaction_item_handle_t item)
{
    if (item) {
        return atomic_load(&(item->state));
    }
    return INIT;
}

esp_err_t transaction_item_set_state(transaction_item_handle_t item, pending_state_t state)
{
    if (item) {
        atomic_store(&(item->state), state);
        return ESP_OK;
    }
    return ESP_FAIL;
}

esp_err_t transaction_set_tick(transaction_handle_t transaction, int msg_id, transaction_tick_t tick)
{
    transaction_item_handle_t item = transaction_get(transaction, msg_id);
    if (item) {
        item->tick = tick;
        return ESP_OK;
    }
    return ESP_FAIL;
}

int transaction_delete_single_expired(transaction_handle_t transaction, transaction_tick_t current_tick, transaction_tick_t timeout)
{
    int msg_id = -1;
    transaction_item_handle_t item;
    CRITICAL_SECTION_LOCK(transaction->lock);
    STAILQ_FOREACH(item, transaction->list, next) {
        if (current_tick - item->tick > timeout) {
            STAILQ_REMOVE(transaction->list, item, transaction_item, next);
            free(item->buffer);
            transaction->size -= item->len;
            msg_id = item->msg_id;
            free(item);
            CRITICAL_SECTION_UNLOCK(transaction->lock);
            return msg_id;
        }

    }
    CRITICAL_SECTION_UNLOCK(transaction->lock);
    return msg_id;
}

int transaction_delete_expired(transaction_handle_t transaction, transaction_tick_t current_tick, transaction_tick_t timeout)
{
    int deleted_items = 0;
    transaction_item_handle_t item, tmp;
    CRITICAL_SECTION_LOCK(transaction->lock);
    STAILQ_FOREACH_SAFE(item, transaction->list, next, tmp) {
        if (current_tick - item->tick > timeout) {
            STAILQ_REMOVE(transaction->list, item, transaction_item, next);
            free(item->buffer);
            transaction->size -= item->len;
            free(item);
            deleted_items ++;
        }
    }
    CRITICAL_SECTION_UNLOCK(transaction->lock);
    return deleted_items;
}

uint64_t transaction_get_size(transaction_handle_t transaction)
{
    return transaction->size;
}

void transaction_delete_all_items(transaction_handle_t transaction)
{
    transaction_item_handle_t item, tmp;
    CRITICAL_SECTION_LOCK(transaction->lock);
    STAILQ_FOREACH_SAFE(item, transaction->list, next, tmp) {
        STAILQ_REMOVE(transaction->list, item, transaction_item, next);
        transaction->size -= item->len;
        free(item->buffer);
        free(item);
    }
    CRITICAL_SECTION_UNLOCK(transaction->lock);
}

void transaction_destroy(transaction_handle_t transaction)
{
    transaction_delete_all_items(transaction);
    CRITICAL_SECTION_CLOSE(transaction->lock);
    free(transaction->list);
    free(transaction);
}

