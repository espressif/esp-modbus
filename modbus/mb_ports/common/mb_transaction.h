/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "esp_err.h"
#include "port_common.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define TRANSACTION_MEMORY MALLOC_CAP_DEFAULT

#define ESP_MEM_CHECK(TAG, a, action) if (!(a)) {                                                      \
        ESP_LOGE(TAG,"%s(%d): %s",  __FUNCTION__, __LINE__, "Memory exhausted"); \
        action;                                                                                         \
        }

struct transaction_item;

typedef struct transaction_t *transaction_handle_t;
typedef struct transaction_item *transaction_item_handle_t;

typedef struct transaction_message {
    uint8_t *buffer;
    uint16_t len;
    int msg_id;
    int node_id;
    void *pnode;
} transaction_message_t;

typedef struct transaction_message *transaction_message_handle_t;
typedef long long transaction_tick_t;

typedef enum pending_state {
    INIT,
    QUEUED,
    ACKNOWLEDGED,
    CONFIRMED,
    REPLIED,
    RECEIVED,
    TRANSMITTED,
    EXPIRED
} pending_state_t;

transaction_handle_t transaction_init(void);
transaction_item_handle_t transaction_enqueue(transaction_handle_t transaction, transaction_message_handle_t message, transaction_tick_t tick);
transaction_item_handle_t transaction_dequeue(transaction_handle_t transaction, pending_state_t pending, transaction_tick_t *tick);
transaction_item_handle_t transaction_get(transaction_handle_t transaction, int msg_id);
transaction_item_handle_t transaction_get_first(transaction_handle_t transaction);
uint8_t *transaction_item_get_data(transaction_item_handle_t item,  size_t *len, uint16_t *msg_id, int *node_id);
esp_err_t transaction_delete(transaction_handle_t transaction, int msg_id);
esp_err_t transaction_delete_item(transaction_handle_t transaction, transaction_item_handle_t item);
int transaction_delete_expired(transaction_handle_t transaction, transaction_tick_t current_tick, transaction_tick_t timeout);

/**
 * @brief Deletes single expired message returning it's message id
 *
 * @return msg id of the deleted message, -1 if no expired message in the transaction
 */
int transaction_delete_single_expired(transaction_handle_t transaction, transaction_tick_t current_tick, transaction_tick_t timeout);
esp_err_t transaction_set_state(transaction_handle_t transaction, int msg_id, pending_state_t pending);
pending_state_t transaction_item_get_state(transaction_item_handle_t item);
esp_err_t transaction_item_set_state(transaction_item_handle_t item, pending_state_t state);
esp_err_t transaction_set_tick(transaction_handle_t transaction, int msg_id, transaction_tick_t tick);
uint64_t transaction_get_size(transaction_handle_t transaction);
void transaction_destroy(transaction_handle_t transaction);
void transaction_delete_all_items(transaction_handle_t transaction);

#ifdef  __cplusplus
}
#endif

