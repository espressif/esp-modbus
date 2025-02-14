/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdatomic.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include "esp_timer.h"
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_err.h"

#include "mb_common.h"
#include "esp_modbus_common.h"
#include "mbc_slave.h"

#include "mb_common.h"
#include "port_common.h"
#include "mb_config.h"
#include "port_serial_common.h"
#include "port_adapter.h"
#include "mb_port_types.h"
#include "port_stubs.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* ----------------------- Defines ------------------------------------------*/

#define MB_ADAPTER_TASK_STACK_SIZE      (CONFIG_FMB_PORT_TASK_STACK_SIZE)
#define MB_ADAPTER_MAX_PORTS            (8)
#define MB_ADAPTER_RX_QUEUE_MAX_SIZE    (CONFIG_FMB_QUEUE_LENGTH * MB_ADAPTER_MAX_PORTS)
#define MB_ADAPTER_TX_QUEUE_MAX_SIZE    (CONFIG_FMB_QUEUE_LENGTH * MB_ADAPTER_MAX_PORTS)
#define MB_ADAPTER_QUEUE_TIMEOUT        (200 / portTICK_PERIOD_MS)
#define MB_ADAPTER_QUEUE_SET_MAX_LEN    ((sizeof(frame_entry_t) + sizeof(mb_uid_info_t)) * MB_ADAPTER_MAX_PORTS) //
#define MB_ADAPTER_CONN_TIMEOUT         (200 / portTICK_PERIOD_MS) 

typedef struct _mb_adapter_port_entry
{
    mb_port_base_t base;
    uint8_t rx_buffer[CONFIG_FMB_BUFFER_SIZE];
    uint16_t recv_length;
    uint64_t send_time_stamp;
    uint64_t recv_time_stamp;
    _Atomic(uint64_t) test_timeout_us;
    uint32_t flags;
    mb_uid_info_t addr_info;
    QueueHandle_t rx_queue;
    QueueHandle_t tx_queue;
    QueueHandle_t conn_queue;                   /*!< conection queue handle */
    SemaphoreHandle_t conn_sema_handle;         /*!< connection blocking semaphore handle */
    esp_timer_handle_t timer_handle;
    EventGroupHandle_t event_group_handle;
    LIST_ENTRY(_mb_adapter_port_entry) entries;
} mb_port_adapter_t;

/* ----------------------- Static variables & functions ----------------------*/
static const char *TAG = "mb_port.test_adapter";

static LIST_HEAD(mb_port_inst, _mb_adapter_port_entry) s_port_list = LIST_HEAD_INITIALIZER(s_port_list);
static uint32_t s_port_list_counter = 0; /*!< port registered instance counter */

// The queue set for the receive task
static QueueSetHandle_t queue_set = NULL;
static TaskHandle_t adapter_task_handle; /*!< receive task handle */

IRAM_ATTR
static bool mb_port_adapter_timer_expired(void *inst)
{
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);

    bool need_poll = false;
    mb_timer_mode_enum_t timer_mode = mb_port_get_cur_timer_mode(&port_obj->base);

    mb_port_timer_disable(&port_obj->base);

    switch (timer_mode)
    {
    case MB_TMODE_T35:
        need_poll = mb_port_event_post(&port_obj->base, EVENT(EV_READY));
        ESP_EARLY_LOGD(TAG, "%p:EV_READY", port_obj->base.descr.parent);
        break;

    case MB_TMODE_RESPOND_TIMEOUT:
        mb_port_event_set_err_type(&port_obj->base, EV_ERROR_RESPOND_TIMEOUT);
        need_poll = mb_port_event_post(&port_obj->base, EVENT(EV_ERROR_PROCESS));

        ESP_EARLY_LOGW(TAG, "%p:EV_ERROR_RESPOND_TIMEOUT", port_obj->base.descr.parent);
        break;

    case MB_TMODE_CONVERT_DELAY:
        /* If timer mode is convert delay, the master event then turns EV_MASTER_EXECUTE status. */
        need_poll = mb_port_event_post(&port_obj->base, EVENT(EV_EXECUTE));
        ESP_EARLY_LOGD(TAG, "%p:MB_TMODE_CONVERT_DELAY", port_obj->base.descr.parent);
        break;

    default:
        need_poll = mb_port_event_post(&port_obj->base, EVENT(EV_READY));
        break;
    }

    return need_poll;
}

void mb_port_adapter_set_response_time(mb_port_base_t *inst, uint64_t resp_time)
{
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    atomic_store(&(port_obj->test_timeout_us), resp_time);
}

int mb_port_adapter_get_rx_buffer(mb_port_base_t *inst, uint8_t **ppfame, int *plen)
{
    MB_RETURN_ON_FALSE((ppfame && plen), -1, TAG, "mb serial get buffer failure.");
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    int sz = port_obj->recv_length;
    if (*ppfame && *plen >= port_obj->recv_length)
    {
        CRITICAL_SECTION(inst->lock)
        {
            memcpy(*ppfame, port_obj->rx_buffer, sz);
        }
    }
    else
    {
        *ppfame = port_obj->rx_buffer;
        *plen = sz;
    }
    return sz;
}

int mb_port_adapter_get_tx_buffer(mb_port_base_t *inst, uint8_t **ppfame, int *plen)
{
    MB_RETURN_ON_FALSE((ppfame && plen), -1, TAG, "mb serial get buffer failure.");
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    int sz = port_obj->recv_length;
    if (*ppfame && *plen >= port_obj->recv_length)
    {
        CRITICAL_SECTION(inst->lock)
        {
            memcpy(*ppfame, port_obj->rx_buffer, sz);
        }
    }
    else
    {
        *ppfame = port_obj->rx_buffer;
        *plen = sz;
    }
    return sz;
}

void mb_port_adapter_set_flag(mb_port_base_t *inst, mb_queue_flags_t mask)
{
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    EventBits_t bits = xEventGroupSetBits(port_obj->event_group_handle, (EventBits_t)mask);
    ESP_LOGV(TAG, "%s: set flag (0x%x).", inst->descr.parent_name, (int)bits);
}

void mb_port_adapter_clear_flag(mb_port_base_t *inst, mb_queue_flags_t mask)
{
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    EventBits_t bits = xEventGroupClearBits(port_obj->event_group_handle, (EventBits_t)mask);
    ESP_LOGV(TAG, "%s: clear flag (0x%x).", inst->descr.parent_name, (int)bits);
}

uint16_t mb_port_adapter_wait_flag(mb_port_base_t *inst, uint16_t mask, uint32_t timeout)
{
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    EventBits_t bits = xEventGroupWaitBits(port_obj->event_group_handle, // The event group being tested.
                                            (EventBits_t)mask,           // The bits within the event group to wait for.
                                            pdTRUE,                      // Masked bits should be cleared before returning.
                                            pdFALSE,                     // Don't wait for both bits, either bit will do.
                                            (TickType_t)timeout);        // Wait during timeout for either bit to be set.
    ESP_LOGV(TAG, "%s: get flag (0x%x).", inst->descr.parent_name, (int)bits);
    return (uint16_t)bits;
}

// Timer task to send notification on timeout expiration
IRAM_ATTR 
static void mb_port_adapter_timer_cb(void *param)
{
    mb_port_adapter_t *port_obj = __containerof(param, mb_port_adapter_t, base);
    uint8_t temp_buffer[CONFIG_FMB_BUFFER_SIZE] = {0};
    mb_port_adapter_t *it;

    if (!LIST_EMPTY(&s_port_list))
    {
        // send the queued frame to all registered ports with the same port number
        int sz = queue_pop(port_obj->tx_queue, (void *)&temp_buffer[0], CONFIG_FMB_BUFFER_SIZE, NULL);
        LIST_FOREACH(it, &s_port_list, entries)
        {
            if (it && (it != port_obj) &&
                (port_obj->addr_info.port == it->addr_info.port) && (sz != -1)
                && (port_obj->addr_info.proto == it->addr_info.proto)
                && (!port_obj->addr_info.uid || !it->addr_info.uid))
            {
                // Send the data to all ports with the same communication port setting except itself
                queue_push(it->rx_queue, (void *)&temp_buffer[0], sz, NULL);
                mb_port_adapter_set_flag(&port_obj->base, MB_QUEUE_FLAG_SENT);
                ESP_LOGD(TAG, "Send (%d bytes) from %s to %s. ", (int)sz, port_obj->base.descr.parent_name, it->base.descr.parent_name);
            }
        }
    }
}

bool mb_port_adapter_is_connected(void *inst)
{
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    if (queue_is_empty(port_obj->conn_queue) 
            && port_obj->base.descr.is_master) {
        return true;
    }
    return false;
}

static void mb_port_adapter_conn_logic(void *inst, mb_uid_info_t *paddr_info)
{
    bool slave_found = false;
    mb_port_adapter_t *slave = NULL;
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);

    if (port_obj->base.descr.is_master) { // master object
        LIST_FOREACH(slave, &s_port_list, entries) {
            if ((paddr_info->uid == slave->addr_info.uid) 
                    && !slave->base.descr.is_master
                    && (paddr_info->port == slave->addr_info.port)) {
                // Register each slave object
                ESP_LOGD(TAG, "Check connection state of object #%d(%s), uid: %d, port: %d, %s",
                            paddr_info->index, paddr_info->node_name_str, 
                            paddr_info->uid, paddr_info->port, 
                            (paddr_info->state == MB_SOCK_STATE_CONNECTED) ? "CONNECTED" : "DISCONNECTED");
                if ((paddr_info->state != MB_SOCK_STATE_CONNECTED) || (paddr_info->inst != inst)) {
                    (void)xQueueSend(slave->conn_queue, &port_obj->addr_info, MB_ADAPTER_QUEUE_TIMEOUT);
                } else {
                    mb_port_adapter_set_flag(inst, MB_QUEUE_FLAG_CONNECTED);
                }                          
                slave_found = true;
                break;
            }
        }
        if (!slave_found) {
            // reactivate the connection set
            ESP_LOGE(TAG, "Slave #%d(%s), uid: %d, port: %d is not found, reconnect.",
                            paddr_info->index, paddr_info->node_name_str, paddr_info->uid, paddr_info->port);
            (void)xQueueSend(port_obj->conn_queue, paddr_info, MB_ADAPTER_QUEUE_TIMEOUT);
            vTaskDelay(MB_ADAPTER_CONN_TIMEOUT);
        }
    } else { // slave connection logic
        ESP_LOGD(TAG, "Register connection in adapter object #%d(%s), uid: %d, port: %d, to master %s",
                    port_obj->addr_info.index, port_obj->addr_info.node_name_str, 
                    port_obj->addr_info.uid, port_obj->addr_info.port, paddr_info->node_name_str);
        // Mimic connection logic for each slave here
        //mb_port_adapter_slave_connect(it);
        port_obj->addr_info.state = MB_SOCK_STATE_CONNECTED;
        mb_port_adapter_t *master = (mb_port_adapter_t *)(paddr_info->inst);
        port_obj->addr_info.inst = paddr_info->inst; // link slave with master
        (void)xQueueSend(master->conn_queue, &port_obj->addr_info, MB_ADAPTER_QUEUE_TIMEOUT);
    }
}

// UART receive event task
static void mb_port_adapter_task(void *p_args)
{
    QueueSetMemberHandle_t active_queue = NULL;
    mb_port_adapter_t *it = NULL;
    mb_uid_info_t addr_info;
    frame_entry_t frame_entry;

    while (1)
    {
        if (!LIST_EMPTY(&s_port_list))
        {
            active_queue = xQueueSelectFromSet(queue_set, MB_ADAPTER_QUEUE_TIMEOUT);
            LIST_FOREACH(it, &s_port_list, entries)
            {
                if (it && active_queue && (it->rx_queue == active_queue)) {
                    if (xQueuePeek(it->rx_queue, &frame_entry, 0) == pdTRUE) {
                        it->recv_length = frame_entry.len;
                        mb_port_event_post(&it->base, EVENT(EV_FRAME_RECEIVED, frame_entry.len, NULL, 0));
                        ESP_LOGD(TAG, "%s, frame %d bytes is ready.", (it->base.descr.parent_name), (int)frame_entry.len);
                    }
                } else if (it && (it->conn_queue == active_queue)) {
                    if (xQueueReceive(it->conn_queue, &addr_info, MB_ADAPTER_QUEUE_TIMEOUT) == pdTRUE) {
                        mb_port_adapter_conn_logic(it, &addr_info);
                    }
                }
            }
        }
        else
        {
            vTaskDelay(1);
        }
    }
    vTaskDelete(NULL);
}

static mb_err_enum_t mb_port_adapter_connect(mb_tcp_opts_t *tcp_opts, void *pobject)
{
    char **paddr_table = tcp_opts->ip_addr_table;
    mb_uid_info_t uid_info;
    mb_port_adapter_t *port_obj = __containerof(pobject, mb_port_adapter_t, base);

    MB_RETURN_ON_FALSE((paddr_table && *paddr_table && (tcp_opts->mode == MB_TCP)),
                        MB_EINVAL, TAG,
                        "%s, invalid address table.", port_obj->base.descr.parent_name);
    int count = 0;
    while (*paddr_table)
    {
        int res = port_scan_addr_string((char *)*paddr_table, &uid_info);
        if (res > 0)
        {
            ESP_LOGD(TAG, "Config: %s, IP: %s, port: %d, slave_addr: %d, ip_ver: %s",
                        (char *)*paddr_table, uid_info.ip_addr_str, uid_info.port,
                        uid_info.uid, (uid_info.addr_type == MB_IPV4 ? "IPV4" : "IPV6"));
            uid_info.index = count++;
            free(uid_info.ip_addr_str);
            uid_info.ip_addr_str = (char *)*paddr_table;
            uid_info.node_name_str = uid_info.ip_addr_str;
            if (xQueueSend(port_obj->conn_queue, &uid_info, MB_EVENT_QUEUE_TIMEOUT_MAX) != pdTRUE)
            {
                ESP_LOGE(TAG, "can not send info to connection queue.");
            };
            // Mimic connection event
            if (!tcp_opts->start_disconnected) {
                uint16_t event = mb_port_adapter_wait_flag(pobject, MB_QUEUE_FLAG_CONNECTED, MB_ADAPTER_CONN_TIMEOUT);
                if (!event) {
                    ESP_LOGE(TAG, "Could not connect to slave %s during timeout.", (char *)*paddr_table);
                }
            }
        }
        else
        {
            ESP_LOGE(TAG, "unable to open slave: %s, check configuration.", (char *)*paddr_table);
        }
        paddr_table++;
    }
    ESP_LOGD(TAG, "parsed and added %d slave configurations.", count);
    return count ? MB_ENOERR : MB_EINVAL;
}

mb_err_enum_t mb_port_adapter_create(mb_uid_info_t *paddr_info, mb_port_base_t **in_out_obj)
{
    mb_port_adapter_t *padapter = NULL;
    mb_err_enum_t ret = MB_EILLSTATE;
    padapter = (mb_port_adapter_t *)calloc(1, sizeof(mb_port_adapter_t));

    MB_GOTO_ON_FALSE((padapter && paddr_info && in_out_obj), MB_EILLSTATE, error, TAG, "mb serial port creation error.");

    CRITICAL_SECTION_INIT(padapter->base.lock);
    padapter->base.descr = ((mb_port_base_t *)*in_out_obj)->descr;
    padapter->addr_info = *paddr_info;

    esp_timer_create_args_t timer_conf = {
        .callback = mb_port_adapter_timer_cb,
        .arg = padapter,
        .dispatch_method = ESP_TIMER_TASK,
        .name = padapter->base.descr.parent_name
    };
    // Create Modbus timer handlers for streams
    MB_GOTO_ON_ERROR(esp_timer_create(&timer_conf, &padapter->timer_handle),
                        error, TAG, "create input stream timer failed.");

    padapter->rx_queue = queue_create(MB_ADAPTER_RX_QUEUE_MAX_SIZE);
    MB_GOTO_ON_FALSE(padapter->rx_queue, MB_EILLSTATE, error, TAG, "create rx queue failed");
    padapter->tx_queue = queue_create(MB_ADAPTER_TX_QUEUE_MAX_SIZE);
    MB_GOTO_ON_FALSE(padapter->tx_queue, MB_EILLSTATE, error, TAG, "create tx queue failed");
    padapter->event_group_handle = xEventGroupCreate();
    MB_GOTO_ON_FALSE((padapter->event_group_handle), MB_EILLSTATE, error, TAG,
                        "%p, event group create error.", *in_out_obj);

    if (!s_port_list_counter)
    {
        // Create a task to handle UART events
        BaseType_t status = xTaskCreatePinnedToCore(mb_port_adapter_task, "adapt_rx_task",
                                                    MB_ADAPTER_TASK_STACK_SIZE,
                                                    &padapter->base, CONFIG_FMB_PORT_TASK_PRIO,
                                                    &adapter_task_handle, CONFIG_FMB_PORT_TASK_AFFINITY);
        // Force exit from function with failure
        MB_GOTO_ON_FALSE((status == pdPASS), MB_EILLSTATE, error, TAG,
                            "serial task creation error, returned (0x%x).", (int)status);
        // Create the queue set to handle clients
        queue_set = xQueueCreateSet(MB_ADAPTER_QUEUE_SET_MAX_LEN);
        MB_GOTO_ON_FALSE((queue_set), MB_EILLSTATE, error, TAG, "can not create queue set.");
    }
    // Add connection set for master object only
    padapter->conn_queue = xQueueCreate(MB_ADAPTER_MAX_PORTS, sizeof(mb_uid_info_t));
    MB_GOTO_ON_FALSE(padapter->conn_queue, MB_EILLSTATE, error, TAG, "create conn queue failed");
    MB_GOTO_ON_FALSE((queue_set && xQueueAddToSet(padapter->conn_queue, queue_set)),
                        MB_EILLSTATE, error, TAG, "can not add conn queue to queue set.");
    // Add rx queue to set
    MB_GOTO_ON_FALSE((queue_set && xQueueAddToSet(padapter->rx_queue, queue_set)),
                        MB_EILLSTATE, error, TAG, "can not add rx queue to queue set.");

    MB_GOTO_ON_FALSE((s_port_list_counter <= MB_ADAPTER_MAX_PORTS), MB_EILLSTATE, error,
                        TAG, "adapter exceeded maximum number of ports = %d", MB_ADAPTER_MAX_PORTS);

    // register new port instance in the list
    LIST_INSERT_HEAD(&s_port_list, padapter, entries);
    s_port_list_counter++;
    char *pstr;
    int res = asprintf(&pstr, "%d;%s;%u", (unsigned)paddr_info->uid,
                        padapter->base.descr.parent_name, (unsigned)paddr_info->port);
    MB_GOTO_ON_FALSE((res), MB_EILLSTATE, error,
                        TAG, "object adress info alloc fail, err: %d", (int)res);
    padapter->base.cb.tmr_expired = mb_port_adapter_timer_expired;
    padapter->base.cb.tx_empty = NULL;
    padapter->base.cb.byte_rcvd = NULL;
    padapter->base.arg = (void *)padapter;

    padapter->addr_info.state = MB_SOCK_STATE_CONNECTING;
    padapter->addr_info.inst = padapter;
    padapter->addr_info.node_name_str = pstr;
    padapter->addr_info.ip_addr_str = pstr;
    *in_out_obj = &(padapter->base);
    ESP_LOGD(TAG, "created object @%p, from parent %p", padapter, padapter->base.descr.parent);
    return MB_ENOERR;

error:
    if (padapter) {
        mb_port_adapter_delete(&padapter->base);
    }
    return ret;
}

mb_err_enum_t mb_port_adapter_tcp_create(mb_tcp_opts_t *tcp_opts, mb_port_base_t **in_out_obj)
{
    mb_uid_info_t addr_info = {
        .ip_addr_str = NULL,
        .index = s_port_list_counter,
        .addr_type = MB_IPV4,
        .uid = tcp_opts->uid,
        .port = tcp_opts->port,
        .proto = MB_TCP,
        .state = MB_SOCK_STATE_UNDEF
    };

    mb_port_base_t *pobj = *in_out_obj;
    mb_err_enum_t ret = mb_port_adapter_create(&addr_info, &pobj);

    if ((ret == MB_ENOERR) && pobj) {
        // Parse master config and register dependent objects
        if (pobj->descr.is_master) {
            ESP_LOGI(TAG, "Parsing of config for %s", pobj->descr.parent_name);
            ret |= mb_port_adapter_connect(tcp_opts, pobj);
            MB_GOTO_ON_FALSE((ret == MB_ENOERR), MB_EILLSTATE, error, TAG, 
                                "%s, could not parse config, err=%x.", pobj->descr.parent_name, (int)ret);
        }
        ESP_LOGD(TAG, "%s, set test time to %" PRIu64, pobj->descr.parent_name, tcp_opts->test_tout_us);
        mb_port_adapter_set_response_time(pobj, (tcp_opts->test_tout_us));
    }
    *in_out_obj = pobj;
    return ret;

error:
    if (pobj) {
        mb_port_adapter_delete(pobj);
    }
    return ret;
}


#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

mb_err_enum_t mb_port_adapter_ser_create(mb_serial_opts_t *ser_opts, mb_port_base_t **in_out_obj)
{
    mb_uid_info_t addr_info = {
        .ip_addr_str = NULL, // unknown
        .index = s_port_list_counter,
        .addr_type = MB_NOIP,
        .uid = ser_opts->uid,
        .port = ser_opts->port,
        .proto = ser_opts->mode,
        .state = MB_SOCK_STATE_UNDEF
    };

    mb_port_base_t *pobj = *in_out_obj;
    mb_err_enum_t ret = mb_port_adapter_create(&addr_info, &pobj);
    if ((ret == MB_ENOERR) && pobj) {
        ESP_LOGD(TAG, "%s, set test time to %d", pobj->descr.parent_name, (int)(ser_opts->test_tout_us));
        mb_port_adapter_set_response_time(pobj, (ser_opts->test_tout_us));
        *in_out_obj = pobj;
    }
    return ret;
}
#endif

void mb_port_adapter_delete(mb_port_base_t *inst)
{
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);

    if (port_obj->rx_queue && !queue_is_empty(port_obj->rx_queue))
    {
        queue_flush(port_obj->rx_queue);
    }
    if (port_obj->tx_queue && !queue_is_empty(port_obj->tx_queue))
    {
        queue_flush(port_obj->tx_queue);
    }
    if (port_obj && port_obj->event_group_handle)
    {
        vEventGroupDelete(port_obj->event_group_handle);
        port_obj->event_group_handle = NULL;
    }
    if (port_obj && port_obj->timer_handle)
    {
        esp_timer_stop(port_obj->timer_handle);
        esp_timer_delete(port_obj->timer_handle);
        port_obj->timer_handle = NULL;
    }
    CRITICAL_SECTION_CLOSE(inst->lock);
    LIST_REMOVE(port_obj, entries);
    if (s_port_list_counter)
    {
        atomic_store(&(s_port_list_counter), (s_port_list_counter - 1));
        if (queue_set && port_obj && port_obj->rx_queue)
        {
            xQueueRemoveFromSet(port_obj->rx_queue, queue_set);
        }
        if (port_obj && port_obj->conn_queue && queue_set)
        {
            xQueueRemoveFromSet(port_obj->conn_queue, queue_set);
        }
    }
    if (!s_port_list_counter) 
    {
        if (port_obj && adapter_task_handle) {
            vTaskDelete(adapter_task_handle);
            adapter_task_handle = NULL;
        }
        vQueueDelete(queue_set);
        queue_set = NULL;
    }
    if (port_obj && port_obj->rx_queue && port_obj->tx_queue) 
    {
        queue_delete(port_obj->rx_queue);
        queue_delete(port_obj->tx_queue);
        port_obj->rx_queue = NULL;
        port_obj->tx_queue = NULL;
    }
    if (port_obj && port_obj->conn_queue)
    {
        vQueueDelete(port_obj->conn_queue);
        port_obj->conn_queue = NULL;
    }
    if (port_obj && port_obj->addr_info.node_name_str)
    {
        free(port_obj->addr_info.node_name_str);
        port_obj->addr_info.node_name_str = NULL;
        port_obj->addr_info.ip_addr_str = NULL;
    }
    free(port_obj);
}

static esp_err_t mb_port_adapter_set_timer(mb_port_base_t *inst, uint64_t time_diff_us)
{
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    esp_timer_stop(port_obj->timer_handle);
    esp_err_t ret = esp_timer_start_once(port_obj->timer_handle, time_diff_us);
    MB_RETURN_ON_FALSE((ret == ESP_OK),
                        ESP_ERR_INVALID_STATE, TAG,
                        "%s, could not start timer, err=%x.", inst->descr.parent_name, (int)ret);
    return ESP_OK;
}

bool mb_port_adapter_recv_data(mb_port_base_t *inst, uint8_t **ppframe, uint16_t *plength)
{
    MB_RETURN_ON_FALSE((ppframe && plength), false, TAG, "mb serial get buffer failure.");
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    int length = *plength ? *plength : port_obj->recv_length;

    if (length)
    {
        CRITICAL_SECTION_LOCK(inst->lock);
        int length = queue_pop(port_obj->rx_queue, &port_obj->rx_buffer[0], CONFIG_FMB_BUFFER_SIZE, NULL);
        if (length)
        {
            mb_port_timer_disable(inst);
            ESP_LOGD(TAG, "%s, received data: %d bytes.", inst->descr.parent_name, length);
            // Stop timer because the new data is received
            // Store the timestamp of received frame
            port_obj->recv_time_stamp = esp_timer_get_time();
            *ppframe = &port_obj->rx_buffer[0];
            ESP_LOG_BUFFER_HEX_LEVEL(MB_STR_CAT(inst->descr.parent_name, ":PORT_RECV"), 
                                        (void *)&port_obj->rx_buffer[0], (uint16_t)length, ESP_LOG_DEBUG);
        }
        CRITICAL_SECTION_UNLOCK(inst->lock);
    }
    else
    {
        ESP_LOGE(TAG, "%s: junk data (%d bytes) received. ", inst->descr.parent_name, length);
    }
    *plength = length;
    return true;
}

bool mb_port_adapter_send_data(mb_port_base_t *inst, uint8_t address, uint8_t *pframe, uint16_t length)
{
    bool res = false;
    mb_port_adapter_t *port_obj = __containerof(inst, mb_port_adapter_t, base);
    uint64_t time_diff = atomic_load(&port_obj->test_timeout_us);

    if (pframe && length)
    {
        CRITICAL_SECTION_LOCK(inst->lock);
        esp_err_t err = queue_push(port_obj->tx_queue, (void *)pframe, length, NULL);
        CRITICAL_SECTION_UNLOCK(inst->lock);
        MB_RETURN_ON_FALSE((err == ESP_OK),
                            false, TAG, "%s, could not send the data into queue.", inst->descr.parent_name);
        MB_RETURN_ON_FALSE((mb_port_adapter_set_timer(inst, time_diff) == ESP_OK),
                            false, TAG, "%s, could not set output timer.", inst->descr.parent_name);
        // Wait for send buffer complition
        uint16_t flags = mb_port_adapter_wait_flag(inst, MB_QUEUE_FLAG_SENT, MB_EVENT_QUEUE_TIMEOUT_MAX);
        port_obj->send_time_stamp = esp_timer_get_time();
        // Print sent packet, the tag used is more clear to see
        ESP_LOG_BUFFER_HEX_LEVEL(MB_STR_CAT(inst->descr.parent_name, ":PORT_SEND"),
                                    (void *)pframe, length, ESP_LOG_DEBUG);
        (void)mb_port_event_post(inst, EVENT(EV_FRAME_SENT));
        ESP_LOGD(TAG, "%s, tx completed, flags = 0x%04x.", inst->descr.parent_name, (int)flags);
        res = true;
        
    }
    else
    {
        ESP_LOGE(TAG, "send callback %p, %u. ", pframe, (unsigned)length);
    }
    return res;
}

void mb_port_adapter_enable(mb_port_base_t *inst)
{
    ESP_LOGD(TAG, "adapter tcp enable port.");
}

void mb_port_adapter_disable(mb_port_base_t *inst)
{
    ESP_LOGD(TAG, "adapter tcp disable port.");
}

mb_uid_info_t *mb_port_adapter_get_slave_info(mb_port_base_t *inst, uint8_t slave_addr, mb_sock_state_t exp_state)
{
    mb_port_adapter_t *it = NULL;

    if (!LIST_EMPTY(&s_port_list))
    {
        LIST_FOREACH(it, &s_port_list, entries)
        {
            if ((it->addr_info.uid == slave_addr) && (it->base.descr.is_master == false))
            {
                return (&it->addr_info);
            }
        }
    }
    return NULL;
}

void mb_port_adapter_tcp_set_conn_cb(mb_port_base_t *inst, void *conn_fp, void *arg)
{
    void (*on_conn_done_cb)(void *) = conn_fp;

    if (mb_port_adapter_is_connected(inst)) {
        if (on_conn_done_cb && arg) {
            on_conn_done_cb(arg);
        }
    }
}

#ifdef __cplusplus
}
#endif
