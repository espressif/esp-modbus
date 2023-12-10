/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

//#include <sys/queue.h>
#include <stdatomic.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_event.h"          // for esp event loop

#if __has_include("mdns.h")
#include "mdns.h"
#endif

#include "mb_frame.h"
#include "mb_config.h"

#include "port_tcp_utils.h"
#include "mb_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

#define MB_PORT_DEFAULT         (502)
#define INVALID_FD              (-1)
#define MB_EVENT_TOUT           (300 / portTICK_PERIOD_MS)
#define MB_CONN_TICK_TIMEOUT    (10 / portTICK_PERIOD_MS)

#define EVENT_HANDLER(handler_name) void handler_name(void *ctx, esp_event_base_t base, int32_t id, void *data)

#define MB_MAX_FDS                  (MB_TCP_PORT_MAX_CONN)
#define MB_RECONNECT_TIME_MS        (1000)
#define MB_RX_QUEUE_MAX_SIZE        (CONFIG_FMB_QUEUE_LENGTH)
#define MB_TX_QUEUE_MAX_SIZE        (CONFIG_FMB_QUEUE_LENGTH)
#define MB_EVENT_QUEUE_SZ           (CONFIG_FMB_QUEUE_LENGTH * MB_TCP_PORT_MAX_CONN)
#define MB_TASK_STACK_SZ            (CONFIG_FMB_PORT_TASK_STACK_SIZE)
#define MB_TASK_PRIO                (CONFIG_FMB_PORT_TASK_PRIO)
#define MB_PORT_TASK_AFFINITY       (CONFIG_FMB_PORT_TASK_AFFINITY)
#define MB_WAIT_DONE_MS             (5000)
#define MB_SELECT_WAIT_MS           (200)
#define MB_TCP_SEND_TIMEOUT_MS      (500)
#define MB_TCP_EVENT_LOOP_TICK_MS   (50)

#define MB_DRIVER_CONFIG_DEFAULT {              \
    .spin_lock = portMUX_INITIALIZER_UNLOCKED,  \
    .mb_tcp_task_handle = NULL,                 \
    .mb_slave_open_count = 0,                   \
    .curr_slave_index = 0,                      \
    .mb_proto = MB_TCP,                         \
    .network_iface_ptr = NULL,                  \
    .mb_slave_info = NULL,                      \
    .mb_slave_curr_info = NULL,                 \
    .close_done_sema = NULL,                    \
    .max_conn_sd = INVALID_FD,                  \
    .slave_conn_count = 0,                      \
    .event_fd = INVALID_FD,                     \
}

#define MB_EVENTFD_CONFIG() (esp_vfs_eventfd_config_t) { \
      .max_fds = MB_TCP_PORT_MAX_CONN \
};

typedef struct _port_driver port_driver_t;

#define MB_CHECK_FD_RANGE(fd) ((fd < MB_TCP_PORT_MAX_CONN) && (fd >= 0))

#define GET_CONFIG_PTR(ctx) (__extension__( \
{ \
    assert(ctx); \
    ((port_driver_t *)ctx); \
} \
))

#define MB_EVENT_TBL_IT(event)    {event, #event}

#define MB_EVENT_BASE(context) (__extension__( \
{ \
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(context); \
    (pdrv_ctx->loop_name) ? (esp_event_base_t)(pdrv_ctx->loop_name) : "UNK_BASE"; \
} \
))

#define MB_GET_SLAVE_STATE(pslave) (atomic_load(&((mb_slave_info_t *)pslave)->addr_info.state))

#define MB_SET_SLAVE_STATE(pslave, slave_state) do { \
    atomic_store(&(((mb_slave_info_t *)pslave)->addr_info.state), slave_state); \
} while(0)

typedef enum _mb_driver_event {
    MB_EVENT_READY = 0x0001,
    MB_EVENT_OPEN = 0x0002,
    MB_EVENT_RESOLVE = 0x0004,
    MB_EVENT_CONNECT = 0x0008,
    MB_EVENT_SEND_DATA = 0x0010,
    MB_EVENT_RECV_DATA = 0x0020,
    MB_EVENT_RECONNECT = 0x0040,
    MB_EVENT_CLOSE = 0x0080,
    MB_EVENT_TIMEOUT = 0x0100
} mb_driver_event_t;

typedef struct {
    mb_driver_event_t event;
    const char *msg;
} event_msg_t;

typedef union {
    struct {
        int32_t event_id;               /*!< an event */
        int32_t opt_fd;                 /*!< fd option for an event */
    };
    uint64_t val;
} mb_event_info_t;

// Post event to event loop and unblocks the select through the eventfd to handle the event loop run,
// So, the eventfd value keeps last event and its fd.
#define DRIVER_SEND_EVENT(ctx, event, fd) (__extension__( \
{ \
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx); \
    static mb_event_info_t event_info; \
    event_info.event_id = (int32_t)event; \
    event_info.opt_fd = fd; \
    (write_event((void *)pdrv_ctx, &event_info) > 0) ? event_info.event_id : -1; \
} \
))

typedef struct _mb_slave_info {
    int index;                          /*!< slave information index */
    int fd;                             /*!< slave global file descriptor */
    int sock_id;                        /*!< socket ID of slave */
    int error;                          /*!< socket error */
    int recv_err;                       /*!< socket receive error */
    mb_uid_info_t addr_info;            /*!< slave address info structure*/
    QueueHandle_t rx_queue;             /*!< receive response queue */
    QueueHandle_t tx_queue;             /*!< send request queue */
    int64_t send_time;                  /*!< send request time stamp */
    int64_t recv_time;                  /*!< receive response time stamp */
    uint16_t tid_counter;               /*!< transaction identifier (TID) for slave */
    uint16_t send_counter;              /*!< number of packets sent to slave during one session */
    uint16_t recv_counter;              /*!< number of packets received from slave during one session */
    bool is_blocking;                   /*!< slave blocking bit state saved */
} mb_slave_info_t;

typedef enum _mb_sync_event {
    MB_SYNC_EVENT_RECV_OK = 0x0001,
    MB_SYNC_EVENT_RECV_FAIL = 0x0002,
    MB_SYNC_EVENT_SEND_OK = 0x0003,
    MB_SYNC_EVENT_TOUT
} mb_sync_event_t;

typedef enum _mb_status_flags {
    MB_FLAG_DISCONNECTED = 0x0001,
    MB_FLAG_CONNECTED = 0x0002,
    MB_FLAG_SUSPEND = 0x0004,
    MB_FLAG_SHUTDOWN = 0x0008
} mb_status_flags_t;

typedef struct _driver_event_cbs {
    void (*on_conn_done_cb)(void *);
    void *arg;
    void (*mb_sync_event_cb)(void *, mb_sync_event_t);
    void *port_arg;
} mb_driver_event_cb_t;

/**
 * @brief Modbus slave addr list item for the master
 */
// typedef struct mb_uid_entry_s {
//     void* pinst;
//     mb_uid_info_t addr_info;
//     LIST_ENTRY(mb_uid_entry_s) entries;  /*!< The slave address entry */
// } mb_uid_entry_t;

/**
 * @brief Modbus driver context parameters
 *
 */
typedef struct _port_driver {
    void *parent;                               /*!< Parent object */
    portMUX_TYPE spin_lock;                     /*!< Driver spin lock */
    _lock_t lock;                               /*!< Driver semaphore mutex */
    bool is_registered;                         /*!< Driver is active flag */
    TaskHandle_t mb_tcp_task_handle;            /*!< Master TCP/UDP handling task handle */
    mb_comm_mode_t mb_proto;                    /*!< Master protocol type */
    void *network_iface_ptr;                    /*!< Master netif interface pointer */
    mb_slave_info_t **mb_slave_info;            /*!< Master information structure for each connected slave */
    uint16_t mb_slave_open_count;               /*!< Master count of connected slaves */
    mb_slave_info_t *mb_slave_curr_info;        /*!< Master current slave information */
    uint16_t curr_slave_index;                  /*!< Master current processing slave index */
    fd_set open_set;                            /*!< File descriptor set for opened slaves */
    fd_set conn_set;                            /*!< File descriptor set for connected slaves */
    EventGroupHandle_t status_flags_hdl;        /*!< Status bits to control nodes states */
    int max_conn_sd;                            /*!< Max file descriptor for connected slaves */
    int slave_conn_count;                       /*!< Number of connected slaves */
    SemaphoreHandle_t close_done_sema;          /*!< Close and done semaphore */
    int event_fd;                               /*!< eventfd descriptor for modbus event tracking */
    esp_event_loop_handle_t event_loop_hdl;     /*!< event loop handle */
    char *loop_name;                            /*!< name for event loop used as base */
    esp_event_handler_instance_t event_handler; /*!< event handler instance */
    mb_driver_event_cb_t event_cbs;
    //LIST_HEAD(mb_uid_info_, mb_uid_entry_s) slave_list; /*!< Slave address information list */
    uint16_t slave_list_count;
} port_driver_t;

/**
 * @brief Register modbus driver
 *
 * This function must be called prior usage of ESP-MODBUS Interface
 *
 * @param ctx - pointer to pointer of driver interface structure to be created.
 * @param config MODBUS virtual filesystem driver configuration. Default base path /dev/net/modbus/tcp is used when this paramenter is NULL.
 * @return esp_err_t
 *          - ESP_OK on success
 */
esp_err_t mbm_drv_register(port_driver_t **config);

/**
 * @brief Unregister modbus driver
 *
 * @param ctx - pointer to driver interface structure
 * @return esp_err_t
 *          - ESP_OK on success
 */
esp_err_t mbm_drv_unregister(void *ctx);

/**
 * @brief Start task of modbus driver
 *
 * @param ctx - pointer to driver interface structure
 * @return esp_err_t
 *          - ESP_OK on success
 */
esp_err_t mbm_drv_start_task(void *ctx);


/**
 * @brief Unregister modbus driver
 *
 * @param ctx - pointer to driver interface structure
 * @return esp_err_t
 *          - ESP_OK on success
 */
esp_err_t mbm_drv_stop_task(void *ctx);

/**
 * @brief get slave information structure from its short slave address
 *
 * This function must be called after initialization of ESP-MODBUS Interface
 *
 * @param uid - modbus slave address of the slave
 * @return mb_slave_info_t
 *          - Address of slave info structure on success
 *          - NULL, if the slave is not found
 */
mb_slave_info_t *mbm_drv_get_slave_info_from_addr(void *ctx, uint8_t uid);

int mbm_drv_open(void *ctx, mb_uid_info_t addr_info, int flags);

ssize_t mbm_drv_write(void *ctx, int fd, const void *data, size_t size);

ssize_t mbm_drv_read(void *ctx, int fd, void *data, size_t size);

int mbm_drv_close(void *ctx, int fd);

int32_t write_event(void *ctx, mb_event_info_t *pevent);

const char *driver_event_to_name_r(mb_driver_event_t event);

void mbm_drv_set_cb(void *ctx, void *conn_cb, void *arg);

mb_status_flags_t mbm_drv_wait_status_flag(void *ctx, mb_status_flags_t mask, uint32_t tout_ms);

EVENT_HANDLER(on_ready);
EVENT_HANDLER(on_open);
EVENT_HANDLER(on_connect);
EVENT_HANDLER(on_resolve);
EVENT_HANDLER(on_send_data);
EVENT_HANDLER(on_recv_data);
EVENT_HANDLER(on_reconnect);
EVENT_HANDLER(on_close);
EVENT_HANDLER(on_timeout);

#endif

#ifdef __cplusplus
}
#endif
