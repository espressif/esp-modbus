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

#define MB_PORT_DEFAULT         (CONFIG_FMB_TCP_PORT_DEFAULT)
#define UNDEF_FD                (-1)
#define MB_EVENT_TOUT           (300 / portTICK_PERIOD_MS)
#define MB_CONN_TICK_TIMEOUT    (10 / portTICK_PERIOD_MS)

typedef void (*mb_event_handler_fp)(void *ctx, esp_event_base_t base, int32_t id, void *data);
#define MB_EVENT_HANDLER(handler_name) void (handler_name)(void *ctx, esp_event_base_t base, int32_t id, void *data)

#define MB_TASK_STACK_SZ            (CONFIG_FMB_PORT_TASK_STACK_SIZE)
#define MB_TASK_PRIO                (CONFIG_FMB_PORT_TASK_PRIO)
#define MB_PORT_TASK_AFFINITY       (CONFIG_FMB_PORT_TASK_AFFINITY)

#define MB_MAX_FDS                  (MB_TCP_PORT_MAX_CONN)
#define MB_RETRY_CNT                (2)
#define MB_RX_QUEUE_MAX_SIZE        (CONFIG_FMB_QUEUE_LENGTH)
#define MB_TX_QUEUE_MAX_SIZE        (CONFIG_FMB_QUEUE_LENGTH)
#define MB_EVENT_QUEUE_SZ           (CONFIG_FMB_QUEUE_LENGTH * MB_TCP_PORT_MAX_CONN)

#define MB_WAIT_DONE_MS             (5000)
#define MB_SELECT_WAIT_MS           (200)
#define MB_TCP_SEND_TIMEOUT_MS      (500)
#define MB_TCP_EVENT_LOOP_TICK_MS   (50)

#define MB_DRIVER_CONFIG_DEFAULT {              \
    .spin_lock = portMUX_INITIALIZER_UNLOCKED,  \
    .listen_sock_fd = UNDEF_FD,                 \
    .retry_cnt = MB_RETRY_CNT,                  \
    .mb_tcp_task_handle = NULL,                 \
    .mb_node_open_count = 0,                    \
    .curr_node_index = 0,                       \
    .mb_proto = MB_TCP,                         \
    .network_iface_ptr = NULL,                  \
    .dns_name = NULL,                           \
    .mb_nodes = NULL,                           \
    .mb_node_curr = NULL,                       \
    .close_done_sema = NULL,                    \
    .node_conn_count = 0,                       \
    .event_fd = UNDEF_FD,                       \
}

#define MB_EVENTFD_CONFIG() (esp_vfs_eventfd_config_t) {    \
      .max_fds = MB_TCP_PORT_MAX_CONN                       \
};

typedef struct _port_driver port_driver_t;

#define MB_CHECK_FD_RANGE(fd) ((fd < MB_TCP_PORT_MAX_CONN) && (fd >= 0))

#define MB_GET_DRV_PTR(ctx) (__extension__( \
{                                           \
    assert(ctx);                            \
    ((port_driver_t *)ctx);                 \
}                                           \
))

#define MB_EVENT_TBL_IT(event)    {event, #event}

#define MB_EVENT_BASE(context) (__extension__(                                      \
{                                                                                   \
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(context);                              \
    (pdrv_ctx->loop_name) ? (esp_event_base_t)(pdrv_ctx->loop_name) : "UNK_BASE";   \
}                                                                                   \
))

#define MB_ADD_FD(fd, max_fd, pfdset) do {      \
    if (fd) {                                   \
        (max_fd = (fd > max_fd) ? fd : max_fd); \
        FD_SET(fd, pfdset);                     \
    }                                           \
} while(0)


// Macro for atomic operations
#define MB_ATOMIC_LOAD(ctx, addr) (__extension__(   \
{                                                   \
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);  \
    (CRITICAL_LOAD(pdrv_ctx->lock, addr));          \
}                                                   \
))

#define MB_ATOMIC_STORE(ctx, addr, val) (__extension__( \
{                                                       \
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);      \
    CRITICAL_STORE(pdrv_ctx->lock, addr, val);          \
}                                                       \
))

// Post event to event loop and unblocks the select through the eventfd to handle the event loop run,
// So, the eventfd value keeps last event and its fd.
#define DRIVER_SEND_EVENT(ctx, event, fd) (__extension__(                               \
{                                                                                       \
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);                                      \
    mb_event_info_t (event_info##__FUNCTION__##__LINE__);                               \
    (event_info##__FUNCTION__##__LINE__).event_id = (int32_t)event;                     \
    (event_info##__FUNCTION__##__LINE__).opt_fd = fd;                                   \
    ((write_event((void *)pdrv_ctx, &(event_info##__FUNCTION__##__LINE__)) > 0)         \
                    ? ((event_info##__FUNCTION__##__LINE__)).event_id : UNDEF_FD);      \
}                                                                                       \
))

#define MB_GET_NODE_STATE(pnode) (atomic_load(&((mb_node_info_t *)pnode)->addr_info.state))

#define MB_SET_NODE_STATE(pnode, node_state) do {                               \
    atomic_store(&(((mb_node_info_t *)pnode)->addr_info.state), node_state);    \
} while(0)

#define MB_EVENT_FROM_NUM(event_num) ((mb_driver_event_t)(1 << (event_num)))

typedef enum _mb_event_num {
    MB_EVENT_READY_NUM = 0,
    MB_EVENT_OPEN_NUM = 1,
    MB_EVENT_RESOLVE_NUM = 2,
    MB_EVENT_CONNECT_NUM = 3,
    MB_EVENT_SEND_DATA_NUM = 4,
    MB_EVENT_RECV_DATA_NUM = 5,
    MB_EVENT_ERROR_NUM = 6,
    MB_EVENT_CLOSE_NUM = 7,
    MB_EVENT_TIMEOUT_NUM = 8,
    MB_EVENT_COUNT = 9
} mb_driver_event_num_t;

typedef enum _mb_driver_event {
    MB_EVENT_READY = (1 << MB_EVENT_READY_NUM),
    MB_EVENT_OPEN = (1 << MB_EVENT_OPEN_NUM),
    MB_EVENT_RESOLVE = (1 << MB_EVENT_RESOLVE_NUM),
    MB_EVENT_CONNECT = (1 << MB_EVENT_CONNECT_NUM),
    MB_EVENT_SEND_DATA = (1 << MB_EVENT_SEND_DATA_NUM),
    MB_EVENT_RECV_DATA = (1 << MB_EVENT_RECV_DATA_NUM),
    MB_EVENT_ERROR = (1 << MB_EVENT_ERROR_NUM),
    MB_EVENT_CLOSE = (1 << MB_EVENT_CLOSE_NUM),
    MB_EVENT_TIMEOUT =(1 << MB_EVENT_TIMEOUT_NUM)
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

typedef struct _mb_node_info {
    int index;                          /*!< slave information index */
    int fd;                             /*!< slave global file descriptor */
    int sock_id;                        /*!< socket ID of slave */
    mb_uid_info_t addr_info;            /*!< slave address info structure*/
    int error;                          /*!< socket error */
    int recv_err;                       /*!< socket receive error */
    QueueHandle_t rx_queue;             /*!< receive response queue */
    QueueHandle_t tx_queue;             /*!< send request queue */
    int64_t send_time;                  /*!< send request time stamp */
    int64_t recv_time;                  /*!< receive response time stamp */
    uint16_t tid_counter;               /*!< transaction identifier (TID) for slave */
    uint16_t send_counter;              /*!< number of packets sent to slave during one session */
    uint16_t recv_counter;              /*!< number of packets received from slave during one session */
    bool is_blocking;                   /*!< slave blocking bit state saved */
} mb_node_info_t;

typedef enum _mb_sync_event {
    MB_SYNC_EVENT_RECV_OK = 0x0001,
    MB_SYNC_EVENT_RECV_FAIL = 0x0002,
    MB_SYNC_EVENT_SEND_OK = 0x0003,
    MB_SYNC_EVENT_TOUT
} mb_sync_event_t;

typedef enum _mb_status_flags {
    MB_FLAG_BLANK = 0x0000,
    MB_FLAG_TRANSACTION_DONE = 0x0001,
    MB_FLAG_DISCONNECTED = 0x0002,
    MB_FLAG_CONNECTED = 0x0004,
    MB_FLAG_SUSPEND = 0x0008,
    MB_FLAG_SHUTDOWN = 0x0010
} mb_status_flags_t;

typedef struct _driver_event_cbs {
    void (*on_conn_done_cb)(void *);
    void *arg;
    uint64_t (*mb_sync_event_cb)(void *, mb_sync_event_t);
    void *port_arg;
} mb_driver_event_cb_t;

/**
 * @brief Modbus driver context parameters
 *
 */
typedef struct _port_driver {
    void *parent;                               /*!< parent object pointer */
    char *dns_name;                             /*!< DNS name of the object */
    portMUX_TYPE spin_lock;                     /*!< spin lock */
    _lock_t lock;                               /*!< semaphore mutex */
    bool is_registered;                         /*!< driver is active flag */
    int listen_sock_fd;                         /*!< listen socket fd */
    int retry_cnt;                              /*!< retry counter for events */
    mb_comm_mode_t mb_proto;                    /*!< current node protocol type */
    uint16_t port;                              /*!< current node port number */
    uint8_t uid;                                /*!< unit identifier of the node */
    bool is_master;                             /*!< identify the type of instance (master, slave) */
    void *network_iface_ptr;                    /*!< netif interface pointer */
    mb_node_info_t **mb_nodes;                  /*!< information structures for each associated node */
    uint16_t mb_node_open_count;                /*!< count of associated nodes */
    uint16_t node_conn_count;                   /*!< number of associated nodes */
    mb_node_info_t *mb_node_curr;               /*!< current slave information */
    uint16_t curr_node_index;                   /*!< current processing slave index */
    fd_set open_set;                            /*!< file descriptor set for opened nodes */
    fd_set conn_set;                            /*!< file descriptor set for associated nodes */
    int event_fd;                               /*!< eventfd descriptor for modbus event tracking */
    SemaphoreHandle_t close_done_sema;          /*!< close and done semaphore */
    EventGroupHandle_t status_flags_hdl;        /*!< status bits to control nodes states */
    TaskHandle_t mb_tcp_task_handle;            /*!< TCP/UDP handling task handle */
    esp_event_loop_handle_t event_loop_hdl;     /*!< event loop handle */
    esp_event_handler_instance_t event_handler[MB_EVENT_COUNT]; /*!< event handler instance */
    char *loop_name;                            /*!< name for event loop used as base */
    mb_driver_event_cb_t event_cbs;
    //LIST_HEAD(mb_uid_info_, mb_uid_entry_s) node_list; /*!< node address information list */
    //uint16_t node_list_count;
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
esp_err_t mb_drv_register(port_driver_t **config);

/**
 * @brief Unregister modbus driver
 *
 * @param ctx - pointer to driver interface structure
 * @return esp_err_t
 *          - ESP_OK on success
 */
esp_err_t mb_drv_unregister(void *ctx);

/**
 * @brief Start task of modbus driver
 *
 * @param ctx - pointer to driver interface structure
 * @return esp_err_t
 *          - ESP_OK on success
 */
esp_err_t mb_drv_start_task(void *ctx);


/**
 * @brief Unregister modbus driver
 *
 * @param ctx - pointer to driver interface structure
 * @return esp_err_t
 *          - ESP_OK on success
 */
esp_err_t mb_drv_stop_task(void *ctx);

/**
 * @brief get slave information structure from its short slave address
 *
 * This function must be called after initialization of ESP-MODBUS Interface
 *
 * @param uid - modbus slave address of the slave
 * @return mb_node_info_t
 *          - Address of slave info structure on success
 *          - NULL, if the slave is not found
 */
mb_node_info_t *mb_drv_get_node_info_from_addr(void *ctx, uint8_t uid);

mb_node_info_t *mb_drv_get_node(void *ctx, int fd);

mb_sock_state_t mb_drv_get_node_state(void *ctx, int fd);

int mb_drv_open(void *ctx, mb_uid_info_t addr_info, int flags);

ssize_t mb_drv_write(void *ctx, int fd, const void *data, size_t size);

ssize_t mb_drv_read(void *ctx, int fd, void *data, size_t size);

int mb_drv_close(void *ctx, int fd);

int32_t write_event(void *ctx, mb_event_info_t *pevent);

const char *driver_event_to_name_r(mb_driver_event_t event);

void mb_drv_set_cb(void *ctx, void *conn_cb, void *arg);

mb_status_flags_t mb_drv_wait_status_flag(void *ctx, mb_status_flags_t mask, TickType_t ticks);

esp_err_t mb_drv_register_handler(void *ctx, mb_driver_event_num_t event, mb_event_handler_fp fp);

esp_err_t mb_drv_unregister_handler(void *ctx, mb_driver_event_num_t event);

void mb_drv_check_suspend_shutdown(void *ctx);

void mb_drv_lock(void *ctx);

void mb_drv_unlock(void *ctx);

mb_node_info_t *mb_drv_get_next_node_from_set(void *ctx, int *pfd, fd_set *pfdset);

mb_status_flags_t mb_drv_set_status_flag(void *ctx, mb_status_flags_t mask);

mb_status_flags_t mb_drv_clear_status_flag(void *ctx, mb_status_flags_t mask);

err_t mb_drv_check_node_state(void *ctx, int *fd, uint32_t timeout_ms);

#endif

#ifdef __cplusplus
}
#endif
