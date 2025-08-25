/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdatomic.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include "errno.h"

#include "esp_log.h"
#include "esp_check.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "esp_netif.h"

#include "port_common.h"
#include "esp_vfs_eventfd.h"
#include "port_tcp_driver.h"
#include "port_tcp_utils.h"

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

static const char *TAG = "mb_driver";

static esp_event_loop_handle_t mb_drv_loop_handle = NULL;
static int mb_drv_loop_inst_counter = 0;
static char msg_buffer[100]; // The buffer for event debugging (used for all instances)

static const event_msg_t event_msg_table[] = {
    MB_EVENT_TBL_IT(MB_EVENT_READY),
    MB_EVENT_TBL_IT(MB_EVENT_OPEN),
    MB_EVENT_TBL_IT(MB_EVENT_RESOLVE),
    MB_EVENT_TBL_IT(MB_EVENT_CONNECT),
    MB_EVENT_TBL_IT(MB_EVENT_SEND_DATA),
    MB_EVENT_TBL_IT(MB_EVENT_RECV_DATA),
    MB_EVENT_TBL_IT(MB_EVENT_ERROR),
    MB_EVENT_TBL_IT(MB_EVENT_CLOSE),
    MB_EVENT_TBL_IT(MB_EVENT_TIMEOUT),
};

// The function to print event
const char *driver_event_to_name_r(mb_driver_event_t event)
{
    msg_buffer[0] = 0;
    size_t i;
    for (i = 0; i < sizeof(event_msg_table) / sizeof(event_msg_table[0]); ++i) {
        if (event_msg_table[i].event & event) {
            strlcat(msg_buffer, "|", sizeof(msg_buffer));
            strlcat(msg_buffer, event_msg_table[i].msg, sizeof(msg_buffer));
        }
    }
    return msg_buffer;
}

static esp_err_t init_event_fd(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    if (!mb_drv_loop_inst_counter) {
        esp_vfs_eventfd_config_t config = MB_EVENTFD_CONFIG();
        esp_err_t err = esp_vfs_eventfd_register(&config);
        if ((err != ESP_OK) && (err != ESP_ERR_INVALID_STATE)) {
            ESP_LOGE(TAG, "eventfd registration fail.");
        }
    }
    drv_obj->event_fd = eventfd(0, 0);
    MB_RETURN_ON_FALSE((drv_obj->event_fd > 0), ESP_ERR_INVALID_STATE, TAG, "eventfd init error.");
    return (drv_obj->event_fd > 0) ? ESP_OK : ESP_ERR_INVALID_STATE;
}

static esp_err_t close_event_fd(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    if (mb_drv_loop_inst_counter) {
        close(drv_obj->event_fd);
    } else {
        ESP_LOGD(TAG, "close eventfd (%d).", (int)drv_obj->event_fd);
        return esp_vfs_eventfd_unregister();
    }
    return ESP_OK;
}

int32_t write_event(void *ctx, mb_event_info_t *event)
{
    MB_RETURN_ON_FALSE((event && ctx), -1, TAG, "wrong arguments.");
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    esp_err_t err = esp_event_post_to(mb_drv_loop_handle,
                                      MB_EVENT_BASE(ctx), event->event_id, event,
                                      sizeof(mb_event_info_t), MB_EVENT_TOUT);
    if ((err != ESP_OK)) {
        ESP_LOGE(TAG, "%p, event loop send fail, err = %d.", ctx, (int)err);
        return -1;
    }
    // send eventfd to just trigger select
    int32_t ret = write(drv_obj->event_fd, (char *)&event->val, sizeof(mb_event_info_t));
    return (ret == sizeof(mb_event_info_t)) ? event->event_id : -1;
}

static int32_t read_event(void *ctx, mb_event_info_t *event)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    MB_RETURN_ON_FALSE(event, ESP_ERR_INVALID_STATE, TAG, "cannot get event.");
    int ret = read(drv_obj->event_fd, (char *)&event->val, sizeof(mb_event_info_t));
    return (ret == sizeof(mb_event_info_t)) ? event->event_id : -1;
}

static esp_err_t mb_drv_event_loop_init(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    esp_err_t err = ESP_OK;
    /* Create Event loop without task (will be created separately)*/
    esp_event_loop_args_t loop_args = {
        .queue_size = MB_EVENT_QUEUE_SZ,
        .task_name = NULL
    };
    if (!mb_drv_loop_handle && !mb_drv_loop_inst_counter) {
        err = esp_event_loop_create(&loop_args, &mb_drv_loop_handle);
        MB_RETURN_ON_FALSE(((err == ESP_OK) && mb_drv_loop_handle), ESP_ERR_INVALID_STATE, 
                                TAG, "create event loop failed, err=%d.", (int)err);
    }
    drv_obj->event_loop_hdl = mb_drv_loop_handle;
    if (asprintf(&drv_obj->loop_name, "loop:%p", ctx) == -1) {
        abort();
    }
    return err;
}

static esp_err_t mb_drv_event_loop_deinit(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    esp_err_t err = ESP_OK;
    // delete event loop
    MB_RETURN_ON_FALSE((mb_drv_loop_handle), ESP_ERR_INVALID_STATE, 
                                    TAG, "delete event loop failed.");
    if (mb_drv_loop_inst_counter) {
        ESP_LOGD(TAG, "delete loop inst: %s.", drv_obj->loop_name);
        free(drv_obj->loop_name);
        drv_obj->loop_name = NULL;
        mb_drv_loop_inst_counter--;
    }
    if (!mb_drv_loop_inst_counter) {
        err = esp_event_loop_delete(mb_drv_loop_handle);
        ESP_LOGD(TAG, "delete event loop: %p.", mb_drv_loop_handle);
        mb_drv_loop_handle = NULL;
        MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, 
                                TAG, "delete event loop failed, error=%d.", (int)err);
    }
    return err;
}

esp_err_t mb_drv_register_handler(void *ctx, mb_driver_event_num_t event_num, mb_event_handler_fp fp)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    mb_driver_event_t event = MB_EVENT_FROM_NUM(event_num);

    ESP_LOGD(TAG, "%p, event #%d, 0x%x, register.", drv_obj, (int)event_num, (int)event);
    MB_RETURN_ON_FALSE((drv_obj->event_handler[event_num] == NULL), ESP_ERR_INVALID_ARG,
                        TAG, "%p, event handler %p, for event %x, is not empty.", drv_obj, drv_obj->event_handler[event_num], (int)event);

    ret = esp_event_handler_instance_register_with(mb_drv_loop_handle, MB_EVENT_BASE(ctx), event,
                                                                fp, ctx, &drv_obj->event_handler[event_num]);
    ESP_LOGD(TAG, "%p, registered event handler %p, event 0x%x", drv_obj, drv_obj->event_handler[event_num], (int)event);
    MB_RETURN_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE,
                            TAG, "%p, event handler %p, registration error.", drv_obj, drv_obj->event_handler[event_num]);
    
    return ESP_OK;
}

esp_err_t mb_drv_unregister_handler(void *ctx, mb_driver_event_num_t event_num)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    mb_driver_event_t event = MB_EVENT_FROM_NUM(event_num);

    ESP_LOGD(TAG, "%p, event handler %p, event 0x%x, unregister.", drv_obj, drv_obj->event_handler[event_num], (int)event);
    MB_RETURN_ON_FALSE((drv_obj->event_handler[event_num]), ESP_ERR_INVALID_ARG,
                        TAG, "%p, event handler %p, for event %x, is incorrect.", drv_obj, drv_obj->event_handler[event_num], (int)event);

    ret = esp_event_handler_instance_unregister_with(mb_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), (int32_t)event, drv_obj->event_handler[event_num]);
    drv_obj->event_handler[event_num] = NULL;
    MB_RETURN_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE ,
                        TAG, "%p, event handler %p, instance unregister with, error = %d", drv_obj, drv_obj->event_handler[event_num], (int)ret);

    return ESP_OK;
}

static esp_err_t init_queues(mb_node_info_t *mb_node)
{
    mb_node->rx_queue = queue_create(MB_RX_QUEUE_MAX_SIZE);
    MB_RETURN_ON_FALSE(mb_node->rx_queue, ESP_ERR_NO_MEM, TAG, "create rx queue failed");
    mb_node->tx_queue = queue_create(MB_TX_QUEUE_MAX_SIZE);
    MB_RETURN_ON_FALSE(mb_node->tx_queue, ESP_ERR_NO_MEM, TAG, "create tx queue failed");
    return ESP_OK;
}

static void delete_queues(mb_node_info_t *pmb_node)
{
    if (pmb_node) {
        if (pmb_node->rx_queue) {
            if (!queue_is_empty(pmb_node->rx_queue)) {
                queue_flush(pmb_node->rx_queue);
            }
            queue_delete(pmb_node->rx_queue);
            pmb_node->rx_queue = NULL;
        }
        if (pmb_node->tx_queue) {
            if (!queue_is_empty(pmb_node->tx_queue)) {
                queue_flush(pmb_node->tx_queue);
            }
            queue_delete(pmb_node->tx_queue);
            pmb_node->tx_queue = NULL;
        }
    }
}

inline void mb_drv_lock(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    CRITICAL_SECTION_LOCK(drv_obj->lock);
}

inline void mb_drv_unlock(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    CRITICAL_SECTION_UNLOCK(drv_obj->lock);
}

__attribute__((unused))
mb_sock_state_t mb_drv_get_node_state(void *ctx, int fd)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *pnode = drv_obj->mb_nodes[fd];
    return (pnode) ? atomic_load(&pnode->addr_info.state) : MB_SOCK_STATE_UNDEF;
}

void mb_drv_check_suspend_shutdown(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);

    if (drv_obj->close_done_sema) {
        mb_status_flags_t status = mb_drv_wait_status_flag(ctx, (MB_FLAG_SHUTDOWN | MB_FLAG_SUSPEND), 0);
        ESP_LOGD(TAG, "%p, driver check shutdown (%d)...", ctx, (int)status);
        if (status & MB_FLAG_SHUTDOWN) {
            xSemaphoreGive(drv_obj->close_done_sema);
            ESP_LOGD(TAG, "%p, driver task shutdown...", ctx);
            vTaskDelete(NULL);
        } else if (status & MB_FLAG_SUSPEND) {
            xSemaphoreGive(drv_obj->close_done_sema);
            ESP_LOGD(TAG, "%p, driver task is suspended...", ctx);
            vTaskSuspend(NULL);
        }
    }
}

mb_status_flags_t mb_drv_set_status_flag(void *ctx, mb_status_flags_t mask)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    return (mb_status_flags_t)xEventGroupSetBits(drv_obj->status_flags_hdl, (EventBits_t)mask);
}

mb_status_flags_t mb_drv_clear_status_flag(void *ctx, mb_status_flags_t mask)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    return (mb_status_flags_t)xEventGroupClearBits(drv_obj->status_flags_hdl, (EventBits_t)mask);
}

mb_status_flags_t mb_drv_wait_status_flag(void *ctx, mb_status_flags_t mask, TickType_t ticks)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    return (mb_status_flags_t)xEventGroupWaitBits(drv_obj->status_flags_hdl,
                                            (BaseType_t)(mask),
                                            pdFALSE,
                                            pdFALSE,
                                            ticks);
}

int mb_drv_open(void *ctx, mb_uid_info_t addr_info, int flags)
{
    int fd = UNDEF_FD;
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *node_ptr = NULL;
    // Find free fd and initialize
    for (fd = 0; fd < MB_MAX_FDS; fd++) {
        node_ptr = drv_obj->mb_nodes[fd];
        if (!node_ptr) {
            node_ptr = calloc(1, sizeof(mb_node_info_t));
            mb_drv_lock(ctx);
            if (!node_ptr) {
                goto err;
            }
            ESP_LOGD(TAG, "%p, open vfd: %d, sl_addr: %02x, node: %s:%u",
                        ctx, fd, (int8_t)addr_info.uid,
                        addr_info.ip_addr_str, (unsigned)addr_info.port);
            if (init_queues(node_ptr) != ESP_OK) {
                goto err;
            }
            if (drv_obj->mb_node_open_count > MB_MAX_FDS) {
                ESP_LOGE(TAG, "Exceeded maximum node count: %d", drv_obj->mb_node_open_count);
                goto err;
            }
            drv_obj->mb_node_open_count++;
            node_ptr->index = fd;
            node_ptr->fd = fd;
            node_ptr->sock_id = addr_info.fd;
            node_ptr->error = -1;
            node_ptr->recv_err = -1;
            node_ptr->addr_info = addr_info;
            //node_ptr->addr_info.ip_addr_str = NULL;
            node_ptr->addr_info.index = fd;
            node_ptr->send_time = esp_timer_get_time();
            node_ptr->recv_time = esp_timer_get_time();
            node_ptr->tid_counter = 0;
            node_ptr->send_counter = 0;
            node_ptr->recv_counter = 0;
            node_ptr->is_blocking = ((flags & O_NONBLOCK) == 0);
            drv_obj->mb_nodes[fd] = node_ptr;
            // mark opened node in the open set
            FD_SET(fd, &drv_obj->open_set);
            mb_drv_unlock(ctx);
            MB_SET_NODE_STATE(node_ptr, MB_SOCK_STATE_OPENED);
            DRIVER_SEND_EVENT(ctx, MB_EVENT_OPEN, fd);
            return fd;
        }
    }

err:
    delete_queues(node_ptr);
    free(node_ptr);
    drv_obj->mb_nodes[fd] = NULL;
    mb_drv_unlock(ctx);
    return UNDEF_FD;
}

mb_node_info_t *mb_drv_get_node(void *ctx, int fd)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    return drv_obj->mb_nodes[fd];
}

// writes data into tx queue
ssize_t mb_drv_write(void *ctx, int fd, const void *data, size_t size)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    ssize_t ret = -1;

    if (size == 0) {
        return 0;
    }

    mb_node_info_t *node_ptr = drv_obj->mb_nodes[fd];
    if (!node_ptr) {
        errno = EBADF;
        return 0;
    }

    if (MB_GET_NODE_STATE(node_ptr) >= MB_SOCK_STATE_CONNECTED) {
        if (queue_push(node_ptr->tx_queue, (void *)data, size, NULL) == ESP_OK) {
            ret = size;
            // Inform FSM that is new frame data is ready to be send
            DRIVER_SEND_EVENT(ctx, MB_EVENT_SEND_DATA, node_ptr->index);
        } else {
            // I/O error
            errno = EIO;
        }
    } else {
        // bad file desc
        errno = EBADF;
    }
    return ret;
}

// reads data from rx queue
ssize_t mb_drv_read(void *ctx, int fd, void *data, size_t size)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *node_ptr = drv_obj->mb_nodes[fd];
    if (!node_ptr) {
        errno = EBADF;
        return 0;
    }

    // fd might be in process of closing (close was already called but preempted)
    if (MB_GET_NODE_STATE(node_ptr) < MB_SOCK_STATE_CONNECTED) {
        // bad file desc
        errno = EBADF;
        return -1;
    }

    if (size == 0) {
        return 0;
    }

    ssize_t actual_size = -1;
    if ((actual_size = queue_pop(node_ptr->rx_queue, data, size, NULL)) < 0) {
        errno = EAGAIN;
    }

    return actual_size;
}

int mb_drv_close(void *ctx, int fd)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *node_ptr = drv_obj->mb_nodes[fd]; // get address of configuration

    if (!node_ptr) {
        // not valid opened fd
        errno = EBADF;
        return -1;
    }
    mb_drv_lock(ctx);
    // stop socket
    if (MB_GET_NODE_STATE(node_ptr) != MB_SOCK_STATE_CLOSED) {
        // Do we need to close connection, if the close event is not run
        if ((node_ptr->sock_id > 0) && (FD_ISSET(node_ptr->sock_id, &drv_obj->conn_set)))
        {
            FD_CLR(node_ptr->sock_id, &drv_obj->conn_set);
            if (drv_obj->node_conn_count)
            {
                drv_obj->node_conn_count--;
            }
        }
        port_close_connection(node_ptr);
    }
    MB_SET_NODE_STATE(node_ptr, MB_SOCK_STATE_CLOSED);
    FD_CLR(fd, &drv_obj->open_set);
    delete_queues(node_ptr);
    if (drv_obj->mb_node_open_count) {
        drv_obj->mb_node_open_count--;
    }
    if (node_ptr->addr_info.node_name_str != node_ptr->addr_info.ip_addr_str) {
        free((void *)node_ptr->addr_info.ip_addr_str); // node ip addr string shall be freed
    }
    free((void *)node_ptr->addr_info.node_name_str);
    node_ptr->addr_info.node_name_str = NULL;
    node_ptr->addr_info.ip_addr_str = NULL;
    free(node_ptr);
    drv_obj->mb_nodes[fd] = NULL;
    mb_drv_unlock(ctx);

    return 0;
}

mb_node_info_t *mb_drv_get_next_node_from_set(void *ctx, int *fd_ptr, fd_set *fdset)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    if (!fdset || !fd_ptr) {
        return NULL;
    }
    mb_node_info_t *node_ptr = NULL;
    for (int fd = *fd_ptr; fd < MB_MAX_FDS; fd++) {
        node_ptr = drv_obj->mb_nodes[fd];
        if (node_ptr && (node_ptr->sock_id > 0)
            && (MB_GET_NODE_STATE(node_ptr) >= MB_SOCK_STATE_CONNECTED) 
            && (FD_ISSET(node_ptr->index, fdset) || (FD_ISSET(node_ptr->sock_id, fdset)))) {
            *fd_ptr = fd;
            //FD_CLR(node_ptr->sock_id, fdset);
            return node_ptr;
        }
    }
    return NULL;
}

mb_node_info_t *mb_drv_get_node_info_from_addr(void *ctx, uint8_t uid)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *node_ptr = NULL;
    for (int fd = 0; fd < MB_MAX_FDS; fd++) {
        node_ptr = drv_obj->mb_nodes[fd];
        if (node_ptr && node_ptr->addr_info.uid == uid) {
            return node_ptr;
        }
    }
    return NULL;
}

static int mb_drv_register_fds(void *ctx, fd_set *fdset)
{
    mb_node_info_t *node_ptr = NULL;
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    // Setup select waiting for eventfd && socket events
    FD_ZERO(fdset);
    int max_fd = UNDEF_FD;
    // Add to the set all connected slaves
    for (int i = 0; i < MB_MAX_FDS; i++) {
        node_ptr = drv_obj->mb_nodes[i];
        if (node_ptr && node_ptr->sock_id && (MB_GET_NODE_STATE(node_ptr) >= MB_SOCK_STATE_CONNECTED)) {
            MB_ADD_FD(node_ptr->sock_id, max_fd, fdset);
        }
    }
    // Add event fd events to the set to handle them in one select
    MB_ADD_FD(drv_obj->event_fd, max_fd, fdset);
    // Add listen socket to handle incoming connections (for slave only)
    MB_ADD_FD(drv_obj->listen_sock_fd, max_fd, fdset);
    return max_fd;
}

// Wait socket ready event during timeout
static int mb_drv_wait_fd_events(void *ctx, fd_set *fdset, fd_set *perrset, int time_ms)
{
    fd_set readset = *fdset;
    int ret = 0;
    struct timeval tv;

    if (!ctx || !fdset) {
        return -1;
    }

    tv.tv_sec = time_ms / 1000;
    tv.tv_usec = (time_ms - (tv.tv_sec * 1000)) * 1000;

    // fill the readset according to the active fds
    int max_fd = mb_drv_register_fds(ctx, &readset);
    if (perrset) {
        *perrset = readset; // initialize error set if used
    }

    ret = select(max_fd + 1, &readset, NULL, perrset, &tv);
    if (ret == 0) {
        // No respond from node during timeout
        ret = ERR_TIMEOUT;
    } else if (ret < 0) {
        ret = -1;
    } 
    *fdset = readset;
    return ret;
}

esp_err_t mb_drv_start_task(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    (void)mb_drv_clear_status_flag(ctx, MB_FLAG_SUSPEND);
    ESP_LOGD(TAG, "%p, resume tcp driver task.", ctx);
    vTaskResume(drv_obj->mb_tcp_task_handle);
    return ESP_OK;
}

esp_err_t mb_drv_stop_task(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    esp_err_t err = ESP_ERR_TIMEOUT;
    if (!drv_obj->close_done_sema) {
        drv_obj->close_done_sema = xSemaphoreCreateBinary();
    }
    (void)mb_drv_set_status_flag(ctx, MB_FLAG_SUSPEND);
    // Check if we can safely suspend the port task (workaround for issue with deadlock in suspend)
    if (!drv_obj->close_done_sema 
            || !(mb_drv_wait_status_flag(ctx, MB_FLAG_SUSPEND, 1) & MB_FLAG_SUSPEND) 
            || (xSemaphoreTake(drv_obj->close_done_sema, pdMS_TO_TICKS(MB_WAIT_DONE_MS)) != pdTRUE)
            ) {
        ESP_LOGD(TAG, "%p, could not stop driver task during timeout.", ctx);
        vTaskSuspend(drv_obj->mb_tcp_task_handle);
        err = ESP_OK;
    }
    ESP_LOGD(TAG, "%p, stop tcp driver task.", ctx);
    if (drv_obj->close_done_sema) {
        vSemaphoreDelete(drv_obj->close_done_sema);
        drv_obj->close_done_sema = NULL;
    }
    return err;
}

err_t mb_drv_check_node_state(void *ctx, int *fd_ptr, uint32_t timeout_ms)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_node_info_t *pnode = NULL;
    err_t err = ERR_TIMEOUT;

    pnode = mb_drv_get_next_node_from_set(ctx, fd_ptr, &drv_obj->conn_set);
    if (pnode && FD_ISSET(pnode->sock_id, &drv_obj->conn_set)) {
        uint64_t last_read_div_us = (esp_timer_get_time() - pnode->recv_time);
        ESP_LOGD(TAG, "%p, node: %d, sock: %d, IP:%s, check connection timeout = %" PRId64 ", rcv_time: %" PRId64 " %" PRIu32,
                    ctx, (int)pnode->index, (int)pnode->sock_id, pnode->addr_info.ip_addr_str,
                    (esp_timer_get_time() / 1000), pnode->recv_time / 1000, timeout_ms);
        if (last_read_div_us >= (uint64_t)(timeout_ms * 1000)) {
            ESP_LOGD(TAG, "%p, node: %d, sock: %d, IP:%s, check connection state, time = %" PRId64 ", rcv_time: %" PRId64,
                        ctx, (int)pnode->index, (int)pnode->sock_id, pnode->addr_info.ip_addr_str,
                        (esp_timer_get_time() / 1000), pnode->recv_time / 1000);
            err = port_check_alive(pnode, 1); // minimize blocking time
            if ((err < 0) && (err != ERR_INPROGRESS)) {
                ESP_LOGD(TAG, "Node #%d (%s), connection error, err=(%d).", pnode->index, pnode->addr_info.ip_addr_str, (int)err);
            } if (err == ERR_OK) {
                ESP_LOGD(TAG, "Node #%d (%s), connection is alive, err=(%d).", pnode->index, pnode->addr_info.ip_addr_str, (int)err);
                pnode->recv_time = esp_timer_get_time();
            }
        }
    }
    return err;
}

void mb_drv_tcp_task(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    ESP_LOGD(TAG, "Start of driver task.");
    while (1) {
        fd_set readset, errorset;
        FD_ZERO(&readset);
        FD_ZERO(&errorset);
        // check all active socket and fd events
        int ret = mb_drv_wait_fd_events(ctx, &readset, &errorset, MB_SELECT_WAIT_MS);
        if (ret == ERR_TIMEOUT) {
            // timeout occured waiting for the vfds
            DRIVER_SEND_EVENT(ctx, MB_EVENT_TIMEOUT, UNDEF_FD);
            mb_drv_check_suspend_shutdown(ctx);
        } else if (ret == -1) {
            // error occured during waiting for vfds activation
            ESP_LOGD(TAG, "%p, task select error.", ctx);
            mb_drv_check_suspend_shutdown(ctx);
            ESP_LOGD(TAG, "%p, socket error, fdset: %" PRIx64, ctx, *(uint64_t *)&errorset);
        } else {
            // Is the fd event triggered, process the event
            if (drv_obj->event_fd && FD_ISSET(drv_obj->event_fd, &readset)) {
                mb_event_info_t mb_event = {0};
                int32_t event_id = read_event(ctx, &mb_event);
                ESP_LOGD(TAG, "%p, fd event get: 0x%02x:%d, %s", 
                            ctx, (int)event_id, (int)mb_event.opt_fd, driver_event_to_name_r(event_id));
                mb_drv_check_suspend_shutdown(ctx);
                // Drive the event loop
                esp_err_t err = esp_event_loop_run(mb_drv_loop_handle, pdMS_TO_TICKS(MB_TCP_EVENT_LOOP_TICK_MS));
                if (err != ESP_OK) {
                    ESP_LOGE(TAG, "%p, event loop run, returns fail: %x", ctx, (int)err);
                }
            } else if (drv_obj->listen_sock_fd && FD_ISSET(drv_obj->listen_sock_fd, &readset)) {
                // If something happened on the listen socket, then it is an incoming connection.
                ESP_LOGD(TAG, "%p, listen_sock is active.", ctx);
                mb_uid_info_t node_info;
                int sock_id = port_accept_connection(drv_obj->listen_sock_fd, &node_info);
                if (sock_id) {
                    if (drv_obj->mb_node_open_count >= MB_MAX_FDS) {
                        ESP_LOGE(TAG, "%p, unable to accept node, maximum is %u connections.", drv_obj, MB_MAX_FDS);
#if LWIP_SO_LINGER
                        struct linger sl;
                        sl.l_onoff = 1;  // non-zero value enables linger option in lwip
                        sl.l_linger = 0; // timeout interval in seconds
                        setsockopt(sock_id, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#endif // LWIP_SO_LINGER
                        close(sock_id);
                    } else {
                        // Create new node info and open it
                        int fd = mb_drv_open(drv_obj, node_info, 0);
                        if (fd < 0) {
                            ESP_LOGE(TAG, "%p, unable to open node: %s", drv_obj, node_info.ip_addr_str);
                        } else {
                            DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, fd);
                        }
                    }
                }
            } else {
                // socket event is ready, process each socket event
                mb_drv_check_suspend_shutdown(ctx);
                int curr_fd = 0;
                mb_node_info_t *node_ptr = NULL;
                ESP_LOGD(TAG, "%p, socket event active: %" PRIx64, ctx, *(uint64_t *)&readset);
                while(((node_ptr = mb_drv_get_next_node_from_set(ctx, &curr_fd, &readset))
                           && (curr_fd < MB_MAX_FDS))) {
                    if (FD_ISSET(node_ptr->sock_id, &drv_obj->conn_set)) {
                        // The data is ready in the socket, read frame and queue
                        FD_CLR(node_ptr->sock_id, &readset);
                        int ret = port_read_packet(node_ptr);
                        if (ret > 0) {
                            ESP_LOGD(TAG, "%p, "MB_NODE_FMT(", frame received."), ctx, (int)node_ptr->fd,
                                        (int)node_ptr->sock_id, node_ptr->addr_info.ip_addr_str);
                            mb_drv_lock(ctx);
                            node_ptr->recv_time = esp_timer_get_time();
                            mb_drv_unlock(ctx);
                            DRIVER_SEND_EVENT(ctx, MB_EVENT_RECV_DATA, node_ptr->index);
                        } else if (ret == ERR_TIMEOUT) {
                            ESP_LOGD(TAG, "%p, "MB_NODE_FMT(", frame read timeout or closed connection."), ctx, (int)node_ptr->fd,
                                        (int)node_ptr->sock_id, node_ptr->addr_info.ip_addr_str);
                        } else if (ret == ERR_BUF) {
                            // After retries a response with incorrect TID received, process failure.
                            drv_obj->event_cbs.mb_sync_event_cb(drv_obj->event_cbs.port_arg, MB_SYNC_EVENT_RECV_FAIL);
                            ESP_LOGD(TAG, "%p, "MB_NODE_FMT(", frame error."), ctx, (int)node_ptr->fd,
                                        (int)node_ptr->sock_id, node_ptr->addr_info.ip_addr_str);
                        } else {
                            if (ret == ERR_CONN) {
                                ESP_LOGD(TAG, "%p, "MB_NODE_FMT(", connection lost."), ctx, (int)node_ptr->fd,
                                            (int)node_ptr->sock_id, node_ptr->addr_info.ip_addr_str);
                                DRIVER_SEND_EVENT(ctx, MB_EVENT_ERROR, node_ptr->index);
                            } else {
                                ESP_LOGD(TAG, "%p, "MB_NODE_FMT(", critical read error=%d, errno=%u."), ctx, (int)node_ptr->fd,
                                        (int)node_ptr->sock_id, node_ptr->addr_info.ip_addr_str, (int)ret, (unsigned)errno);
                                DRIVER_SEND_EVENT(ctx, MB_EVENT_ERROR, node_ptr->index);
                            }
                        }
                    }
                    curr_fd++;
                    mb_drv_check_suspend_shutdown(ctx);
                }
            }
        }
    }
}

esp_err_t mb_drv_register(port_driver_t **ctx)
{
    port_driver_t driver_config = MB_DRIVER_CONFIG_DEFAULT;
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    int i = 0;
    
    port_driver_t *pctx = (port_driver_t *)calloc(1, sizeof(port_driver_t));
    MB_GOTO_ON_FALSE((pctx), ESP_ERR_NO_MEM, error, TAG, "%p, driver allocation fail.", pctx);
    *pctx = driver_config;

    CRITICAL_SECTION_INIT(pctx->lock);

    // create and initialize modbus driver context structure
    pctx->mb_nodes = calloc(MB_MAX_FDS, sizeof(mb_node_info_t *));
    MB_GOTO_ON_FALSE((pctx->mb_nodes), ESP_ERR_NO_MEM, error, TAG, "%p, node allocation fail.", pctx);

    for (i = 0; i < MB_MAX_FDS; i++) {
        pctx->mb_nodes[i] = NULL;
    }
    // initialization of event handlers
    for (i = 0; i < MB_EVENT_COUNT; i++) {
        pctx->event_handler[i] = NULL;
    }

    ret = init_event_fd((void *)pctx);
    MB_GOTO_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE , error, 
                        TAG, "%p, vfs eventfd init error.", pctx);

    ret = mb_drv_event_loop_init((void *)pctx);
    MB_GOTO_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE , error, 
                        TAG, "%p, event loop init error.", pctx);

    pctx->status_flags_hdl = xEventGroupCreate();
    MB_GOTO_ON_FALSE((pctx->status_flags_hdl), ESP_ERR_INVALID_STATE, error, 
                        TAG, "%p, mb event group error.", pctx);

    mb_drv_loop_inst_counter++;

    // Create task for packet processing
    BaseType_t state = xTaskCreatePinnedToCore(mb_drv_tcp_task,
                                                "mb_drv_tcp_task",
                                                MB_TASK_STACK_SZ,
                                                pctx,
                                                MB_TASK_PRIO,
                                                &pctx->mb_tcp_task_handle,
                                                MB_PORT_TASK_AFFINITY);
    MB_GOTO_ON_FALSE((state == pdTRUE), ESP_ERR_INVALID_STATE , error, 
                        TAG, "%p, event task creation error.", pctx);
    (void)mb_drv_stop_task(pctx);

    *ctx = pctx;
    pctx->is_registered = true;
    FD_ZERO(&pctx->open_set);
    FD_ZERO(&pctx->conn_set);
    return ESP_OK;

error:
    if (pctx) {
        if (pctx->mb_tcp_task_handle) {
            vTaskDelete(pctx->mb_tcp_task_handle);
        }
        if (mb_drv_loop_handle) {
            (void)esp_event_loop_delete(mb_drv_loop_handle);
            mb_drv_loop_handle = NULL;
            free(pctx->loop_name);
            pctx->loop_name = NULL;
        }
        if (pctx->event_fd) {
            close(pctx->event_fd);
            (void)esp_vfs_eventfd_unregister();
        }
        if (pctx->close_done_sema) {
            vSemaphoreDelete(pctx->close_done_sema);
            pctx->close_done_sema = NULL;
        }
        free(pctx->mb_nodes);
    }
    free(pctx);
    return ret;
}

esp_err_t mb_drv_unregister(void *ctx)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    ESP_LOGD(TAG, "%p, driver unregister.", drv_obj);
    (void)mb_drv_set_status_flag(ctx, MB_FLAG_SHUTDOWN);
    drv_obj->close_done_sema = xSemaphoreCreateBinary();

    // if no semaphore (alloc issues) or couldn't acquire it, just delete the task
    if (!drv_obj->close_done_sema 
            || !(mb_drv_wait_status_flag(ctx, MB_FLAG_SHUTDOWN, 0) & MB_FLAG_SHUTDOWN) 
            || (xSemaphoreTake(drv_obj->close_done_sema, pdMS_TO_TICKS(MB_WAIT_DONE_MS)) != pdTRUE)
            ) {
        ESP_LOGD(TAG, "%p, driver tasks couldn't exit within timeout -> abruptly deleting the task.", drv_obj);
        vTaskDelete(drv_obj->mb_tcp_task_handle);
    }

    mb_drv_event_loop_deinit(ctx);
    if (drv_obj->close_done_sema) {
        vSemaphoreDelete(drv_obj->close_done_sema);
        drv_obj->close_done_sema = NULL;
    }

    esp_err_t err = close_event_fd(ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "could not close the eventfd handle, err = %d. Already closed?", err);
    }

    if (drv_obj->listen_sock_fd) {
        shutdown(drv_obj->listen_sock_fd, SHUT_RDWR);
        close(drv_obj->listen_sock_fd);
        drv_obj->listen_sock_fd = UNDEF_FD;
    }

    for (int i = 0; i < MB_MAX_FDS; i++) {
        mb_node_info_t *node_ptr = drv_obj->mb_nodes[i];
        if (node_ptr) {
            ESP_LOGD(TAG, "%p, close node instance #%d(%s).", ctx, i, node_ptr->addr_info.node_name_str);
            mb_drv_close(ctx, i);
        }
    }

    free(drv_obj->mb_nodes); // free the node info address array
    drv_obj->mb_nodes = NULL;

    vEventGroupDelete(drv_obj->status_flags_hdl);

    drv_obj->is_registered = false;
    CRITICAL_SECTION_CLOSE(drv_obj->lock);
    free(drv_obj);

    return ESP_OK;
}

void mb_drv_set_cb(void *ctx, void *conn_cb, void *arg)
{
    port_driver_t *drv_obj = MB_GET_DRV_PTR(ctx);
    mb_drv_lock(ctx);
    drv_obj->event_cbs.on_conn_done_cb = conn_cb;
    drv_obj->event_cbs.arg = arg;
    mb_drv_unlock(ctx);
}

#endif