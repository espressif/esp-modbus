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

static const char *TAG = "mbm_driver";

static esp_event_loop_handle_t mbm_drv_loop_handle = NULL;
static int mbm_drv_loop_inst_counter = 0;
static char msg_buffer[100]; // The buffer for event debugging (used for all instances)

/* ================== Utils ====================== */

static const event_msg_t event_msg_table[] = {
    MB_EVENT_TBL_IT(MB_EVENT_READY),
    MB_EVENT_TBL_IT(MB_EVENT_OPEN),
    MB_EVENT_TBL_IT(MB_EVENT_RESOLVE),
    MB_EVENT_TBL_IT(MB_EVENT_CONNECT),
    MB_EVENT_TBL_IT(MB_EVENT_SEND_DATA),
    MB_EVENT_TBL_IT(MB_EVENT_RECV_DATA),
    MB_EVENT_TBL_IT(MB_EVENT_RECONNECT),
    MB_EVENT_TBL_IT(MB_EVENT_CLOSE),
    MB_EVENT_TBL_IT(MB_EVENT_TIMEOUT),
};

static esp_err_t mbm_drv_unregister_handlers(void *ctx);

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
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    if (!mbm_drv_loop_inst_counter) {
        esp_vfs_eventfd_config_t config = MB_EVENTFD_CONFIG();
        esp_err_t err = esp_vfs_eventfd_register(&config);
        if ((err != ESP_OK) && (err != ESP_ERR_INVALID_STATE)) {
            ESP_LOGE(TAG, "eventfd registration fail.");
        }
    }
    pdrv_ctx->event_fd = eventfd(0, 0);
    MB_RETURN_ON_FALSE((pdrv_ctx->event_fd > 0), ESP_ERR_INVALID_STATE, TAG, "eventfd init error.");
    return (pdrv_ctx->event_fd > 0) ? ESP_OK : ESP_ERR_INVALID_STATE;
}

static esp_err_t close_event_fd(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    if (mbm_drv_loop_inst_counter) {
        close(pdrv_ctx->event_fd);
    } else {
        ESP_LOGW(TAG, "close eventfd (%d).", (int)pdrv_ctx->event_fd);
        return esp_vfs_eventfd_unregister();
    }
    return ESP_OK;
}

int32_t write_event(void *ctx, mb_event_info_t *pevent)
{
    MB_RETURN_ON_FALSE((pevent && ctx), -1, TAG, "wrong arguments.");
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    esp_err_t err = esp_event_post_to(mbm_drv_loop_handle,
                                      MB_EVENT_BASE(ctx), (int32_t)pevent->event_id, pevent,
                                      sizeof(mb_event_info_t), MB_EVENT_TOUT);
    if ((err != ESP_OK)) {
        ESP_LOGE(TAG, "%p, event loop send fail, err = %d.", ctx, (int)err);
        return -1;
    }
    int32_t ret = write(pdrv_ctx->event_fd, (char *)&pevent->val, sizeof(mb_event_info_t));
    return (ret == sizeof(mb_event_info_t)) ? pevent->event_id : -1;
}

static int32_t read_event(void *ctx, mb_event_info_t *pevent)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    MB_RETURN_ON_FALSE(pevent, ESP_ERR_INVALID_STATE, TAG, "cannot get event.");
    int ret = read(pdrv_ctx->event_fd, (char *)&pevent->val, sizeof(mb_event_info_t));
    return (ret == sizeof(mb_event_info_t)) ? pevent->event_id : -1;
}

static esp_err_t mbm_drv_event_loop_init(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    esp_err_t err = ESP_OK;
    /* Create Event loop without task (will be created separately)*/
    esp_event_loop_args_t loop_args = {
        .queue_size = MB_EVENT_QUEUE_SZ,
        .task_name = NULL
    };
    if (!mbm_drv_loop_handle && !mbm_drv_loop_inst_counter) {
        err = esp_event_loop_create(&loop_args, &mbm_drv_loop_handle);
        MB_RETURN_ON_FALSE(((err == ESP_OK) && mbm_drv_loop_handle), ESP_ERR_INVALID_STATE, 
                                TAG, "create event loop failed, err=%d.", (int)err);
    }
    pdrv_ctx->event_loop_hdl = mbm_drv_loop_handle;
    if (asprintf(&pdrv_ctx->loop_name, "loop:%p", ctx) == -1) {
        abort();
    }
    return err;
}

static esp_err_t mbm_drv_event_loop_deinit(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    esp_err_t err = ESP_OK;
    // delete event loop */
    if (mbm_drv_loop_handle && mbm_drv_loop_inst_counter) {
        ESP_LOGW(TAG, "delete loop inst: %s.", pdrv_ctx->loop_name);
        mbm_drv_loop_inst_counter--;
    }
    if (mbm_drv_loop_handle && !mbm_drv_loop_inst_counter) {
        err = esp_event_loop_delete(mbm_drv_loop_handle);
        ESP_LOGW(TAG, "delete event loop: %p.", mbm_drv_loop_handle);
        mbm_drv_loop_handle = NULL;
        free(pdrv_ctx->loop_name);
        pdrv_ctx->loop_name = NULL;
        MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, 
                                TAG, "delete event loop failed, error=%d.", (int)err);
    }
    return err;
}

static esp_err_t mbm_drv_register_handlers(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;

    ret = esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_READY, 
                                                                &on_ready, ctx, &pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_OPEN, 
                                                                &on_open, ctx, &pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_RESOLVE, 
                                                                &on_resolve, ctx, &pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_CONNECT, 
                                                                &on_connect, ctx, &pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_SEND_DATA, 
                                                                &on_send_data, ctx, &pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_RECV_DATA, 
                                                                &on_recv_data, ctx, &pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_RECONNECT, 
                                                                &on_reconnect, ctx, &pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_CLOSE, 
                                                                &on_close, ctx, &pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_register_with(mbm_drv_loop_handle, MB_EVENT_BASE(ctx), MB_EVENT_TIMEOUT,
                                                                &on_timeout, ctx, &pdrv_ctx->event_handler);
    MB_RETURN_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE , 
                            TAG, "%p, event handler %p, registration error.", pdrv_ctx, pdrv_ctx->event_handler);
    
    return ESP_OK;
}

static esp_err_t mbm_drv_unregister_handlers(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    ESP_LOGW(TAG, "%p, event handler %p, unregister.", pdrv_ctx, pdrv_ctx->event_handler);

    ret = esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_READY, pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_OPEN, pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_RESOLVE, pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_CONNECT, pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_SEND_DATA, pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_RECV_DATA, pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_RECONNECT, pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_CLOSE, pdrv_ctx->event_handler);
    ret |= esp_event_handler_instance_unregister_with(mbm_drv_loop_handle,
                                                      MB_EVENT_BASE(ctx), MB_EVENT_TIMEOUT, pdrv_ctx->event_handler);
    MB_RETURN_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE , 
                        TAG, "%p, event handler %p, unregister error.", pdrv_ctx, pdrv_ctx->event_handler);
    
    return ESP_OK;
}

static esp_err_t init_queues(mb_slave_info_t *mb_slave)
{
    mb_slave->rx_queue = queue_create(MB_RX_QUEUE_MAX_SIZE);
    MB_RETURN_ON_FALSE(mb_slave->rx_queue, ESP_ERR_NO_MEM, TAG, "create rx queue failed");
    mb_slave->tx_queue = queue_create(MB_TX_QUEUE_MAX_SIZE);
    MB_RETURN_ON_FALSE(mb_slave->tx_queue, ESP_ERR_NO_MEM, TAG, "create tx queue failed");
    return ESP_OK;
}

static void delete_queues(mb_slave_info_t *pmb_slave)
{
    queue_delete(pmb_slave->rx_queue);
    queue_delete(pmb_slave->tx_queue);
    pmb_slave->rx_queue = NULL;
    pmb_slave->tx_queue = NULL;
}

static inline void mbm_drv_lock(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    CRITICAL_SECTION_LOCK(pdrv_ctx->lock);
}

static inline void mbm_drv_unlock(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    CRITICAL_SECTION_UNLOCK(pdrv_ctx->lock);
}

__attribute__((unused))
static mb_sock_state_t mbm_drv_get_slave_state(void *ctx, int fd)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_slave_info_t *pslave = pdrv_ctx->mb_slave_info[fd];
    return (pslave) ? atomic_load(&pslave->addr_info.state) : MB_SOCK_STATE_UNDEF;
}

static void mbm_drv_check_suspend_shutdown(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    
    if (pdrv_ctx->close_done_sema) {        
        mb_status_flags_t status = mbm_drv_wait_status_flag(ctx, (MB_FLAG_SHUTDOWN | MB_FLAG_SUSPEND), 0);
        ESP_LOGW(TAG, "%p, driver check shutdown (%d)...", ctx, (int)status);
        if (status & MB_FLAG_SHUTDOWN) {
            xSemaphoreGive(pdrv_ctx->close_done_sema);
            ESP_LOGW(TAG, "%p, driver task shutdown...", ctx);
            vTaskDelete(NULL);
        } else if (status & MB_FLAG_SUSPEND) {
            xSemaphoreGive(pdrv_ctx->close_done_sema);
            ESP_LOGW(TAG, "%p, driver task is suspended...", ctx);
            vTaskSuspend(NULL);
        }
    }
}

static mb_status_flags_t mbm_drv_set_status_flag(void *ctx, mb_status_flags_t mask)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    return (mb_status_flags_t)xEventGroupSetBits(pdrv_ctx->status_flags_hdl, (EventBits_t)mask);
}

static mb_status_flags_t mbm_drv_clear_status_flag(void *ctx, mb_status_flags_t mask)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    return (mb_status_flags_t)xEventGroupClearBits(pdrv_ctx->status_flags_hdl, (EventBits_t)mask);
}

mb_status_flags_t mbm_drv_wait_status_flag(void *ctx, mb_status_flags_t mask, uint32_t tout_ms)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    return (mb_status_flags_t)xEventGroupWaitBits(pdrv_ctx->status_flags_hdl,
                                            (BaseType_t)(mask),
                                            pdFALSE,
                                            pdFALSE,
                                            pdMS_TO_TICKS(tout_ms));
}

int mbm_drv_open(void *ctx, mb_uid_info_t addr_info, int flags)
{
    int fd = -1;
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_slave_info_t *pslave_info = NULL;
    // Find free fd and initialize
    for (fd = 0; fd < MB_MAX_FDS; fd++) {
        pslave_info = pdrv_ctx->mb_slave_info[fd];
        if (!pslave_info) {
            pslave_info = calloc(1, sizeof(mb_slave_info_t));
            if (!pslave_info) {
                goto err;
            }
            ESP_LOGW(TAG, "%p, open vfd: %d, sl_addr: %02x, node: %s:%u",
                        ctx, fd, (int8_t)addr_info.uid,
                        addr_info.ip_addr_str, (unsigned)addr_info.port);
            if (init_queues(pslave_info) != ESP_OK) {
                goto err;
            }
            if (pdrv_ctx->mb_slave_open_count > MB_MAX_FDS) {
                goto err;
            }
            mbm_drv_lock(ctx);
            pdrv_ctx->mb_slave_open_count++;
            pslave_info->index = fd;
            pslave_info->fd = fd;
            pslave_info->sock_id = -1;
            pslave_info->error = -1;
            pslave_info->recv_err = -1;
            pslave_info->addr_info = addr_info;
            pslave_info->addr_info.ip_addr_str = NULL;
            pslave_info->addr_info.index = fd;
            pslave_info->send_time = esp_timer_get_time();
            pslave_info->recv_time = esp_timer_get_time();
            pslave_info->tid_counter = 0;
            pslave_info->send_counter = 0;
            pslave_info->recv_counter = 0;
            pslave_info->is_blocking = ((flags & O_NONBLOCK) == 0);
            pdrv_ctx->mb_slave_info[fd] = pslave_info;
            // mark opened slave in the open set
            FD_SET(fd, &pdrv_ctx->open_set);
            mbm_drv_unlock(ctx);
            MB_SET_SLAVE_STATE(pslave_info, MB_SOCK_STATE_OPENED);
            DRIVER_SEND_EVENT(ctx, MB_EVENT_OPEN, fd);
            return fd;
        }
    }
err:
    free(pslave_info);
    pdrv_ctx->mb_slave_info[fd] = NULL;
    mbm_drv_unlock(ctx);
    return INVALID_FD;
}

// writes data into tx queue
ssize_t mbm_drv_write(void *ctx, int fd, const void *data, size_t size)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    ssize_t ret = -1;

    if (size == 0) {
        return 0;
    }

    mb_slave_info_t *pslave_info = pdrv_ctx->mb_slave_info[fd];
    if (!pslave_info) {
        errno = EBADF;
        return 0;
    }

    if (MB_GET_SLAVE_STATE(pslave_info) >= MB_SOCK_STATE_CONNECTED) {
        if (queue_push(pslave_info->tx_queue, (void *)data, size, NULL) == ESP_OK) {
            ret = size;
            mbm_drv_lock(ctx);
            pdrv_ctx->mb_slave_curr_info = pslave_info;
            pdrv_ctx->curr_slave_index = pslave_info->index;
            mbm_drv_unlock(ctx);
            // Inform FSM that is new frame data is ready to be send
            DRIVER_SEND_EVENT(ctx, MB_EVENT_SEND_DATA, pslave_info->index);
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
ssize_t mbm_drv_read(void *ctx, int fd, void *data, size_t size)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_slave_info_t *pslave_info = pdrv_ctx->mb_slave_info[fd];
    if (!pslave_info) {
        errno = EBADF;
        return 0;
    }

    // fd might be in process of closing (close was already called but preempted)
    if (MB_GET_SLAVE_STATE(pslave_info) < MB_SOCK_STATE_CONNECTED) {
        // bad file desc
        errno = EBADF;
        return -1;
    }

    if (size == 0) {
        return 0;
    }

    ssize_t actual_size = -1;
    if ((actual_size = queue_pop(pslave_info->rx_queue, data, size, NULL)) < 0) {
        errno = EAGAIN;
    }

    return actual_size;
}

int mbm_drv_close(void *ctx, int fd)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_slave_info_t *pslave_info = pdrv_ctx->mb_slave_info[fd]; // get address of configuration

    if (!pslave_info) {
        // not valid opened fd
        errno = EBADF;
        return -1;
    }
    
    // stop socket 
    MB_SET_SLAVE_STATE(pslave_info, MB_SOCK_STATE_CLOSED);
    // port_close_connection((mb_slave_info_t *)pslave_info);
    mbm_drv_lock(ctx);
    FD_CLR(fd, &pdrv_ctx->open_set);
    delete_queues(pslave_info);
    if (pslave_info->addr_info.node_name_str != pslave_info->addr_info.ip_addr_str) {
        free((void *)pslave_info->addr_info.ip_addr_str); // slave ip addr string shall be freed
    }
    free((void *)pslave_info->addr_info.node_name_str);
    pslave_info->addr_info.node_name_str = NULL;
    pslave_info->addr_info.ip_addr_str = NULL;
    free(pslave_info);
    pdrv_ctx->mb_slave_info[fd] = NULL;
    mbm_drv_unlock(ctx);

    return 0;
}

static mb_slave_info_t *mbm_drv_get_next_config_from_set(void *ctx, int *pfd, fd_set *pfdset)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    if (!pfdset || !pfd) {
        return NULL;
    }
    mb_slave_info_t *pslave_info = NULL;
    for (int fd = *pfd; fd < MB_MAX_FDS; fd++) {
        pslave_info = pdrv_ctx->mb_slave_info[fd];
        if (pslave_info && (pslave_info->sock_id > 0)
            && (MB_GET_SLAVE_STATE(pslave_info) >= MB_SOCK_STATE_CONNECTED) 
            && (FD_ISSET(pslave_info->index, pfdset) || (FD_ISSET(pslave_info->sock_id, pfdset)))) {
            *pfd = fd;
            //FD_CLR(pslave_info->sock_id, pfdset);
            return pslave_info;
        }
    }
    return NULL;
}

mb_slave_info_t *mbm_drv_get_slave_info_from_addr(void *ctx, uint8_t slave_addr)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_slave_info_t *pslave_info = NULL;
    for (int fd = 0; fd < MB_MAX_FDS; fd++) {
        pslave_info = pdrv_ctx->mb_slave_info[fd];
        if (pslave_info && pslave_info->addr_info.uid == slave_addr) {
            return pslave_info;
        }
    }
    return NULL;
}

static int mbm_drv_get_socket_max_fd(void *ctx, fd_set *pfdset)
{
    mb_slave_info_t *pslave_info = NULL;
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    // Setup select waiting for eventfd && socket events
    FD_ZERO(pfdset);
    int max_fd = -1;
    for (int i = 0; i < MB_MAX_FDS; i++) {
        pslave_info = pdrv_ctx->mb_slave_info[i];
        if (pslave_info && MB_GET_SLAVE_STATE(pslave_info) >= MB_SOCK_STATE_CONNECTED) {
            FD_SET(pslave_info->sock_id, pfdset);
            max_fd = pslave_info->sock_id > max_fd ? pslave_info->sock_id : max_fd;
        }
    }
    max_fd = (pdrv_ctx->event_fd > max_fd) ? pdrv_ctx->event_fd : max_fd;
    FD_SET(pdrv_ctx->event_fd, pfdset);
    return max_fd;
}

// Wait socket ready event during timeout
static int mbm_drv_wait_fd_events(void *ctx, fd_set *pfdset, fd_set *perrset, int time_ms)
{
    fd_set readset = *pfdset;
    int ret = 0;
    struct timeval tv;

    if (!ctx || !pfdset) {
        return -1;
    }

    tv.tv_sec = time_ms / 1000;
    tv.tv_usec = (time_ms - (tv.tv_sec * 1000)) * 1000;

    // fill the readset according to the active fds
    int max_fd = mbm_drv_get_socket_max_fd(ctx, &readset);
    if (perrset) {
        *perrset = readset; // initialize error set if used
    }

    ret = select(max_fd + 1, &readset, NULL, perrset, &tv);
    if (ret == 0) {
        // No respond from slave during timeout
        ret = ERR_TIMEOUT;
    } else if (ret < 0) {
        ret = -1;
    } 
    *pfdset = readset;
    return ret;
}

esp_err_t mbm_drv_start_task(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    (void)mbm_drv_clear_status_flag(ctx, MB_FLAG_SUSPEND);
    ESP_LOGW(TAG, "%p, resume tcp driver task.", ctx);
    vTaskResume(pdrv_ctx->mb_tcp_task_handle);
    return ESP_OK;
}

esp_err_t mbm_drv_stop_task(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    esp_err_t err = ESP_ERR_TIMEOUT;
    if (!pdrv_ctx->close_done_sema) {
        pdrv_ctx->close_done_sema = xSemaphoreCreateBinary();
    }
    (void)mbm_drv_set_status_flag(ctx, MB_FLAG_SUSPEND);
    // Check if we can safely suspend the port task (workaround for issue with deadlock in suspend)
    if (!pdrv_ctx->close_done_sema 
            || !(mbm_drv_wait_status_flag(ctx, MB_FLAG_SUSPEND, 1) & MB_FLAG_SUSPEND) 
            || (xSemaphoreTake(pdrv_ctx->close_done_sema, pdMS_TO_TICKS(MB_WAIT_DONE_MS)) != pdTRUE)
            ) {
        ESP_LOGW(TAG, "%p, could not stop driver task during timeout.", ctx);
        vTaskSuspend(pdrv_ctx->mb_tcp_task_handle);
        err = ESP_OK;
    }
    ESP_LOGW(TAG, "%p, stop tcp driver task.", ctx);
    if (pdrv_ctx->close_done_sema) {
        vSemaphoreDelete(pdrv_ctx->close_done_sema);
        pdrv_ctx->close_done_sema = NULL;
    }
    return err;
}

void mbm_drv_tcp_task(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    ESP_LOGD(TAG, "Start of driver task.");
    while (1) {
        fd_set readset, errorset;
        // check all active socket and fd events
        int ret = mbm_drv_wait_fd_events(ctx, &readset, &errorset, MB_SELECT_WAIT_MS);
        if (ret == ERR_TIMEOUT) {
            // timeout occured waiting for the vfds
            ESP_LOGW(TAG, "%p, task select timeout.", ctx);
            mbm_drv_check_suspend_shutdown(ctx);
        } else if (ret == -1) {
            // error occured during waiting for vfds activation
            ESP_LOGW(TAG, "%p, task select error.", ctx);
            mbm_drv_check_suspend_shutdown(ctx);
            ESP_LOGD(TAG, "%p, socket error, fdset: %" PRIx64, ctx, *(uint64_t *)&errorset);
        } else {
            // Is the fd event triggered, process the event
            if (FD_ISSET(pdrv_ctx->event_fd, &readset)) {
                mb_event_info_t mbm_event = {0};
                int32_t event_id = read_event(ctx, &mbm_event);
                ESP_LOGW(TAG, "%p, fd event get: 0x%02x:%d, %s", 
                            ctx, (int)event_id, (int)mbm_event.opt_fd, driver_event_to_name_r(event_id));
                mbm_drv_check_suspend_shutdown(ctx);
                // Drive the event loop
                esp_err_t err = esp_event_loop_run(mbm_drv_loop_handle, pdMS_TO_TICKS(MB_TCP_EVENT_LOOP_TICK_MS));
                if (err != ESP_OK) {
                    ESP_LOGE(TAG, "%p, event loop run, returns fail: %x", ctx, (int)err);
                }
            } else {   // socket data is ready, process each socket event
                mbm_drv_check_suspend_shutdown(ctx);
                int curr_fd = 0;
                mb_slave_info_t *pslave_info = NULL;
                ESP_LOGW(TAG, "%p, socket event active: %" PRIx64, ctx, *(uint64_t *)&readset);
                while(((pslave_info = (mb_slave_info_t *)mbm_drv_get_next_config_from_set(ctx, &curr_fd, &readset)) 
                           && (curr_fd < MB_MAX_FDS))) {
                    if (FD_ISSET(pslave_info->sock_id, &pdrv_ctx->conn_set)) {
                        // The data is ready in the socket, read frame and queue
                        FD_CLR(pslave_info->sock_id, &readset);
                        int ret = port_read_packet(pdrv_ctx->parent, pslave_info);
                        if (ret > 0) {
                            ESP_LOGD(TAG, "%p, "MB_SLAVE_FMT(", frame received."), ctx, (int)pslave_info->fd,
                                        (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str);
                            mbm_drv_lock(ctx);
                            pslave_info->recv_time = esp_timer_get_time();
                            mbm_drv_unlock(ctx);
                            DRIVER_SEND_EVENT(ctx, MB_EVENT_RECV_DATA, pslave_info->index);
                        } else if (ret == ERR_TIMEOUT) {
                            ESP_LOGD(TAG, "%p, "MB_SLAVE_FMT(", frame read timeout."), ctx, (int)pslave_info->fd,
                                        (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str);
                        } else if (ret == ERR_BUF) {
                            // After retries a response with incorrect TID received, process failure.
                            pdrv_ctx->event_cbs.mb_sync_event_cb(pdrv_ctx->event_cbs.port_arg, MB_SYNC_EVENT_RECV_FAIL);
                            ESP_LOGW(TAG, "%p, "MB_SLAVE_FMT(", frame error."), ctx, (int)pslave_info->fd,
                                        (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str);
                        } else {
                            ESP_LOGE(TAG, "%p, "MB_SLAVE_FMT(", critical error=%d, errno=%u."), ctx, (int)pslave_info->fd,
                                        (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str, (int)ret, (unsigned)errno);
                            if (ret == ERR_CONN) {
                                ESP_LOGW(TAG, "%p, "MB_SLAVE_FMT(", connection lost."), ctx, (int)pslave_info->fd,
                                            (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str);
                                DRIVER_SEND_EVENT(ctx, MB_EVENT_RECONNECT, pslave_info->index);
                            }
                        }
                    }
                    curr_fd++;
                    mbm_drv_check_suspend_shutdown(ctx);
                }
            }
        }
    }
}

EVENT_HANDLER(on_reconnect)
{
    static int curr_fd = 0;
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    mb_slave_info_t *pslave_info = NULL;
    if (MB_CHECK_FD_RANGE(pevent_info->opt_fd)) {
        curr_fd = pevent_info->opt_fd;
        pslave_info = mbm_drv_get_next_config_from_set(ctx, &curr_fd, &pdrv_ctx->conn_set);
        if (pslave_info) {
            uint64_t last_read_div_us = esp_timer_get_time() - pslave_info->recv_time;
            ESP_LOGW(TAG, "%p, slave: %d, sock: %d, IP:%s, check connection, time = %" PRId64 ", rcv_time: %" PRId64,
                    ctx, (int)pslave_info->index, (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str,
                    (esp_timer_get_time() / 1000), pslave_info->recv_time / 1000);
            if (last_read_div_us >= (uint64_t)(MB_RECONNECT_TIME_MS * 1000)) {
                err_t err = port_check_alive(pslave_info, MB_RECONNECT_TIME_MS);
                if (err < 0) {
                    ESP_LOGW(TAG, "%p, slave: %d, sock: %d, inactive for %" PRId64 " [ms], reconnect...",
                            ctx, (int)pslave_info->index, (int)pslave_info->sock_id,
                            (last_read_div_us / 1000));
                    MB_SET_SLAVE_STATE(pslave_info, MB_SOCK_STATE_OPENED);
                    FD_CLR(pslave_info->sock_id, &pdrv_ctx->conn_set);
                    port_close_connection(pslave_info);
                    mbm_drv_lock(ctx);
                    pdrv_ctx->slave_conn_count--;
                    mbm_drv_unlock(ctx);
                    DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pslave_info->index);
                } else {
                    curr_fd++;
                }
            } else {
                ESP_LOGW(TAG, "%p, slave: %d, sock: %d, inactive for %" PRId64 " [ms], wait reconnection...",
                            ctx, (int)pslave_info->index, (int)pslave_info->sock_id,
                            (last_read_div_us / 1000));
            }
        }
    } else if (pevent_info->opt_fd < 0) {
        // send resolve event to all slaves
        for (int fd = 0; fd < pdrv_ctx->mb_slave_open_count; fd++) {
            mb_slave_info_t *pslave = pdrv_ctx->mb_slave_info[fd];
            if (pslave && (MB_GET_SLAVE_STATE(pslave) == MB_SOCK_STATE_OPENED) 
                && FD_ISSET(pslave->index, &pdrv_ctx->open_set)) {
                DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pslave->index);
            }
            mbm_drv_check_suspend_shutdown(ctx);
        }
    }
}

EVENT_HANDLER(on_ready)
{
    // The driver is registered
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGW(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
}

EVENT_HANDLER(on_open)
{
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGW(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
}

EVENT_HANDLER(on_resolve)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGW(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    if (MB_CHECK_FD_RANGE(pevent_info->opt_fd)) {
        // The mdns is not used in the main app, then can use manually defined IPs
        int fd = pevent_info->opt_fd;
        mb_slave_info_t *pslave = pdrv_ctx->mb_slave_info[fd];
        if (pslave && (MB_GET_SLAVE_STATE(pslave) == MB_SOCK_STATE_OPENED) 
                    && FD_ISSET(pslave->index, &pdrv_ctx->open_set)) {
            // The slave IP is defined manually
            if (port_check_host_addr(pslave->addr_info.node_name_str, NULL)) {
                pslave->addr_info.ip_addr_str = pslave->addr_info.node_name_str;
                ESP_LOGW(TAG, "%p, slave: %d, IP address [%s], added to connection list.", ctx, (int)fd, pslave->addr_info.ip_addr_str);
                MB_SET_SLAVE_STATE(pslave, MB_SOCK_STATE_RESOLVED);
                DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pslave->index);
            } else {
#ifdef MB_MDNS_IS_INCLUDED
                int ret = port_resolve_mdns_host(pslave->addr_info.node_name_str, (char **)&pslave->addr_info.ip_addr_str);
                if (ret > 0) {
                    ESP_LOGI(TAG, "%p, slave: %d, resolved with IP:%s.", ctx, (int)fd, pslave->addr_info.ip_addr_str);
                    MB_SET_SLAVE_STATE(pslave, MB_SOCK_STATE_RESOLVED);
                    DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pslave->index);
                } else {
                    // continue resolve while not resolved
                    DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pslave->index);
                }
#else
                ESP_LOGE(TAG, "%p, slave: %d, IP:%s, mdns service is not supported.", ctx, (int)fd, pslave->addr_info.node_name_str);
                DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pslave->index);
#endif
            }
        }
    } else if (pevent_info->opt_fd < 0) {
        // Todo: Removed from this version 
        // #ifdef MB_MDNS_IS_INCLUDED
        //         // If the mDNS feature support is enabled, use it to resolve the slave IP
        //         res = mbm_drv_resolve_mdns_service(ctx, "_modbus", "_tcp", pdrv_ctx->addr_type);
        //         ESP_LOGW(TAG, "%p, use mdns to resolve slave: %d, resolved: %d devices.", ctx, (int)pevent_info->opt_fd, res);
        // #else
        for (int fd = 0; fd < pdrv_ctx->mb_slave_open_count; fd++) {
            mb_slave_info_t *pslave = pdrv_ctx->mb_slave_info[fd];
            if (pslave && (MB_GET_SLAVE_STATE(pslave) == MB_SOCK_STATE_OPENED) 
                    && FD_ISSET(pslave->index, &pdrv_ctx->open_set)) {
                DRIVER_SEND_EVENT(ctx, MB_EVENT_RESOLVE, pslave->index);
            }
            mbm_drv_check_suspend_shutdown(ctx);
        }
        // #endif
    }
}

EVENT_HANDLER(on_connect)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_slave_info_t *pslave_info = NULL;
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGW(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    err_t err = ERR_CONN;
    if (MB_CHECK_FD_RANGE(pevent_info->opt_fd)) {
        pslave_info = pdrv_ctx->mb_slave_info[pevent_info->opt_fd];
        if (pslave_info && (MB_GET_SLAVE_STATE(pslave_info) < MB_SOCK_STATE_CONNECTED)) {
            ESP_LOGW(TAG, "%p, connection phase, slave: #%d(%d) [%s].",
                     ctx, (int)pevent_info->opt_fd, (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str);
            if (pslave_info->sock_id != -1) {
                port_close_connection(pslave_info);
            }
            err = port_connect(ctx, pslave_info);
            switch (err) {
                case ERR_OK:
                    if (!FD_ISSET(pslave_info->sock_id, &pdrv_ctx->conn_set)) {
                        FD_SET(pslave_info->sock_id, &pdrv_ctx->conn_set);
                        mbm_drv_lock(ctx);
                        pdrv_ctx->slave_conn_count++;
                        pdrv_ctx->max_conn_sd = (pslave_info->sock_id > pdrv_ctx->max_conn_sd) ? (int)pslave_info->sock_id : pdrv_ctx->max_conn_sd;
                        // Update time stamp for connected slaves
                        pslave_info->send_time = esp_timer_get_time();
                        pslave_info->recv_time = esp_timer_get_time();
                        mbm_drv_unlock(ctx);
                        ESP_LOGI(TAG, "%p, slave: #%d, sock:%d, IP: %s, is connected.",
                                ctx, (int)pevent_info->opt_fd, (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str);
                    }
                    MB_SET_SLAVE_STATE(pslave_info, MB_SOCK_STATE_CONNECTED);
                    port_keep_alive(pslave_info);
                    break;
                case ERR_INPROGRESS:
                    if (FD_ISSET(pslave_info->sock_id, &pdrv_ctx->conn_set)) {
                        FD_CLR(pslave_info->sock_id, &pdrv_ctx->conn_set);
                        ESP_LOGW(TAG, "%p, slave: #%d, sock:%d, IP:%s, connect fail error = %d.",
                                ctx, (int)pevent_info->opt_fd, (int)pslave_info->sock_id,
                                pslave_info->addr_info.ip_addr_str, (int)err);
                        mbm_drv_lock(ctx);
                        if (pdrv_ctx->slave_conn_count) {
                            pdrv_ctx->slave_conn_count--;
                        }
                        mbm_drv_unlock(ctx);
                    }
                    MB_SET_SLAVE_STATE(pslave_info, MB_SOCK_STATE_CONNECTING);
                    vTaskDelay(MB_CONN_TICK_TIMEOUT);
                    // try to connect to slave and check connection again if it is not connected
                    DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pevent_info->opt_fd);
                    break;
                case ERR_CONN:
                    ESP_LOGE(TAG, "Modbus connection phase, slave: %d [%s], connection error (%d).",
                            (int)pevent_info->opt_fd, pslave_info->addr_info.ip_addr_str, (int)err);
                    break;
                default:
                    ESP_LOGE(TAG, "Invalid error state, slave: %d [%s], error = %d.",
                            (int)pevent_info->opt_fd, pslave_info->addr_info.ip_addr_str, (int)err);
                    break;
            }
        }
    } else {
        // if the event fd is -1 (an event for all slaves),
        // then perform connection phase for all resolved slaves sending the connection event
        for (int node = 0; (node < MB_TCP_PORT_MAX_CONN); node++) {
            pslave_info = pdrv_ctx->mb_slave_info[node];
            if (pslave_info && (MB_GET_SLAVE_STATE(pslave_info) == MB_SOCK_STATE_RESOLVED)) {
                if (((pslave_info->sock_id < 0) || !FD_ISSET(pslave_info->sock_id, &pdrv_ctx->conn_set)) 
                            && FD_ISSET(node, &pdrv_ctx->open_set)) {
                    DRIVER_SEND_EVENT(ctx, MB_EVENT_CONNECT, pslave_info->index);
                }
            }
            mbm_drv_check_suspend_shutdown(ctx);
        }
    }
    ESP_LOGD(TAG, "Opened/connected: %u, %u.", 
                (unsigned)pdrv_ctx->mb_slave_open_count, (unsigned)pdrv_ctx->slave_conn_count);
    if (pdrv_ctx->mb_slave_open_count == pdrv_ctx->slave_conn_count) {
        if (pdrv_ctx->event_cbs.on_conn_done_cb) {
            pdrv_ctx->event_cbs.on_conn_done_cb(pdrv_ctx->event_cbs.arg);
        }
        ESP_LOGI(TAG, "%p, Connected: %u, %u, start polling.", 
                    ctx, (unsigned)pdrv_ctx->mb_slave_open_count, (unsigned)pdrv_ctx->slave_conn_count);
    }
}

EVENT_HANDLER(on_send_data)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGW(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    mb_slave_info_t *pinfo = pdrv_ctx->mb_slave_info[pevent_info->opt_fd];
    if (pinfo && !queue_is_empty(pinfo->tx_queue)) {
        uint8_t tx_buffer[MB_TCP_BUFF_MAX_SIZE] = {0};
        ESP_LOGW(TAG, "%p, get info: %d, sock_id: %d, queue_state: %d, state: %d.",
                    ctx, (int)pevent_info->opt_fd, (int)pinfo->sock_id, 
                    (int)queue_is_empty(pinfo->tx_queue), (int)MB_GET_SLAVE_STATE(pinfo));
        size_t sz = queue_pop(pinfo->tx_queue, tx_buffer, sizeof(tx_buffer), NULL);
        if (MB_GET_SLAVE_STATE(pinfo) < MB_SOCK_STATE_CONNECTED) {
            mbm_drv_lock(ctx);
            pdrv_ctx->mb_slave_curr_info = pinfo;
            mbm_drv_unlock(ctx);
            // if slave is not connected, drop data.
            ESP_LOGE(TAG, "%p, "MB_SLAVE_FMT(", is invalid, drop send data."),
                        ctx, (int)pinfo->index, (int)pinfo->sock_id, pinfo->addr_info.ip_addr_str);
            return;
        }
        int ret = port_write_poll(pinfo, tx_buffer, sz, MB_TCP_SEND_TIMEOUT_MS);
        if (ret < 0) {
            ESP_LOGE(TAG, "%p, "MB_SLAVE_FMT(", send data failure, err(errno) = %d(%u)."),
                        ctx, (int)pinfo->index, (int)pinfo->sock_id, 
                        pinfo->addr_info.ip_addr_str, (int)ret, (unsigned)errno);
            DRIVER_SEND_EVENT(ctx, MB_EVENT_RECONNECT, pinfo->index);
            pinfo->error = ret;
        } else {
            ESP_LOGD(TAG, "%p, "MB_SLAVE_FMT(", send data successful: TID=0x%04x, %d (bytes), errno %d"),
                        ctx, (int)pinfo->index, (int)pinfo->sock_id, 
                        pinfo->addr_info.ip_addr_str, pinfo->tid_counter, (int)ret, (unsigned)errno);
            pinfo->error = 0;
            // Every successful write increase TID counter
            if (pinfo->tid_counter < (USHRT_MAX - 1)) {
                pinfo->tid_counter++;
            } else {
                pinfo->tid_counter = (uint16_t)(pinfo->index << 8U);
            }
        }
        pdrv_ctx->event_cbs.mb_sync_event_cb(pdrv_ctx->event_cbs.port_arg, MB_SYNC_EVENT_SEND_OK);
        mbm_drv_lock(ctx);
        pdrv_ctx->mb_slave_curr_info = pinfo;
        pinfo->send_time = esp_timer_get_time();
        pinfo->send_counter = (pinfo->send_counter < (USHRT_MAX - 1)) ? (pinfo->send_counter + 1) : 0;
        mbm_drv_unlock(ctx);
        // Get send buffer from stack
        ESP_LOG_BUFFER_HEX_LEVEL("SENT", tx_buffer, sz, ESP_LOG_WARN);
    }
}

EVENT_HANDLER(on_recv_data)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGW(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    size_t sz = 0;
    uint8_t pbuf[MB_TCP_BUFF_MAX_SIZE] = {0};
    // Get frame from queue, check for correctness, push back correct frame and generate receive condition.
    // Removes incorrect or expired frames from the queue, leave just correct one then sent sync event
    mb_slave_info_t *pslave_info = pdrv_ctx->mb_slave_info[pevent_info->opt_fd];
    if (pslave_info) {
        ESP_LOGI(TAG, "%p, slave #%d(%d) [%s], receive data ready.", ctx, (int)pevent_info->opt_fd, 
                    (int)pslave_info->sock_id, pslave_info->addr_info.ip_addr_str);
        while ((sz <= 0) && !queue_is_empty(pslave_info->rx_queue)) {
            size_t sz = queue_pop(pslave_info->rx_queue, pbuf, MB_TCP_BUFF_MAX_SIZE, NULL);
            if ((sz > MB_TCP_FUNC) && (sz < sizeof(pbuf))) {
                uint16_t tid = MB_TCP_MBAP_GET_FIELD(pbuf, MB_TCP_TID);
                ESP_LOGW(TAG, "%p, packet TID: #%.4x received.", ctx, tid);
                if (tid == (pslave_info->tid_counter - 1)) {
                    queue_push(pslave_info->rx_queue, pbuf, sz, NULL);
                    mbm_drv_lock(ctx);
                    pslave_info->recv_time = esp_timer_get_time();
                    mbm_drv_unlock(ctx);
                    // send receive event to modbus object
                    pdrv_ctx->event_cbs.mb_sync_event_cb(pdrv_ctx->event_cbs.port_arg, MB_SYNC_EVENT_RECV_OK);
                    break;
                }
            }
            mbm_drv_check_suspend_shutdown(ctx);
        }
    }
}

EVENT_HANDLER(on_close)
{
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGW(TAG, "%s  %s, fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    // if close all sockets event is received
    if (pevent_info->opt_fd < 0) {
        (void)mbm_drv_clear_status_flag(pdrv_ctx, MB_FLAG_DISCONNECTED);
        for (int fd = 0; fd < MB_MAX_FDS; fd++) {
            mb_slave_info_t *pslave = pdrv_ctx->mb_slave_info[fd];
            if (pslave && (MB_GET_SLAVE_STATE(pslave) >= MB_SOCK_STATE_OPENED) 
                    && FD_ISSET(pslave->index, &pdrv_ctx->open_set)) {
                mbm_drv_lock(ctx);              
                // Check connection and unregister slave
                if ((pslave->sock_id > 0) && (FD_ISSET(pslave->sock_id, &pdrv_ctx->conn_set)) ) {
                    FD_CLR(pslave->sock_id, &pdrv_ctx->conn_set);
                    if (pdrv_ctx->slave_conn_count) {
                        pdrv_ctx->slave_conn_count--;
                    }
                }
                FD_CLR(pslave->index, &pdrv_ctx->open_set);
                mbm_drv_unlock(ctx);
                // close the socket connection, if active
                (void)port_close_connection(pslave);
                // change slave state immediately to release from select
                MB_SET_SLAVE_STATE(pslave, MB_SOCK_STATE_READY);
            }
        }
        (void)mbm_drv_set_status_flag(pdrv_ctx, MB_FLAG_DISCONNECTED);
        mbm_drv_check_suspend_shutdown(ctx);
    }
}

EVENT_HANDLER(on_timeout)
{
    // Slave timeout triggered
    mb_event_info_t *pevent_info = (mb_event_info_t *)data;
    ESP_LOGW(TAG, "%s  %s: fd: %d", (char *)base, __func__, (int)pevent_info->opt_fd);
    mbm_drv_check_suspend_shutdown(ctx);
}

esp_err_t mbm_drv_register(port_driver_t **ctx)
{
    port_driver_t driver_config = MB_DRIVER_CONFIG_DEFAULT;
    esp_err_t ret = ESP_ERR_INVALID_STATE;
    
    port_driver_t *pctx = (port_driver_t *)calloc(1, sizeof(port_driver_t));
    MB_GOTO_ON_FALSE((pctx), ESP_ERR_NO_MEM, error, TAG, "%p, driver allocation fail.", pctx);
    *pctx = driver_config;
    //spinlock_initialize(&driver_config.spin_lock);
    CRITICAL_SECTION_INIT(pctx->lock);

    // create and initialize modbus driver conetext structure
    pctx->mb_slave_info = calloc(MB_MAX_FDS, sizeof(mb_slave_info_t *));
    MB_GOTO_ON_FALSE((pctx->mb_slave_info), ESP_ERR_NO_MEM, error, TAG, "%p, node allocation fail.", pctx);

    for (int i = 0; i < MB_MAX_FDS; i++) {
        pctx->mb_slave_info[i] = NULL;
    }

    ret = init_event_fd((void *)pctx);
    MB_GOTO_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE , error, 
                        TAG, "%p, vfs eventfd init error.", pctx);

    ret = mbm_drv_event_loop_init((void *)pctx);
    MB_GOTO_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE , error, 
                        TAG, "%p, event loop init error.", pctx);
    
    ret = mbm_drv_register_handlers((void *)pctx);
    MB_GOTO_ON_FALSE((ret == ESP_OK), ESP_ERR_INVALID_STATE , error, 
                        TAG, "%p, event handler registration error.", pctx);

    pctx->status_flags_hdl = xEventGroupCreate();
    MB_GOTO_ON_FALSE((pctx->status_flags_hdl), ESP_ERR_INVALID_STATE, error, 
                        TAG, "%p, mb event group error.", pctx);

    mbm_drv_loop_inst_counter++;

#ifdef MB_MDNS_IS_INCLUDED
    port_start_mdns_service();
#endif

    // Create task for packet processing
    BaseType_t state = xTaskCreatePinnedToCore(mbm_drv_tcp_task,
                                                "mbm_drv_tcp_task",
                                                MB_TASK_STACK_SZ,
                                                pctx,
                                                MB_TASK_PRIO,
                                                &pctx->mb_tcp_task_handle,
                                                MB_PORT_TASK_AFFINITY);
    MB_GOTO_ON_FALSE((state == pdTRUE), ESP_ERR_INVALID_STATE , error, 
                        TAG, "%p, event task creation error.", pctx);
    
    (void)mbm_drv_stop_task(pctx);

    *ctx = pctx;
    pctx->is_registered = true;
    FD_ZERO(&pctx->open_set);
    FD_ZERO(&pctx->conn_set);
    DRIVER_SEND_EVENT((void *)pctx, MB_EVENT_READY, -1);
    return ESP_OK;

error:
    if (pctx) {
        if (pctx->mb_tcp_task_handle) {
            vTaskDelete(pctx->mb_tcp_task_handle);
        }
        if (pctx->event_handler) {
            mbm_drv_unregister_handlers(pctx);
            pctx->event_handler = NULL;
        }
        if (mbm_drv_loop_handle) {
            (void)esp_event_loop_delete(mbm_drv_loop_handle);
            mbm_drv_loop_handle = NULL;
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
        free(pctx->mb_slave_info);
    }
    free(pctx);
    return ret;
}

esp_err_t mbm_drv_unregister(void *ctx)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    ESP_LOGW(TAG, "%p, driver unregister.", pdrv_ctx);
    pdrv_ctx->close_done_sema = xSemaphoreCreateBinary();
    (void)mbm_drv_set_status_flag(ctx, MB_FLAG_SHUTDOWN);

    // Change the state of all slaves to close
    //DRIVER_SEND_EVENT(ctx, MB_EVENT_CLOSE, -1);
    //(void)mbm_drv_wait_status_flag(ctx, MB_FLAG_DISCONNECTED, MB_RECONNECT_TIME_MS);

    // if no semaphore (alloc issues) or couldn't acquire it, just delete the task
    if (!pdrv_ctx->close_done_sema 
            || !(mbm_drv_wait_status_flag(ctx, MB_FLAG_SHUTDOWN, 0) & MB_FLAG_SHUTDOWN) 
            || (xSemaphoreTake(pdrv_ctx->close_done_sema, pdMS_TO_TICKS(MB_WAIT_DONE_MS)) != pdTRUE)
            ) {
        ESP_LOGW(TAG, "%p, driver tasks couldn't exit within timeout -> abruptly deleting the task.", pdrv_ctx);
        vTaskDelete(pdrv_ctx->mb_tcp_task_handle);
    }

    mbm_drv_unregister_handlers(ctx);
    mbm_drv_event_loop_deinit(ctx);
    
    if (pdrv_ctx->close_done_sema) {
        vSemaphoreDelete(pdrv_ctx->close_done_sema);
        pdrv_ctx->close_done_sema = NULL;
    }

    esp_err_t err = close_event_fd(ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "could not close the eventfd handle, err = %d. Already closed?", err);
    }

    for (int i = 0; i < MB_MAX_FDS; i++) {
        mb_slave_info_t *pslave_info = pdrv_ctx->mb_slave_info[i];
        if (pslave_info) {
            ESP_LOGW(TAG, "%p, close slave instance #%d(%s).", ctx, i, pslave_info->addr_info.node_name_str);
            mbm_drv_close(ctx, i);
        }
    }

    free(pdrv_ctx->mb_slave_info); // free the slave info address array
    pdrv_ctx->mb_slave_info = NULL;

    vEventGroupDelete(pdrv_ctx->status_flags_hdl);

    // if the MDNS resolving is enabled, then free it
#ifdef MB_MDNS_IS_INCLUDED
    mdns_free();
#endif

    pdrv_ctx->is_registered = false;
    free(pdrv_ctx);

    return ESP_OK;
}

void mbm_drv_set_cb(void *ctx, void *conn_cb, void *arg)
{
    port_driver_t *pdrv_ctx = GET_CONFIG_PTR(ctx);
    mbm_drv_lock(ctx);
    pdrv_ctx->event_cbs.on_conn_done_cb = conn_cb;
    pdrv_ctx->event_cbs.arg = arg;
    mbm_drv_unlock(ctx);
}

#endif