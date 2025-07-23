.. _modbus_api_port_initialization:

Modbus Port Initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^

The ESP_Modbus supports Modbus SERIAL and TCP communication objects and an object must be initialized before calling any other Modbus API. The functions below are used to create and then initialize Modbus controller interface (either master or slave) over a particular transmission medium (either Serial or TCP/IP):

- :cpp:func:`mbc_slave_create_serial`
- :cpp:func:`mbc_master_create_serial`
- :cpp:func:`mbc_master_create_tcp`
- :cpp:func:`mbc_slave_create_tcp`

Calling the constructor function allows to create communication object with the specific communication options be defined in the configuration structure. The pointer to communication object is returned by constructor API and is being used as a handle for each following API call.

.. code:: c

    // Pointer to allocate interface structure 
    // is used later as a first parameter for each API call
    static void *master_handle = NULL;
    ESP_ERROR_CHECK(mbc_master_create_serial(&config, &master_handle));
    ...

.. code:: c

    static void *master_handle = NULL;
    ESP_ERROR_CHECK(mbc_master_create_tcp(&config, &master_handle));
    ...

.. code:: c

    static void *slave_handle = NULL;
    ESP_ERROR_CHECK(mbc_slave_create_tcp(&config, &slave_handle));
    ...

.. code:: c

    static void *slave_handle = NULL;
    ESP_ERROR_CHECK(mbc_slave_create_serial(&config, &slave_handle));
    ...

Refer to :ref:`modbus_api_master_setup_communication_options` and :ref:`modbus_api_slave_setup_communication_options` for more information on how to configure communication options for the master and slave object accordingly.

.. _modbus_api_master_setup_communication_options:

Master Communication Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The configuration structure is used to recognize the type of object being initialized. An example of initialization for Modbus serial master in RTU is below. The configuration structure provided as a parameter and is different for serial and TCP communication mode.

.. code:: c

    #define MB_PORT_NUM 2
    #define MB_DEV_SPEED 115200
    static void *master_handle = NULL;
    ....
    // Initialize Modbus controller
    mb_communication_info_t config = {
        .ser_opts.port = MB_PORT_NUM,           // master communication port number
        .ser_opts.mode = MB_RTU,                // mode of Modbus communication (MB_RTU, MB_ASCII)
        .ser_opts.baudrate = MB_DEV_SPEED,      // baud rate of the port
        .ser_opts.parity = MB_PARITY_NONE,      // parity option for the port
        .ser_opts.uid = 0,                      // unused for master
        .ser_opts.response_tout_ms = 1000,      // slave response time for master (if = 0, taken from default config)
        .ser_opts.data_bits = UART_DATA_8_BITS, // number of data bits for communication port
        .ser_opts.stop_bits = UART_STOP_BITS_1  // number of stop bits for the communication port
    };
    esp_err_t err = mbc_master_create_serial(&config, &master_handle);
    if (master_handler == NULL || err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller initialization fail.");
    }

.. note:: RS485 communication requires call to UART specific APIs to setup communication mode and pins. Refer to the `UART communication section <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/peripherals/uart.html#uart-api-running-uart-communication>`__ in documentation.

An example of initialization for Modbus TCP master is below. The Modbus master TCP requires additional definition of IP address table where number of addresses should be equal to number of unique slave addresses in master Modbus Data Dictionary. The Unit Identifier defined in the table below corresponds to UID (slave short address field) in the Data Dictionary.
The format of slave definition following the notation `UID;slave_host_ip_or_dns_name;port_number` and allows some variations as described in the example below.

.. code:: c

    // This is public pointer for the module and used by master
    // to resolve slave addresses and reconnect when connection is broken
    static char *slave_ip_address_table[] = {
        "01;mb_slave_tcp_01;502",       // Define the slave using mdns host name ("mb_slave_tcp_01") with UID = 01 and communication port 502
        "200;mb_slave_tcp_c8;1502",     // Definition of slave with mdns name "mb_slave_tcp_C8" and UID = 200, port = 1502
        "35;192.168.32.54;1502",        // Definition of slave with the static IPV4 address and UID = 35, port = 502
        "12:2001:0db8:85a3:0000:0000:8a2e:0370:7334:502",        // Definition of the slave with static IPV6 address and UID = 12, port = 502
        NULL                            // End of table condition (must be included)
    };

.. code:: c

    #define MB_TCP_PORT 502
    static void *master_handle = NULL;
    ....
    mb_communication_info_t tcp_master_config = {
        .tcp_opts.port = MB_TCP_PORT,                               // Default TCP Port number
        .tcp_opts.mode = MB_TCP,                                    // TCP mode of communication
        .tcp_opts.addr_type = MB_IPV4,                              // type of IP address (MB_IPV4, MB_IPV6)
        .tcp_opts.ip_addr_table = (void *)slave_ip_address_table,   // list of slaves for master (must be defined)
        .tcp_opts.uid = 0,                                          // the UID unused for master
        .tcp_opts.start_disconnected = false,                       // false - manage connections to all slaves before start
        .tcp_opts.response_tout_ms = 2000,                          // slave response time in milliseconds for master, 0 - use default konfig
        .tcp_opts.ip_netif_ptr = (void*)get_example_netif(),        // the pointer to netif inteface
    };
    esp_err_t err = mbc_master_create_tcp(pcomm_info, &master_handle);
    if (master_handler == NULL || err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller initialization fail.");
    }

.. note:: Refer to `esp_netif component <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_netif.html>`__ for more information about network interface initialization.

The slave IP addresses of the slaves can be resolved automatically by the stack using mDNS service as described in the example. In this case each slave has to use the mDNS service support and define its host name appropriately.
Refer to :ref:`example TCP master <example_mb_tcp_master>`, :ref:`example TCP slave <example_mb_tcp_slave>` for more information.

.. note:: The Modbus Master TCP functionality is under testing and competition status will be announced later over official channels.

.. _modbus_api_slave_setup_communication_options:

Slave Communication Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The function initializes the Modbus controller interface and its active context (tasks, RTOS objects and other resources).

This example code to initialize Modbus serial slave:

.. code:: c

    #define MB_PORT_NUM 2
    #define MB_DEV_SPEED 115200
    #define MB_SLAVE_ADDR 1
    static void* slave_handle = NULL;
    ....
    mb_communication_info_t config = {
        .ser_opts.port = MB_PORT_NUM,
        .ser_opts.mode = MB_ASCII,              // ASCII communication mode
        .ser_opts.baudrate = MB_DEV_SPEED,
        .ser_opts.parity = MB_PARITY_NONE,
        .ser_opts.uid = MB_SLAVE_ADDR,          // Modbus slave UID - Unit Identifier (short address)
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1
    };
    // Initialization and setup of Modbus serial slave in ASCII communication mode
    esp_err_t err = mbc_slave_create_serial(&config, &slave_handle);
    if (slave_handle == NULL || err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller initialization fail.");
    }

.. note:: RS485 communication requires call to UART specific APIs to setup communication mode and pins. Refer to the `UART communication section <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/peripherals/uart.html#uart-api-running-uart-communication>`__ in documentation.

This example code to initialize Modbus TCP slave:

.. code:: c

    #define MB_SLAVE_ADDR 1
    #define MB_TCP_PORT_NUMBER 1502
    static void* slave_handle = NULL;
    ....
    mb_communication_info_t tcp_slave_config = {
        .tcp_opts.port = MB_TCP_PORT_NUMBER,                // communication port number for Modbus slave
        .tcp_opts.mode = MB_TCP,                            // mode of communication for slave
        .tcp_opts.addr_type = MB_IPV4,                      // type of addressing being used
        .tcp_opts.ip_addr_table = NULL,                     // Bind to any address
        .tcp_opts.ip_netif_ptr = (void*)get_example_netif(),// the pointer to netif inteface
        .tcp_opts.uid = MB_SLAVE_ADDR                       // Modbus slave Unit Identifier
    };
    esp_err_t err = mbc_slave_create_tcp(&tcp_slave_config, &slave_handle);
    if (slave_handle == NULL || err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller initialization fail.");
    }

.. note:: Refer to `esp_netif component <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_netif.html>`__ for more information about network interface initialization.

.. _modbus_master_slave_configuration_aspects:

Important Configuration Aspects
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The slave and its behavior has some dependency with the master and its options. The master uses a timeout to determine if a slave is responding in a timely manner. This timeout is configured on the master side, not used by the slave. If the slave's response is not received within this timeout period, the master will consider the request a failure.

    * Master Timeout (``CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND``): This is the duration a master will wait for a response from the slave. The default value set by the ``CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND`` kconfig option on the master side can be overridden for the concrete master instance in its communication options structure. 

    * Slave Behavior: The slave itself does not use this timeout for its internal operations. Instead, it measures its request processing time, which is the time from receiving a master's request to sending the slave's response. If this processing time exceeds the master's configured timeout because the master sends a new request while the previous one is under processing, the slave will log a warning.

The Race Condition
~~~~~~~~~~~~~~~~~~

A common issue occurs when the slave's Request Processing Time is longer than the Master Timeout.

In this scenario:

    * The master sends a request.

    * The slave begins processing the request.

    * The master's timeout expires, and it marks the request as failed.

    * The master immediately sends a new request for the next transaction.

    * The slave finishes processing the first request and sends a response.

    * The slave then receives the master's new request, potentially before the previous response is sent.

The TCP slave's log message, such as ``W (571368) mb_port.tcp.slave: 0x3ffc8ba4, node #1, socket(#56)(192.168.88.250), handling time [ms]: 1394, exceeds slave response time in master.``, indicates this condition. The slave is warning that its internal processing time of 1394 ms was longer than the timeout configured on the master.

To prevent the race condition from occurring, the slave will discard the pending response to the master's first request to avoid potential errors and an overloaded input queue. On the master side, this situation results in a timeout error for the first request, followed by the successful start of the next one. If the reasons for the race condition are not addressed, this can lead to the slave's input queues becoming cluttered, potentially causing the slave to stop responding altogether.

Corrective Actions
@@@@@@@@@@@@@@@@@@

To resolve this, user must:

    * Increase the Master Timeout (``CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND``) to be significantly greater than the maximum expected Request Processing Time on the slave.

    * Reduce the request rate from the master nodes to give the slave more time to process each request.

.. note:: Set the Master Timeout to a value greater than the worst-case Round-Trip Time (RTT) on your network. A reasonable starting point is at least 1000 ms, but you should perform network measurements under maximum load to determine an appropriate value.

Keep-Alive Mechanism for TCP Slave
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Modbus TCP slave includes a `TCP keep-alive mechanism <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/lwip.html#tcp-options>`__ to detect dead connections and free up resources. This feature is enabled by default.

* Keep-Alive Timeout (``CONFIG_FMB_TCP_KEEP_ALIVE_TOUT_SEC``): This is the time after which the slave will send a keep-alive probe to the master if no data has been received. If the master does not respond to this probe, the slave considers the connection dead and closes it. The keep-alive timeout is configured using the ``CONFIG_FMB_TCP_KEEP_ALIVE_TOUT_SEC`` kconfig option.

Corrective Actions
@@@@@@@@@@@@@@@@@@

The TCP slave logs an error, such as ``E (227779) mb_port.tcp.slave: 0x3ffc8abc, node #4, socket(#59)(192.168.88.252), communication fail, err= -11``, when a connection is closed due to a keep-alive timeout.

.. note:: The keep-alive timeout should be configured carefully. It is recommended to set it to a value greater than the Master Timeout to avoid prematurely dropping a connection during a long-running transaction. Be mindful of the trade-off: a short timeout can drop good connections during temporary network issues and increase the RTT time, while a very long timeout can waste resources on dead connections and increase communication error detection time.

Manage Multiple Connections
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Modbus TCP slave supports multiple connections from external master nodes. The maximum number of simultaneous connections is configured using the ``CONFIG_FMB_TCP_PORT_MAX_CONN`` kconfig option. If the number of incoming connections exceeds this value, the slave will reject new connections. The slave manages the active connections and is able to close inactive connections that do not send requests for longer than the ``CONFIG_FMB_TCP_KEEP_ALIVE_TOUT_SEC`` time.

.. note:: Each additional master connection can increase the Request Processing Time on the slave. This, in turn, impacts the overall Round-Trip Time (RTT), which is the total time for a request to travel to the slave and a response to return to the master.
