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

.. note:: The Modbus library supports integration with the MDNS component in order to resolve the node names within the Modbus segment. This behavior is configurable and can be enabled by the ``CONFIG_FMB_MDNS_INTEGRATION_ENABLE`` kconfig value, which is enabled by default. This key allows you to disable MDNS integration and use IP addresses in the master configuration or use the MDNS resolution on the user project level. If the MDNS is disabled but the MDNS names are used in the configuration, the stack logs an error: ``E (20127) mb_port.tcp.master: 0x3ffc9ff0, slave: 2, IP:mb_slave_tcp_01, mdns service is not supported.``

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
