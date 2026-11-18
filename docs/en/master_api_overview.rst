.. _modbus_api_master_overview:

Modbus Master API Overview
--------------------------

The following overview describes how to set up Modbus master communication. The overview reflects a typical programming workflow and is broken down into the sections provided below:

1. :ref:`modbus_api_master_communication_options` - Initialization of the master and setup of the communication.
2. :ref:`modbus_api_master_configure_descriptor` - Configure data descriptors to access slave parameters.
3. :ref:`modbus_api_master_descriptor_initialization` - Associate the data dictionary with the master instance.
4. :ref:`modbus_api_master_start_communication` - Start the Modbus master stack.
5. :ref:`modbus_api_master_communication` - Sending / receiving data using CID parameters.
6. :ref:`modbus_api_master_legacy_communication` - Legacy Modbus request API.
7. :ref:`modbus_api_master_destroy` - Destroy Modbus controller and its resources.

See more:

* :ref:`modbus_api_master_handler_customization` - Customization of Modbus function handling.

.. _modbus_api_master_communication_options:

Master Create and Communication Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The configuration structure specifies the type of object being initialized and defines its user-specific options, the structure is provided as a parameter and is different for serial and TCP communication modes.

An example of initialization for a Modbus serial master is below:

.. code:: c

    static void *master_handle = NULL;
    ....
    mb_communication_info_t comm = {
        .ser_opts.port = CONFIG_MB_UART_PORT_NUM,
        .ser_opts.mode = MB_RTU,                // communication mode - MB_ASCII or MB_RTU
        .ser_opts.baudrate = CONFIG_MB_UART_BAUD_RATE,
        .ser_opts.parity = MB_PARITY_NONE,
        .ser_opts.uid = 0,                      // unused for master
        .ser_opts.response_tout_ms = CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1
    };
    esp_err_t err = mbc_master_create_serial(&comm, &master_handle);
    if (master_handle == NULL || err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller initialization fail.");
    }

.. note:: RS485 communication requires a call to UART-specific APIs to set up the communication mode and pins. Refer to the UART initialization code in the `basic master example <https://github.com/espressif/esp-modbus/blob/main/examples/get_started/basic_master/main/basic_master.c>`__.

Modbus TCP Master
~~~~~~~~~~~~~~~~~

The Modbus TCP master requires a slave IP address table. Each entry maps a short slave address (Unit Identifier, UID) to a host and port. The stack uses this table to connect and to reconnect when a connection is broken.

Each entry follows the notation ``UID;slave_host_ip_or_dns_name;port_number``. Host names, IPv4 addresses, and IPv6 addresses are all valid, as shown below. The table must be ``NULL``-terminated.

The table can be filled in the following ways:

1. **Hardcoded in source code**

   Edit ``slave_ip_address_table`` in the master application. This is the most direct way to define slaves when addresses are known at build time.

2. **mDNS discovery (automatic)**

   Use an mDNS host name in the table (for example ``mb_slave_tcp_01``) instead of a numeric IP address. The library resolves those names when ``CONFIG_FMB_MDNS_INTEGRATION_ENABLE`` is set (enabled by default). Disable this option to use only numeric IP addresses, or to resolve names in the application instead of in the stack.

   If mDNS is disabled but the table still contains host names, the stack logs an error such as: ``E (20127) mb_port.tcp.master: 0x3ffc9ff0, slave: 2, IP:mb_slave_tcp_01, mdns service is not supported.``

   Examples can also enable ``CONFIG_MB_MDNS_IP_RESOLVER`` so the master queries for Modbus services advertised by slaves. Each slave must enable the same option and use a unique Modbus slave address.

3. **Manual input via stdin**

   Examples can fill the table at run time. Enable ``CONFIG_MB_SLAVE_IP_FROM_STDIN`` and ``CONFIG_MB_CONSOLE_HELPER_ENABLED``, then enter addresses when prompted with ``Waiting IP<N> from stdin:``. Use the format ``IP <N>=<IP_ADDRESS>;<PORT>``, where ``N = (configured slave address - 1)``.

   Example: ``IP 0=192.168.1.21;1502``

.. note:: Match the address family to the connection option selected in the example: ``EXAMPLE_CONNECT_IPV4`` or ``EXAMPLE_CONNECT_IPV6``.

An example of initialization for a Modbus TCP master is below.

.. code:: c

    // All the slave devices being accessed by master.
    enum {
        MB_SLAVE_ADDR1 = 1,  // Add other slave addresses here.
        MB_SLAVE_ADDR2 = 35,
        MB_SLAVE_ADDR3 = 12,
        MB_DEVICE_COUNT = 4  // Equal to the number of registered slaves + 1
    };

    // Table to resolve slave addresses and reconnect when connection is broken
    static char *slave_ip_address_table[] = {
        "01;mb_slave_tcp_01;502",       // Slave using mDNS host name ("mb_slave_tcp_01"), UID = 01, port 502
        "35;192.168.32.54;1502",        // Slave with static IPv4 address, UID = 35, port 1502
        "12;2001:0db8:85a3:0000:0000:8a2e:0370:7334;502",  // Slave with static IPv6 address, UID = 12, port 502
        NULL                            // End of table (must be included)
    };

.. code:: c

    static void *master_handle = NULL;
    mb_tcp_addr_type_t ip_addr_type = MB_IPV4;
    ....
    // Setup of network
    init_services(ip_addr_type);

    mb_communication_info_t tcp_master_config = {
        .tcp_opts.port = CONFIG_FMB_TCP_PORT_DEFAULT,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = ip_addr_type,
        .tcp_opts.ip_addr_table = (void *)slave_ip_address_table,
        .tcp_opts.uid = 0,
        .tcp_opts.start_disconnected = false,
        .tcp_opts.response_tout_ms = CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND,
        .tcp_opts.ip_netif_ptr = (void *)get_example_netif()
    };
    esp_err_t err = mbc_master_create_tcp(&tcp_master_config, &master_handle);
    if (master_handle == NULL || err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller initialization fail.");
    }

.. note:: ``init_services()`` is required only for TCP masters and must be called before :cpp:func:`mbc_master_create_tcp`. For more information on how the code is used, see the `basic master example <https://github.com/espressif/esp-modbus/blob/main/examples/get_started/basic_master/main/basic_master.c>`__.

Refer to :ref:`example TCP master <example_mb_tcp_master>` and :ref:`example TCP slave <example_mb_tcp_slave>` for complete examples of mDNS and stdin-based address configuration.

.. _modbus_api_master_configure_descriptor:

Configuring Master Data Access
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ESP implementation of Modbus includes an abstraction layer called the Modbus Controller, which introduces several key concepts:

Characteristic
~~~~~~~~~~~~~~~

A characteristic represents specific Modbus register(s) to be read or written on a slave device. It is accessed using its characteristic identifier (CID) and encapsulates all necessary metadata about the register.

Data Dictionary
~~~~~~~~~~~~~~~

The data dictionary is a parameter description table that defines all Modbus registers the master will access on slave devices in the network. Each entry is a characteristic identified by a characteristic ID (CID), which represents a specific piece of data such as temperature, voltage, or a configuration value, and maps it to the corresponding Modbus registers on the slave. This abstraction simplifies the handling of register addresses, data formats, and function codes.

.. note:: The data dictionary can be initialized from an SD card, MQTT, or another source before the stack is started.

The master must define a data dictionary. Each characteristic includes the following fields:

.. list-table::
  :header-rows: 1
  :widths: 30 70

  * - Field
    - Description
  * - ``cid``
    - Unique CID number representing the parameter (used as an index in the data dictionary)
  * - ``param_key``
    - Description of the characteristic (must be unique)
  * - ``param_units``
    - Description of measurement units
  * - ``mb_slave_addr``
    - Slave device short address (unit ID)
  * - **Register Location (Slave)**
    -
  * - ``mb_param_type``
    - Modbus register type (:cpp:enumerator:`MB_PARAM_INPUT`, :cpp:enumerator:`MB_PARAM_HOLDING`, :cpp:enumerator:`MB_PARAM_COIL`, :cpp:enumerator:`MB_PARAM_DISCRETE`)
  * - ``mb_reg_start``
    - Starting register address in the slave
  * - ``mb_size``
    - Size in registers (2 bytes for INPUT and HOLDING, 1 bit for COIL and DISCRETE)
  * - **Data Storage (Master)**
    -
  * - ``param_offset``
    - Offset of the start address
  * - ``param_type``
    - Data type (Float, U8, U16, U32, ASCII, and so on). See types in :ref:`modbus_mapping_complex_data_types`.
  * - ``param_size``
    - Number of bytes to store
  * - **Access Control**
    -
  * - ``param_opts``
    - Options for limits or alarm states
  * - ``access``
    - Permissions (read, write, trigger, and so on): :cpp:enumerator:`PAR_PERMS_READ`, :cpp:enumerator:`PAR_PERMS_WRITE`, :cpp:enumerator:`PAR_PERMS_READ_WRITE_TRIGGER`, :cpp:enumerator:`PAR_PERMS_CUST_CMD`

**Example entry:**

.. code:: c

    const mb_parameter_descriptor_t device_parameters[] = {
    {
        CID_EX_0,                           // CID number
        "Example_register",                 // Description
        "-",                                // Units (extra description)
        MB_SLAVE_ADDR1,                     // Slave address
        MB_PARAM_HOLDING,                   // Register area type
        0,                                  // Start address in slave register area
        1,                                  // Size in registers
        0,                                  // Offset start address
        PARAM_TYPE_U16,                     // Data type
        PARAM_SIZE_U16,                     // Size in bytes
        OPTS(0, 0, 0),                      // Options
        PAR_PERMS_READ_WRITE_TRIGGER        // Permissions
    }
    };

The types described in :ref:`modbus_mapping_complex_data_types` can represent value formats used by known third-party devices.
Once a CID type is defined in the data dictionary, the stack converts values to and from the corresponding type into a format the compiler can use.

.. _modbus_api_master_descriptor_initialization:

Master Descriptor Initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to associate the data dictionary with the master instance, the function below must be used, and a pointer to the data dictionary (called the descriptor) must be provided as a parameter:

:cpp:func:`mbc_master_set_descriptor`

.. code:: c

    static void *master_handle = NULL; // Must exist in the module and be initialized prior to the call
    ....
    // Set master data dictionary for initialized master instance - master_handle
    ESP_ERROR_CHECK(mbc_master_set_descriptor(master_handle, &device_parameters[0], num_device_parameters));

.. _modbus_api_master_start_communication:

Master Initialization
^^^^^^^^^^^^^^^^^^^^^

Master stack initialization is the last step before enabling communication. This is performed using the function below:

:cpp:func:`mbc_master_start`

.. code:: c

    static void *master_handle = NULL;  // Pointer to master instance
    ....
    esp_err_t err = mbc_master_start(master_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller start fail, err = 0x%x.", (int)err);
    }

.. _modbus_api_master_communication:

Master Communication
^^^^^^^^^^^^^^^^^^^^

The common ESP-Modbus communication flow looks like this:

:cpp:func:`mbc_master_get_cid_info`

The function gets information about a characteristic ID (CID) from the data dictionary and returns the CID description in the form of the :cpp:type:`mb_parameter_descriptor_t` structure. Each characteristic is accessed using its CID number.

.. code:: c

    mbc_master_get_cid_info(master_handle, cid, &param_descriptor)

:cpp:func:`mbc_master_get_parameter`

The function reads data from a Modbus slave device based on the characteristic ID (CID) from the data dictionary.

.. code:: c

    mbc_master_get_parameter(master_handle, cid, parameter_value, &type)

:cpp:func:`mbc_master_set_parameter`

The function writes data to a Modbus slave device based on the characteristic ID (CID) from the data dictionary.

.. code:: c

    mbc_master_set_parameter(master_handle, cid, parameter_value, &type)

.. note:: For a complete usage example, refer to :ref:`example Serial master <example_mb_master>`.

:cpp:func:`mbc_master_get_parameter_with`

The function reads data from a Modbus slave addressed by UID (slave address), based on the characteristic ID (CID) from the data dictionary. The ``mb_slave_addr`` field of the CID entry in :cpp:type:`mb_parameter_descriptor_t` must be equal to ``MB_SLAVE_ADDR_PLACEHOLDER``. For TCP communication, the connection phase must be completed before calling this function.

.. code:: c

    mbc_master_get_parameter_with(master_handle, cid, MB_DEVICE_ADDR1, parameter_value, &type)

:cpp:func:`mbc_master_set_parameter_with`

The function is similar to the previous one, but writes data to any slave device addressed by UID (slave address) instead of using the ``mb_slave_addr`` field defined in the data dictionary. The corresponding ``mb_slave_addr`` field for the CID entry in the data dictionary must be defined as ``MB_SLAVE_ADDR_PLACEHOLDER``.

.. code:: c

    mbc_master_set_parameter_with(master_handle, cid, MB_DEVICE_ADDR1, parameter_value, &type)

.. note:: When TCP communication is used, the functions above also check the connection state of the accessed slave and return an error if the slave is not connected.

.. _modbus_api_master_legacy_communication:

Legacy Modbus Communication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:cpp:func:`mbc_master_send_request`

This function executes a blocking Modbus request. The master sends a data request (as defined in the parameter request structure :cpp:type:`mb_param_request_t`) and then blocks until a response from the corresponding slave is received, and returns the status of command execution. This function provides a standard way for read/write access to Modbus devices in the network.

.. note:: The function can be used to form a custom request with non-standard commands to resolve compatibility issues with custom slaves. If that is not the case, the regular API should be used: :cpp:func:`mbc_master_set_parameter`, :cpp:func:`mbc_master_get_parameter`.

The following example shows how to use the Modbus command ``<0x11 - Report Slave ID>`` to read vendor-specific information from the slave. It uses :cpp:func:`mbc_master_send_request` to send the request.

.. code:: c

    #define MB_DEVICE_ADDR1 1 // the slave UID to retrieve information
    ...
    static void *master_handle = NULL; // the master handler is initialized previously
    ...
    // Set the request structure for the master to send the <Report Slave ID> command
    mb_param_request_t req = {
        .slave_addr = MB_DEVICE_ADDR1,  // the UID of the device to get the information,
        .command = 0x11,                // the <Report Slave ID> command,
        .reg_start = 0,                 // is obsolete, need to be zero for this request,
        .reg_size = (CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE >> 1) // size of the buffer in registers to save ID
    };
    uint8_t info_buf[CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE] = {0};
    // Send the request to slave
    err = mbc_master_send_request(master_handle, &req, &info_buf[0]);
    if (err != ESP_OK) {
        ESP_LOGE("SLAVE_INFO", "Read slave info fail.");
    } else {
        ESP_LOG_BUFFER_HEX_LEVEL("SLAVE_INFO", (void*)info_buf, sizeof(info_buf), ESP_LOG_WARN);
    }

The following example shows how to use the extra fields of :cpp:type:`mb_param_request_t` for command ``0x17`` (23 -- Read/Write Multiple Registers). It writes 3 ``float`` holding values (6 registers, starting at field ``holding_data0``) and reads 1 ``float`` holding value (2 registers, starting at field ``holding_data2``) of the storage structure ``holding_reg_params_t`` in the same transaction.

.. note:: The storage structure ``holding_reg_params_t`` uses ``float`` (4 bytes) to store the holding registers. Since the Modbus protocol considers one holding register to be 2 bytes long, both ``reg_size`` (read length) and ``wr_rd_multi_reg_func.wr_reg_size`` (write length) must be expressed in registers -- i.e. twice the number of ``float`` values to transfer. The macro ``HOLD_REG_START()`` defined in the ESP-Modbus project examples is used to get the register offset for the respective field in the storage structure.

.. code:: c

    #define MB_DEVICE_ADDR1 1 // Slave UID to send the request
    ...
    static void *master_handle = NULL; // The master handler should be initialized before send request function
    ...

    float read_write_holding_buffer[3] = {23.4f, 45.6f, 56.7f};

    mb_param_request_t read_write_holding_request = {
        .slave_addr = MB_DEVICE_ADDR1,
        .command = 0x17,                                                // 0x17 (23) -- Read/Write Multiple Registers
        .reg_start = HOLD_REG_START(holding_data2),                     // Read start address: field holding_data2 in holding_reg_params_t
        .reg_size = 2,                                                  // Length of the data to read (registers)
        .wr_rd_multi_reg_func.wr_reg_start = HOLD_REG_START(holding_data0), // Write start address: field holding_data0 in holding_reg_params_t
        .wr_rd_multi_reg_func.wr_reg_size = 6                           // Length of the data to write (registers)
    };

      err = mbc_master_send_request(master_handle, &read_write_holding_request, &read_write_holding_buffer);
      if (err != ESP_OK) {
          ESP_LOGE("MASTER_COMMAND_0x17", "Read and write of multiple holding registers fail.");
      } else {
          ESP_LOGI("MASTER_COMMAND_0x17", "Read and write of multiple holding registers success. Value read: %f", read_write_holding_buffer[0]);
      }

.. note:: Please refer to :ref:`modbus_master_slave_configuration_aspects` for proper configuration.

.. _modbus_api_master_handler_customization:

Master Customize Function Handlers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Master object contains the command handling table to define specific handling functionality for each supported Modbus command. The default handling functions in this table support the most common Modbus commands. However, the list of commands can be extended by adding a new command into the handling table with its custom handling behavior. It is also possible to override the function handler for a specific command. The API functions described below allow using this behavior for Master objects.

:cpp:func:`mbc_set_handler`

The function adds a new handler for the function code or overrides the existing handler.

.. note:: The custom handler set by :cpp:func:`mbc_set_handler` should be as short as possible and should contain simple, safe logic so that it does not break the normal functionality of the stack. It is the user application's responsibility to handle the command appropriately.

:cpp:func:`mbc_get_handler`

The function returns the handler for the specified function code from the handling table. This allows keeping and using the predefined handlers for standard functions.

:cpp:func:`mbc_delete_handler`

The function deletes the handler for the specified command and frees the handler table entry.

:cpp:func:`mbc_get_handler_count`

The function returns the actual number of command handlers registered for the object referred to by its parameter.

The example code to override the handler routine for the command ``<0x04 - Read Input Registers>`` is below. This example performs a custom action and then calls the standard handler, which maps the device data to the command buffer from the actual parameter. This is the recommended behavior for handling functions, but users can change the order of the calls if absolutely required. Please refer to the existing handler `mbm_fn_read_inp_reg <https://github.com/espressif/esp-modbus/blob/main/modbus/mb_objects/functions/mbfuncinput_master.c#L103>`__ for more information.

.. code:: c

    static void *master_handle = NULL;
    const uint8_t command  = 0x04;
    mb_fn_handler_fp pstandard_handler = NULL;
    ....
    // This is the custom function handler for the command.
    // The handler is executed from the context of modbus controller event task and should be as simple as possible.
    //
    // Parameters:
    // pinst - pointer to the Modbus instance (mb_base_t),
    // frame_ptr - the pointer to the incoming ADU frame from the slave starting from the function code,
    // plen - the pointer to the length of the frame.
    //
    // After return from the handler, the modbus object will
    // handle the end of transaction according to the exception returned.
    mb_exception_t my_custom_fc04_handler(void *pinst, uint8_t *frame_ptr, uint16_t *plen)
    {
        mb_exception_t exception = MB_EX_CRITICAL;
        ESP_RETURN_ON_FALSE(frame_ptr && plen, exception, TAG, "incorrect frame buffer length");
        // It is the possible place for the custom behavior
        if (pstandard_handler) {
            exception = pstandard_handler(pinst, frame_ptr, plen); // invoke standard behavior with mapping
        }
        return exception;
    }
    ....
    // Get the standard handler for the command to use it in the custom handler.
    err = mbc_get_handler(master_handle, command , &pstandard_handler);
    ESP_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "could not get handler for command %d, returned (0x%x).", (int)command , (int)err);
    // This call overrides the handler for the standard command.
    err = mbc_set_handler(master_handle, command , my_custom_fc04_handler);
    ESP_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                        "could not override handler, returned (0x%x).", (int)err);

The following example handles a custom vendor-specific command. This example sends the "Master" string to the slave and gets the response with text appended to the sent string. It is a simple echo example to demonstrate the functionality.

.. code:: c

    #define MB_CUST_DATA_LEN 100
    static char my_custom_data[MB_CUST_DATA_LEN] = {0}; // custom data buffer for the request
    static void *master_handle = NULL;  // Pointer to Master instance

    // This is the custom function handler to process the incoming slave response.
    // Parameters:
    // pinst - pointer to the Modbus instance (mb_base_t),
    // frame_ptr - the pointer to the incoming ADU frame from the slave starting from the function code,
    // plen - the pointer to the length of the frame.
    //
    // Despite the logging shown here, try to use only simple functionality in the handler.
    mb_exception_t my_custom_fc_handler(void *pinst, uint8_t *frame_ptr, uint16_t *plen)
    {
        MB_RETURN_ON_FALSE((frame_ptr && plen && *plen && *plen < (MB_CUST_DATA_LEN - 1)), MB_EX_ILLEGAL_DATA_VALUE, TAG,
                                "incorrect custom frame buffer");
        ESP_LOGI(TAG, "Custom handler, Frame ptr: %p, len: %u", frame_ptr, *plen);
        strncpy((char *)&my_custom_data[0], (char *)&frame_ptr[1], MB_CUST_DATA_LEN);
        ESP_LOG_BUFFER_HEXDUMP("CUSTOM_DATA", &my_custom_data[0], (*plen - 1), ESP_LOG_INFO);
        return MB_EX_NONE;
    }
    ....
    // The setup of the master object is completed and the master_handle is already initialized

    // Add custom command handler
    const uint8_t custom_command = 0x41; // the function code for the request
    // Override or add new handler entry.
    err = mbc_set_handler(master_handle, custom_command, my_custom_fc_handler);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "could not override handler, returned (0x%x).", (int)err);
    mb_fn_handler_fp phandler = NULL;
    // Make sure the handler is updated correctly
    err = mbc_get_handler(master_handle, custom_command, &phandler);
    MB_RETURN_ON_FALSE((err == ESP_OK && phandler == my_custom_fc_handler), ESP_ERR_INVALID_STATE, TAG,
                            "could not get handler for command %d, returned (0x%x).", (int)custom_command, (int)err);

    char *pcustom_string = "Master"; // The custom request string that will be sent to the slave
    mb_param_request_t req = {
        .slave_addr = MB_DEVICE_ADDR1,              // the slave UID to send the request
        .command = custom_command,                  // the custom function code,
        .reg_start = 0,                             // unused,
        .reg_size = (strlen(pcustom_string) >> 1)   // length of the data to send (registers)
    };

    // Send the request with custom command (vendor specific)
    // This function supports sending of even number of bytes
    // as instructed by req.reg_size (Modbus register = 2 bytes)
    err = mbc_master_send_request(master_handle, &req, pcustom_string);
    if (err != ESP_OK) {
        ESP_LOGE("CUSTOM_DATA", "Send custom request fail.");
    } else {
        // The request is processed correctly and the `my_custom_data[]` contains the sent string with appended slave string
        ...
    }

Refer to :ref:`example Serial master <example_mb_master>` for more information.

.. _modbus_api_master_destroy:

Modbus Master Teardown
^^^^^^^^^^^^^^^^^^^^^^

This function stops the Modbus communication stack, destroys the controller interface, and frees all used active objects.

:cpp:func:`mbc_master_delete`

.. code:: c

    // Pointer to master instance, must be initialized by constructor
    static void *master_handle = NULL;
    ...
    ESP_ERROR_CHECK(mbc_master_delete(master_handle));
    // Necessary extra step for TCP instances, it pairs with init_services()
    destroy_services();

.. note:: ``destroy_services()`` is required only for TCP masters and must be called after :cpp:func:`mbc_master_delete`. For more information on how the code is used, see the `basic master example <https://github.com/espressif/esp-modbus/blob/main/examples/get_started/basic_master/main/basic_master.c>`__.
