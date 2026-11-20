.. _modbus_api_slave_overview:

Modbus Slave API Overview
-------------------------

The sections below represent a typical programming workflow for the slave API, which should be called in the following order:

1. :ref:`modbus_api_slave_communication_options` - Initialization of the slave and setup of the communication.
2. :ref:`modbus_api_slave_configure_descriptor` - Configure data descriptors to access slave parameters.
3. :ref:`modbus_api_slave_communication` - Sending / receiving data. Filter events when master accesses the register areas.
4. :ref:`modbus_api_slave_destroy` - Destroy Modbus controller and its resources.

See more:

* :ref:`modbus_api_slave_handler_customization` - Customization of Modbus function handlers in slave.
* :ref:`modbus_api_slave_custom_id` - Custom Slave ID (Vendor-specific slave identification).

.. _modbus_api_slave_communication_options:

Slave Communication Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The function initializes the Modbus controller interface and its active context (tasks, RTOS objects and other resources).

The following example initializes a Esp-Modbus serial slave:

.. code:: c

    static void* slave_handle = NULL;
    ....
    mb_communication_info_t config = {
        .ser_opts.port = CONFIG_MB_UART_PORT_NUM,
        .ser_opts.mode = MB_ASCII,                      // communication mode - MB_ASCII or  MB_RTU
        .ser_opts.baudrate = CONFIG_MB_UART_BAUD_RATE,
        .ser_opts.parity = MB_PARITY_NONE,
        .ser_opts.uid = CONFIG_MB_SLAVE_ADDR,          // Modbus slave UID - Unit Identifier (short address)
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1
    };
    // Initialization and setup of Modbus serial slave in ASCII communication mode
    esp_err_t err = mbc_slave_create_serial(&config, &slave_handle);
    if (slave_handle == NULL || err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller initialization fail.");
    }

.. note:: RS485 communication requires a call to UART-specific APIs to set up the communication mode and pins. Refer to the uart_initialization() function in the `basic slave example <https://github.com/espressif/esp-modbus/blob/main/examples/get_started/basic_slave/main/basic_slave.c>`__.

The following example initializes a Esp-Modbus TCP slave:

.. code:: c

    static void* slave_handle = NULL;
    ....
    // Setup of network
    init_services();

    mb_communication_info_t tcp_slave_config = {
        .tcp_opts.port = CONFIG_FMB_TCP_PORT_DEFAULT,       // communication port number for Modbus slave
        .tcp_opts.mode = MB_TCP,                            // mode of communication for slave
        .tcp_opts.addr_type = MB_IPV4,                      // type of addressing being used
        .tcp_opts.ip_addr_table = NULL,                     // Bind to any address
        .tcp_opts.ip_netif_ptr = (void*)get_example_netif(),// the pointer to netif interface
        .tcp_opts.uid = CONFIG_MB_SLAVE_ADDR                // Modbus slave Unit Identifier
    };
    esp_err_t err = mbc_slave_create_tcp(&tcp_slave_config, &slave_handle);
    if (slave_handle == NULL || err != ESP_OK) {
        ESP_LOGE(TAG, "mb controller initialization fail.");
    }

.. note:: ``init_services()`` is required only for TCP slaves and must be called before :cpp:func:`mbc_slave_create_tcp`. For more information on code usage, see the `basic slave example <https://github.com/espressif/esp-modbus/blob/main/examples/get_started/basic_slave/main/basic_slave.c>`__.



After creating the Modbus slave controller interface, it is necessary to start the stack:

:cpp:func:`mbc_slave_start`

.. code:: c

    static void* slave_handle = NULL;
    ....
    ESP_ERROR_CHECK(mbc_slave_start(slave_handle)); // The handle must be initialized prior to start call.

.. _modbus_api_slave_configure_descriptor:

Configuring Slave Data Access - Area Descriptor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The slave stack requires the user to define structures (memory mapping areas), called area descriptors, that store the Modbus registers accessed by the master. After they are defined, these area descriptors are assigned to the Modbus controller interface using :cpp:func:`mbc_slave_set_descriptor`.

.. note:: One slave can define several area descriptors per Modbus register type (Holding Registers, Input Registers, Coils, Discrete Inputs), each with a different ``start_offset``.

A register area is defined using the :cpp:type:`mb_register_area_descriptor_t` structure.

.. list-table:: Table of Modbus register area descriptor
  :header-rows: 1
  :widths: 20 80

  * - Field
    - Description
  * - ``type``
    - Type of the Modbus register area. Refer to :cpp:type:`mb_param_type_t` for more information.
  * - ``address``
    - A pointer to the memory area which is used to store the register data for this area descriptor.
  * - ``start_offset``
    - Zero-based register offset for the defined register area.
  * - ``size``
    - The size of the memory area in bytes which is used to store register data.
  * - ``access``
    - Area descriptor access type. Options: ``MB_ACCESS_RW``, ``MB_ACCESS_RO``, ``MB_ACCESS_WO``.
    
    
.. code:: c  
    
    // Note: error checking is omitted for simplicity.
    // slave_handle must be previously created.

    // Slave holding register area. The descriptor associates this structure
    // as the holding registers available for reading or writing. 
    
    struct holding_params {
        uint16_t holding_1;
    };

    struct holding_params holding_register = { 0 }; // Register saving structure
    
    mb_register_area_descriptor_t reg_area = {0};

    // Initialization of Holding area
    reg_area.type = MB_PARAM_HOLDING;
    reg_area.address = (void *)&holding_register.holding_1;
    reg_area.start_offset = holding_register.holding_1;
    reg_area.size = sizeof(*holding_register);    
    reg_area.access = MB_ACCESS_RW; // Access type: MB_ACCESS_RW, MB_ACCESS_RO, MB_ACCESS_WO

    mbc_slave_set_descriptor(slave_handle, reg_area);

    holding_register.holding_1 = 10;

.. _modbus_api_slave_communication:

Slave Communication
~~~~~~~~~~~~~~~~~~~

The common ESP-Modbus Slave communication flow looks like this:

:cpp:func:`mbc_slave_check_event`


Blocking function that checks, depending on the mask provided, whether there is a master request in the queue. Once the specified event is found, the function returns the corresponding event :cpp:type:`mb_event_group_t`, which describes the type of register access being done.

.. code:: c

    #define MB_READ_MASK                        (MB_EVENT_INPUT_REG_RD | MB_EVENT_HOLDING_REG_RD | MB_EVENT_DISCRETE_RD | MB_EVENT_COILS_RD)
    #define MB_WRITE_MASK                       (MB_EVENT_HOLDING_REG_WR | MB_EVENT_COILS_WR)
    #define MB_READ_WRITE_MASK                  (MB_READ_MASK | MB_WRITE_MASK)

    ...

    mbc_slave_check_event(slave_handle, MB_READ_WRITE_MASK);

:cpp:func:`mbc_slave_get_param_info`

Consumes the request queue and populates the :cpp:type:`mb_param_info_t` structure with information about the accessed parameter. A timeout can be specified when waiting for a notification.

.. note:: The Kconfig ``CONFIG_FMB_CONTROLLER_NOTIFY_QUEUE_SIZE`` key can be used to configure the notification queue size. 

.. list-table:: Table: Description of the register info structure: :cpp:type:`mb_param_info_t`
  :widths: 10 90
  :header-rows: 1
  
  * - Field
    - Description
  * - ``time_stamp``
    - The timestamp of the event when the defined parameter is accessed
  * - ``mb_offset``
    - Start Modbus register accessed by the master
  * - ``type``
    - Type of the Modbus register area being accessed (see :cpp:type:`mb_event_group_t`)
  * - ``address``
    - Memory address that corresponds to the accessed register in the defined area descriptor
  * - ``size``
    - Number of registers being accessed by the master

The following example gets an event when holding or input registers are accessed in the slave:

.. code:: c

    #define MB_READ_MASK            (MB_EVENT_INPUT_REG_RD | MB_EVENT_HOLDING_REG_RD)
    #define MB_WRITE_MASK           (MB_EVENT_HOLDING_REG_WR)
    #define MB_READ_WRITE_MASK      (MB_READ_MASK | MB_WRITE_MASK)
    #define MB_PAR_INFO_GET_TOUT    (10 / portTICK_RATE_MS)                           
    ....
    static void *slave_handle = NULL;  // communication object handle
    ....

    mb_param_info_t reg_info = {0}; // Modbus master request structure

    // Check the queue for the specified event. The function
    // blocks while waiting for register access
    (void)mbc_slave_check_event(slave_handle, MB_READ_WRITE_MASK);

    // Obtain the parameter information from the queue for the access from the master 
    ESP_ERROR_CHECK(mbc_slave_get_param_info(slave_handle, &reg_info, MB_PAR_INFO_GET_TOUT));
    const char* rw_str = (reg_info.type & MB_READ_MASK) ? "READ" : "WRITE";

    // Filter events and process them accordingly
    if (reg_info.type & (MB_EVENT_HOLDING_REG_WR | MB_EVENT_HOLDING_REG_RD)) {
        ESP_LOGI(TAG, "HOLDING %s (%u us), ADDR:%u, TYPE:%u, INST_ADDR:0x%.4x, SIZE:%u",
                    rw_str,
                    (uint32_t)reg_info.time_stamp,
                    (uint32_t)reg_info.mb_offset,
                    (uint32_t)reg_info.type,
                    (uint32_t)reg_info.address,
                    (uint32_t)reg_info.size);
    } else if (reg_info.type & (MB_EVENT_INPUT_REG_RD)) {
        ESP_LOGI(TAG, "INPUT %s (%u us), ADDR:%u, TYPE:%u, INST_ADDR:0x%.4x, SIZE:%u",
                    rw_str,
                    (uint32_t)reg_info.time_stamp,
                    (uint32_t)reg_info.mb_offset,
                    (uint32_t)reg_info.type,
                    (uint32_t)reg_info.address,
                    (uint32_t)reg_info.size);
    }

.. note:: Please refer to :ref:`modbus_master_slave_configuration_aspects` for proper configuration.


Update Register Value
^^^^^^^^^^^^^^^^^^^^^

:cpp:func:`mbc_slave_lock`

:cpp:func:`mbc_slave_unlock`

In the slave application, it is also possible to modify a register value after communication has started. Because the register areas are a critical section of the stack, access must be protected:

.. code:: c

    static void *slave_handle = NULL;   // communication object handle
    ...
    (void)mbc_slave_lock(slave_handle); // ignore the returned error if the object is not actual
    holding_reg_area[1] += 10; // the data is part of initialized register area accessed by slave
    (void)mbc_slave_unlock(slave_handle);

Access to a registered area shared between several slave objects from the user application must be protected by a critical section based on a spin lock:

.. code:: c

    #include "freertos/FreeRTOS.h"
    ...
    static portMUX_TYPE g_spinlock = portMUX_INITIALIZER_UNLOCKED;
    ...
    portENTER_CRITICAL(&param_lock);
    holding_reg_area[2] = 123;
    portEXIT_CRITICAL(&param_lock);

.. _modbus_api_slave_handler_customization:

Slave Customize Function Handlers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The slave object contains a command handler table that defines the handling for each supported Modbus command.
The default handlers in this table cover the most common Modbus commands. The list of commands can be extended by adding a new command to the table with custom handling. It is also possible to override the handler for a specific command. The API functions below support this behavior for slave objects.

:cpp:func:`mbc_set_handler`

Adds a new handler for a function code, or overrides the existing handler for that function code.

:cpp:func:`mbc_get_handler`

Returns the handler for the specified function code from the handling table. This allows reuse of the predefined handlers for standard functions.

:cpp:func:`mbc_delete_handler`

Deletes the handler for the specified command and frees the handler table entry.

:cpp:func:`mbc_get_handler_count`

Returns the number of command handlers registered for the object.

The following example extends the standard command to read input registers by executing custom code and then calling the standard handler. Refer to :cpp:func:`mbs_fn_read_input_reg` for more information on handling custom commands.

.. code:: c

    // slave_handle must be previously created.
    mb_fn_handler_fp pstandard_handler = NULL;
    ....
    // This is the custom function handler for the modbus command.

    // Parameters: 
    // pinst - pointer to the Modbus instance (mb_base_t),
    // frame_ptr - the pointer to the incoming ADU request frame from master starting from function code,
    // plen - the pointer to length of the frame. The handler body can override the buffer and return the length of data.

    // After return from the handler, the Modbus slave finishes the transaction according to the exception returned,
    // then builds the response frame and sends it back to the master.
    mb_exception_t my_custom_fc04_handler(void *pinst, uint8_t *frame_ptr, uint16_t *plen)
    {
        MB_RETURN_ON_FALSE(frame_ptr && plen, MB_EX_CRITICAL, TAG, "incorrect frame buffer length");
        // Place the custom behavior to process the buffer here

        if (pstandard_handler) {
            exception = pstandard_handler(pinst, frame_ptr, plen); // invoke standard behavior with mapping
        }
        return exception;
    }
    ...
    const uint8_t override_command = 0x04;  // Modbus command to read input registers

    // Get the standard handler for the command to use it in the custom handler.
    err = mbc_get_handler(slave_handle, override_command, &pstandard_handler);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE, TAG,
                            "could not get handler for command %d, returned (0x%x).", (int)override_command, (int)err);

    // Set the custom handler function for the modbus command
    err = mbc_set_handler(slave_handle, override_command, my_custom_fc04_handler);
    MB_RETURN_ON_FALSE((err == ESP_OK), ;, TAG,
                        "could not override handler, returned (0x%x).", (int)err);

    mb_fn_handler_fp phandler = NULL;
    // Check the actual handler that was set for the Modbus command
    err = mbc_get_handler(slave_handle, override_command, &phandler);
    MB_RETURN_ON_FALSE((err == ESP_OK && phandler == my_custom_fc04_handler), ;, TAG,
                          "could not get handler, returned (0x%x).", (int)err);



.. note:: Custom handlers set with :cpp:func:`mbc_set_handler` should be as short as possible, contain simple and safe logic, and avoid blocking calls so they do not break normal stack operation. If the whole transaction time, including response latency, exceeds the slave response time configured on the master, the master ignores the transaction. Handling the command correctly is the responsibility of the user application.

.. _modbus_api_slave_custom_id:

Slave Custom ID
~~~~~~~~~~~~~~~~

The slave supports a custom identification structure that can hold slave-specific information. This information can be retrieved by the master using the standard Modbus command ``0x11`` (Report Slave ID).

The custom identification is structured as follows:

.. list-table::
  :header-rows: 1
  :widths: 30 70

  * - Field
    - Description
  * - UID
    - Slave ID
  * - Slave status
    - ``0x00`` = OFF, ``0xFF`` = ON
  * - Custom Field
    - Custom data

By default, the ESP-Modbus slave uses these values:

.. list-table::
  :header-rows: 1
  :widths: 20 30 50

  * - UID
    - Slave status
    - Custom Field
  * - 01
    - FF
    - 33 22 11

The API functions below can be used to set and get this information from the slave object.

The option ``CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT`` enables the functionality. ``CONFIG_FMB_CONTROLLER_SLAVE_ID`` in menuconfig initializes the custom identification value, and ``CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE`` defines the maximum size of the slave identification structure.

:cpp:func:`mbc_set_slave_id`

Sets a vendor-specific slave ID for the slave object.

.. note:: Each slave object sets a short default identifier defined by the ``CONFIG_FMB_CONTROLLER_SLAVE_ID`` Kconfig value on start. This can be overridden by this API function. 
  
Example of initialization for slave ID:

.. code:: c

    #include "mbcontroller.h"                                 // for mbcontroller defines and api
    ...

    // Keep in mind that the slave object and handle were already created and started

    const char *pdevice_name = "my_slave_device_description"; // the vendor specific part for slave to be retrieved by master

    bool is_started = (bool)(err == ESP_OK);                  // running status of the slave to be reported

    // This is the way to set Slave ID information so the master can retrieve it using the Report Slave ID command.
    esp_err_t err = mbc_set_slave_id(mbc_slave_handle, uid, is_started, (uint8_t *)pdevice_name, strlen(pdevice_name));
    if (err == ESP_OK) {
        ESP_LOG_BUFFER_HEX_LEVEL("SET_SLAVE_ID", (void*)pdevice_name, strlen(pdevice_name), ESP_LOG_WARN);
    } else {
        ESP_LOGE("SET_SLAVE_ID", "Set slave ID fail, err=%d.", err);
    }
    ...

:cpp:func:`mbc_get_slave_id`

Gets the actual slave UID, running status, and vendor-specific data.

Example to get the actual slave identifier:

.. code:: c

    #include "mbcontroller.h"
    #include "sdkconfig.h"
    ...
    // Keep in mind that the slave object and handle were already created and started


     // the vendor specific part of structure for slave to be retrieved by master
    uint8_t current_slave_id[CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE] = {0};
    uint8_t id_len = 0; 

    esp_err_t err = mbc_get_slave_id(mbc_slave_handle, &current_slave_id[0], &id_len);
    if (err == ESP_OK) {
        ESP_LOGW("GET_SLAVE_ID", "Get slave ID, length=%u.", id_len);
        ESP_LOG_BUFFER_HEX_LEVEL("GET_SLAVE_ID", (void*)current_slave_id, id_len, ESP_LOG_WARN);
    } else {
        ESP_LOGE("GET_SLAVE_ID", "Get slave ID fail, err=%d.", err);
    }
    ...

.. _modbus_api_slave_destroy:

Modbus Slave Teardown
~~~~~~~~~~~~~~~~~~~~~

This function stops the Modbus communication stack, destroys the controller interface, and frees all used active objects allocated for the slave.  

:cpp:func:`mbc_slave_delete`

.. code:: c

    ESP_ERROR_CHECK(mbc_slave_delete(slave_handle)); // delete the slave communication object defined by its handle

    // Necessary extra step for TCP instances, it pairs with init_services()
    destroy_services();

.. note:: ``destroy_services()`` is required only for TCP slaves and must be called after :cpp:func:`mbc_slave_delete`. For more information on code usage, see the `basic slave example <https://github.com/espressif/esp-modbus/blob/main/examples/get_started/basic_slave/main/basic_slave.c>`__.