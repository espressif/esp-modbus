.. _modbus_api_slave_overview:

Modbus Slave API Overview
-------------------------

The sections below represent typical programming workflow for the slave API which should be called in following order:

1. :ref:`modbus_api_port_initialization` - Initialization of Modbus controller interface using communication options.
2. :ref:`modbus_api_slave_configure_descriptor` - Configure data descriptors to access slave parameters.
3. :ref:`modbus_api_slave_setup_communication_options` - Allows to setup communication options for selected port.
4. :ref:`modbus_api_slave_communication` - Start stack and sending / receiving data. Filter events when master accesses the register areas.
5. :ref:`modbus_api_slave_destroy` - Destroy Modbus controller and its resources.

.. _modbus_api_slave_configure_descriptor:

Configuring Slave Data Access
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following functions must be called when the Modbus controller slave port is already initialized. Refer to :ref:`modbus_api_port_initialization`.

The slave stack requires the user to define structures (memory storage areas) that store the Modbus parameters accessed by stack. These structures should be prepared by the user and be assigned to the Modbus controller interface using :cpp:func:`mbc_slave_set_descriptor` API call before the start of communication. The slave task can call the :cpp:func:`mbc_slave_check_event` function which will block until the Modbus master access the slave. The slave task can then get information about the data being accessed.

.. note:: One slave can define several area descriptors per each type of Modbus register area with different start_offset.

Register area is defined by using the :cpp:type:`mb_register_area_descriptor_t` structure. 

.. list-table:: Table 3 Modbus register area descriptor 
  :widths: 8 92
  :header-rows: 1

  * - Field
    - Description
  * - ``start_offset``
    - Zero based register relative offset for defined register area. Example: register address = 40002 ( 4x register area - Function 3 - holding register ), start_offset = 2 
  * - ``type``
    - Type of the Modbus register area. Refer to :cpp:type:`mb_param_type_t` for more information.
  * - ``address``
    - A pointer to the memory area which is used to store the register data for this area descriptor.
  * - ``size``
    - The size of the memory area in bytes which is used to store register data.
    
:cpp:func:`mbc_slave_set_descriptor`

The function initializes Modbus communication descriptors for each type of Modbus register area (Holding Registers, Input Registers, Coils (single bit output), Discrete Inputs). Once areas are initialized and the :cpp:func:`mbc_slave_start()` API is called the Modbus stack can access the data in user data structures by request from master.

.. code:: c

    #define MB_REG_INPUT_START_AREA0    (0)
    #define MB_REG_HOLDING_START_AREA0  (0)
    #define MB_REG_HOLD_CNT             (100)
    #define MB_REG_INPUT_CNT            (100)
    ....
    static void *slave_handle = NULL;                   // Pointer to interface structure allocated by constructor
    ....
    mb_register_area_descriptor_t reg_area;             // Modbus register area descriptor structure
    unit16_t holding_reg_area[MB_REG_HOLD_CNT] = {0};   // storage area for holding registers 
    unit16_t input_reg_area[MB_REG_INPUT_CNT] = {0};    // storage area for input registers 

    reg_area.type = MB_PARAM_HOLDING;                   // Set type of register area
    reg_area.start_offset = MB_REG_HOLDING_START_AREA0; // Offset of register area in Modbus protocol
    reg_area.address = (void*)&holding_reg_area[0];     // Set pointer to storage instance
    reg_area.size = (sizeof(holding_reg_area) << 1);    // Set the size of register storage area in bytes!
    reg_area.access = MB_ACCESS_RW;                     // Set the access rights for the area
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(slave_handle, reg_area));
    
    reg_area.type = MB_PARAM_INPUT;
    reg_area.start_offset = MB_REG_INPUT_START_AREA0;
    reg_area.address = (void*)&input_reg_area[0];
    reg_area.size = (sizeof(input_reg_area) << 1);
    reg_area.access = MB_ACCESS_RW;
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(slave_handle, reg_area));


At least one area descriptor per each Modbus register type must be set in order to provide register access to its area. If the master tries to access an undefined area, the stack will generate a Modbus exception.

The stack supports the extended data types when enabled through the the option ``CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND`` in kconfig menu.
In this case the mapped data values can be initialized to specific format using :ref:`modbus_api_endianness_conversion`.
Please refer to secton :ref:`modbus_mapping_complex_data_types` for more information about data types.

Example initialization of mapped values:

.. code:: c

    #include "mbcontroller.h"       // for mbcontroller defines and api
    val_32_arr holding_float_abcd[2] = {0};
    val_64_arr holding_double_ghefcdab[2] = {0};
    ...
    // set the Modbus parameter to specific format
    portENTER_CRITICAL(&param_lock); // critical section is required if the stack is active
    mb_set_float_abcd(&holding_float_abcd[0], (float)12345.0);
    mb_set_float_abcd(&holding_float_abcd[1], (float)12345.0);
    mb_set_double_ghefcdab(&holding_double_ghefcdab[0], (double)12345.0);
    portEXIT_CRITICAL(&param_lock);
    ...
    // The actual abcd formatted value can be converted to actual float represenatation as below
    ESP_LOGI("TEST", "Test value abcd: %f", mb_get_float_abcd(&holding_float_abcd[0]));
    ESP_LOGI("TEST", "Test value abcd: %f", mb_get_float_abcd(&holding_float_abcd[1]));
    ESP_LOGI("TEST", "Test value ghefcdab: %lf", mb_get_double_ghefcdab(&holding_double_ghefcdab[0]));
    ...

The slave communication object supports initialization of special object identification structure which is vendor specific and can clarify some slave specific information for each slave object. The API functions below can be used to set and get this information from the slave object accordingly.
This information set in the slave can be retrieved by master object using the standard Modbus command `0x11 - <Report Slave ID>`.

:cpp:func:`mbc_set_slave_id`

Allows to set vendor specific slave ID for the concrete slave object.

.. note:: Each slave object sets the short default identificator defined in ``CONFIG_FMB_CONTROLLER_SLAVE_ID`` Kconfig value on start. This can be overridden by this API function. The option ``CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT`` allows disabling this functionality and the option ``CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE`` defines the maximum size of the slave identification structure.

Example of initialization for slave ID:

.. code:: c

    #include "mbcontroller.h"       // for mbcontroller defines and api
    ...
    static void *mbc_slave_handle = NULL;
    mb_communication_info_t comm_config = {
        .ser_opts.port = MB_PORT_NUM,
        .ser_opts.mode = MB_RTU,
        .ser_opts.baudrate = MB_DEV_SPEED,
        .ser_opts.parity = MB_PARITY_NONE,
        .ser_opts.uid = MB_SLAVE_ADDR,
        .ser_opts.data_bits = UART_DATA_8_BITS,
        .ser_opts.stop_bits = UART_STOP_BITS_1
    };
    // Initialization of Modbus slave controller object
    ESP_ERROR_CHECK(mbc_slave_create_serial(&comm_config, &mbc_slave_handle));
    // Starts of modbus controller and stack
    esp_err_t err = mbc_slave_start(mbc_slave_handle);
    const char *pdevice_name = "my_slave_device_description"; // the vendor specific part for slave to be retrieved by master
    bool is_started = (bool)(err == ESP_OK);                  // running status of the slave to be reported
    // This is the way to set Slave ID information to retrieve it by master using <Report Slave ID> command.
    esp_err_t err = mbc_set_slave_id(mbc_slave_handle, comm_config.ser_opts.uid, is_started, (uint8_t *)pdevice_name, strlen(pdevice_name));
    if (err == ESP_OK) {
        ESP_LOG_BUFFER_HEX_LEVEL("SET_SLAVE_ID", (void*)pdevice_name, strlen(pdevice_name), ESP_LOG_WARN);
    } else {
        ESP_LOGE("SET_SLAVE_ID", "Set slave ID fail, err=%d.", err);
    }
    ...

:cpp:func:`mbc_get_slave_id`

Allows to get actual slave UID, running status of slave and vendor specific data. The default object identificator is defined by option ``CONFIG_FMB_CONTROLLER_SLAVE_ID`` as ``01 ff 33 22 11`` (slave UID, running state, extended vendor data structure) and can be overridden in user application.

Example to get the actual slave identificator:

.. code:: c

    #include "mbcontroller.h"
    #include "sdkconfig.h"
    ...
    static void *mbc_slave_handle = NULL; // the object is initialized and started
     // the vendor specific part of structure for slave to be retrieved by master
    uint8_t current_slave_id[CONFIG_FMB_CONTROLLER_SLAVE_ID_MAX_SIZE] = {0};
    esp_err_t err = mbc_get_slave_id(mbc_slave_handle, &current_slave_id[0], &length);
    if (err == ESP_OK) {
        ESP_LOGW("GET_SLAVE_ID", "Get slave ID, length=%u.", length);
        ESP_LOG_BUFFER_HEX_LEVEL("GET_SLAVE_ID", (void*)current_slave_id, length, ESP_LOG_WARN);
    } else {
        ESP_LOGE("GET_SLAVE_ID", "Get slave ID fail, err=%d.", err);
    }
    ...

.. _modbus_api_slave_communication:

Slave Communication
^^^^^^^^^^^^^^^^^^^

The function below is used to start Modbus controller interface and allows communication.

:cpp:func:`mbc_slave_start`

.. code:: c

    static void* slave_handle = NULL;
    ....
    ESP_ERROR_CHECK(mbc_slave_start(slave_handle)); // The handle must be initialized prior to start call.

:cpp:func:`mbc_slave_check_event`

The blocking call to function waits for a event specified (represented as an event mask parameter). Once the master accesses the parameter and the event mask matches the parameter type, the application task will be unblocked and function will return the corresponding event :cpp:type:`mb_event_group_t` which describes the type of register access being done.

:cpp:func:`mbc_slave_get_param_info`

The function gets information about accessed parameters from the Modbus controller event queue. The KConfig ``CONFIG_FMB_CONTROLLER_NOTIFY_QUEUE_SIZE`` key can be used to configure the notification queue size. The timeout parameter allows a timeout to be specified when waiting for a notification. The :cpp:type:`mb_param_info_t` structure contains information about accessed parameter.

.. list-table:: Table 4 Description of the register info structure: :cpp:type:`mb_param_info_t`
  :widths: 10 90
  :header-rows: 1
  
  * - Field
    - Description
  * - ``time_stamp``
    - the time stamp of the event when defined parameter is accessed 
  * - ``mb_offset``
    - start Modbus register accessed by master
  * - ``type``
    - type of the Modbus register area being accessed (See the :cpp:type:`mb_event_group_t` for more information)
  * - ``address``
    - memory address that corresponds to accessed register in defined area descriptor
  * - ``size``
    - number of registers being accessed by master

Example to get event when holding or input registers accessed in the slave:

.. code:: c

    #define MB_READ_MASK            (MB_EVENT_INPUT_REG_RD | MB_EVENT_HOLDING_REG_RD)
    #define MB_WRITE_MASK           (MB_EVENT_HOLDING_REG_WR)
    #define MB_READ_WRITE_MASK      (MB_READ_MASK | MB_WRITE_MASK)
    #define MB_PAR_INFO_GET_TOUT    (10 / portTICK_RATE_MS)                           
    ....
    static void *slave_handle = NULL;  // communication object handle
    ....
    // Get the mask of the queued events, the function
    // blocks while waiting for register access
    (void)mbc_slave_check_event(mbc_slave_handle, MB_READ_WRITE_MASK);
    // Obtain the parameter information from parameter queue regarding access from master 
    ESP_ERROR_CHECK(mbc_slave_get_param_info(mbc_slave_handle, &reg_info, MB_PAR_INFO_GET_TOUT));
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

:cpp:func:`mbc_slave_lock`

:cpp:func:`mbc_slave_unlock`

The direct access to slave register area from user application must be protected by critical section. The following functions can be used to protect access to the data from registered mapping area while the communication object is active.

.. code:: c

    static void *slave_handle = NULL;  // communication object handle
    ...
    (void)mbc_slave_lock(slave_handle); // ignore the returned error if the object is not actual
    holding_reg_area[1] += 10; // the data is part of initialized register area accessed by slave
    (void)mbc_slave_unlock(slave_handle);

The access to registered area shared between several slave objects from user application must be protected by critical section base on spin lock:

.. code:: c

    #include "freertos/FreeRTOS.h"
    ...
    static portMUX_TYPE g_spinlock = portMUX_INITIALIZER_UNLOCKED;
    ...
    portENTER_CRITICAL(&param_lock);
    holding_reg_area[2] = 123;
    portEXIT_CRITICAL(&param_lock);

.. _modbus_api_slave_destroy:

Modbus Slave Teardown
^^^^^^^^^^^^^^^^^^^^^

This function stops the Modbus communication stack, destroys the controller interface, and frees all used active objects allocated for the slave.  

:cpp:func:`mbc_slave_delete`

.. code:: c

    ESP_ERROR_CHECK(mbc_slave_delete(slave_handle)); // delete the master communication object defined by its handle