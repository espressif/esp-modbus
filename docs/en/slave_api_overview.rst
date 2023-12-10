.. _modbus_api_slave_overview:

Modbus Slave API Overview
-------------------------

The sections below represent typical programming workflow for the slave API which should be called in following order:

1. :ref:`modbus_api_port_initialization` - Initialization of Modbus controller interface for the selected port.
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
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(slave_handle, reg_area));
    
    reg_area.type = MB_PARAM_INPUT;
    reg_area.start_offset = MB_REG_INPUT_START_AREA0;
    reg_area.address = (void*)&input_reg_area[0];
    reg_area.size = (sizeof(input_reg_area) << 1);
    ESP_ERROR_CHECK(mbc_slave_set_descriptor(slave_handle, reg_area));


At least one area descriptor per each Modbus register type must be set in order to provide register access to its area. If the master tries to access an undefined area, the stack will generate a Modbus exception.

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
    if (event & (MB_EVENT_HOLDING_REG_WR | MB_EVENT_HOLDING_REG_RD)) {
        ESP_LOGI(TAG, "HOLDING %s (%u us), ADDR:%u, TYPE:%u, INST_ADDR:0x%.4x, SIZE:%u",
                    rw_str,
                    (uint32_t)reg_info.time_stamp,
                    (uint32_t)reg_info.mb_offset,
                    (uint32_t)reg_info.type,
                    (uint32_t)reg_info.address,
                    (uint32_t)reg_info.size);
    } else if (event & (MB_EVENT_INPUT_REG_RD)) {
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
    holding_reg_area[2] += 10; // the data is part of initialized register area accessed by slave
    (void)mbc_slave_unlock(slave_handle);

.. _modbus_api_slave_destroy:

Modbus Slave Teardown
^^^^^^^^^^^^^^^^^^^^^

This function stops the Modbus communication stack, destroys the controller interface, and frees all used active objects allocated for the slave.  

:cpp:func:`mbc_slave_delete`

.. code:: c

    ESP_ERROR_CHECK(mbc_slave_delete(slave_handle)); // delete the master communication object defined by its handle