ESP-Modbus
==========

Overview
--------

The Modbus serial communication protocol is de facto standard protocol widely used to connect industrial electronic devices. Modbus allows communication among many devices connected to the same network, for example, a system that measures temperature and humidity and communicates the results to a computer. The Modbus protocol uses several types of data: Holding Registers, Input Registers, Coils (single bit output), Discrete Inputs. Versions of the Modbus protocol exist for serial port and for Ethernet and other protocols that support the Internet protocol suite. There are many variants of Modbus protocols, some of them are:

    * ``Modbus RTU`` — This is used in serial communication and makes use of a compact, binary representation of the data for protocol communication. The RTU format follows the commands/data with a cyclic redundancy check checksum as an error check mechanism to ensure the reliability of data. Modbus RTU is the most common implementation available for Modbus. A Modbus RTU message must be transmitted continuously without inter-character hesitations. Modbus messages are framed (separated) by idle (silent) periods. The RS-485 interface communication is usually used for this type.
    * ``Modbus ASCII`` — This is used in serial communication and makes use of ASCII characters for protocol communication. The ASCII format uses a longitudinal redundancy check checksum. Modbus ASCII messages are framed by leading colon (":") and trailing newline (CR/LF).
    * ``Modbus TCP/IP or Modbus TCP`` — This is a Modbus variant used for communications over TCP/IP networks, connecting over port 502. It does not require a checksum calculation, as lower layers already provide checksum protection.

.. note:: This documentation (and included code snippets) requires some familiarity with the Modbus protocol. Refer to the Modbus Organization's with protocol specifications for specifics :ref:`modbus_organization`.

.. _modbus_supported_communication_options:

Modbus Supported Communication Options
--------------------------------------

The Modbus library supports the standard communication options as per Modbus specification stated below.

.. list-table:: Standard Modbus communication options
  :widths: 10 90
  :header-rows: 1
  
  * - Modbus option
    - Description of the option
  * - RTU communication
    - * 1 start bit
      * 8 data bits, least significant bit sent first
      * 1 bit for even / odd parity-no bit for no parity
      * 1 stop bit if parity is used, 2 stop bits if no parity
      * Cyclical Redundancy Check (CRC)
  * - ASCII communication
    - * 1 start bit
      * 7-8 data bits, least significant bit sent first
      * 1 bit for even / odd parity-no bit for no parity
      * 1 stop bit if parity is used, 2 stop bits if no parity
      * Longitudinal Redundancy Check (LRC)
  * - TCP communication
    - * Communications between client (master) - server (slave) over TCP/IP networks
      * Connection uses the standard port 502
      * The frames do not require checksum calculation (provided by lower layers)

Some vendors may use subset of communication options. In this case the detailed information is clarified in the device manual and it is possible to override the standard communication options for support of such devices.
Please refer to :ref:`modbus_api_slave_setup_communication_options`, :ref:`modbus_api_master_setup_communication_options` for more information.

Messaging Model And Data Mapping
--------------------------------

Modbus is an application protocol that defines rules for messaging structure and data organization that are independent of the data transmission medium. Traditional serial Modbus is a register-based protocol that defines message transactions that occur between master(s) and slave devices (multiple masters are allowed on using Modbus TCP/IP). The slave devices listen for communication from the master and simply respond as instructed. The master(s) always controls communication and may communicate directly to one slave, or all connected slaves, but the slaves cannot communicate directly with each other.

.. figure:: ../_static/modbus-segment.png
    :align: center
    :scale: 80%
    :alt: Modbus segment diagram
    :figclass: align-center

    Modbus segment diagram

.. note:: It is assumed that the number of slaves and their register maps are known by the Modbus master before the start of stack.

The register map of each slave device is usually part of its device manual. A Slave device usually permits configuration of its short slave address and communication options that are used within the device's network segment.

The Modbus protocol allows devices to map data to four types of registers (Holding, Input, Discrete, Coil). The figure below illustrates an example mapping of a device's data to the four types of registers.

.. figure:: ../_static/modbus-data-mapping.png
    :align: center
    :scale: 80%
    :alt: Modbus data mapping
    :figclass: align-center

    Modbus data mapping

.. _modbus_mapping_complex_data_types:

Mapping Of Complex Data Types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As per section 4.2 of Modbus specification, "MODBUS uses a ``big-Endian`` representation for addresses and data items. This means that when a numerical quantity larger than a single byte is transmitted, the most significant byte is sent first". The biggest official structure defined by the Modbus specification is a 16-bit word register, which is 2 bytes. However, vendors sometimes group two or even four 16-bit registers together to be interpretted as 32-bit or 64-bit values, respectively. It is also possible when the Modbus vendors group many registers together for serial numbers, text strings, time/date, etc. Regardless of how the vendor intends the data to be interpreted, the Modbus protocol itself simply transfers 16-bit word registers. These values grouped from registers may use either little-endian or big-endian register order.

.. note:: Each individual 16-bit register, is encoded in big-endian order (assuming the Modbus device abides by the Modbus specification). However, the 32-bit and 64-bit types naming conventions like ABCD or ABCDEFGH, does not take into account the network format byte order of frame. For example: the ABCD prefix for 32-bit values means the common Modbus mapping format and corresponds to the CDAB on network format (order in the frame).

Common Data Types Supported By Modbus Vendors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table:: Table 1 basic types used by Modbus vendors
  :widths: 8 3 20
  :header-rows: 1

  * - Type
    - Range
    - Format description
  * - U8, I8 - Unsigned/Signed 8-bit type
    - (0 .. 255)/(-128 .. 127)
    - Common unsigned 8-bit type that is stored usually in one Modbus register. The value can be stored in HI or LO byte of the register or packed with the next byte into one 16 - bit register.
  * - U16 - Unsigned integer 16-bit type
    - 0 - 65535
    - Stored in one 16-bit register. The values can be stored with AB or BA endianness.
  * - I16 - Signed integer 16-bit type
    - -32768 to 32767 is allowed. 
    - Stored in one 16-bit register. The values can be stored with AB or BA forendiannessmat.
  * - I32 - Signed long integer 32-bit type
    - -2147483648 to 2147483647 is allowed. 
    - Stored in two consecutive 16-bit register. The values can be stored with ABCD - DCBA endianness (see below).
  * - U32 - Unsigned long integer 32-bit type
    - 0 to 4294967295 is allowed. 
    - Stored in two consecutive 16-bit register. The values can be stored with ABCD - DCBA endianness.
  * - U64 Unsigned Long long integers (Unsigned integer 64)
    - 0 to 18446744073709551615 is allowed. 
    - Stored in four consecutive 16-bit register. The values can be stored with ABCDEFGH - BADCFEHG endianness.
  * - I64 Signed Long long integers (Signed integer 64)
    - -9223372036854775808 to 9223372036854775807 is allowed. 
    - Stored in four consecutive 16-bit register. The values can be stored with ABCDEFGH - BADCFEHG endianness.
  * - Floating point single precision 32-bit
    - 1.17549435E-38 to 3.40282347E+38 is allowed.
    - Stored in two consecutive 16-bit register per IEEE754. The values can be stored with ABCD - DCBA endianness.
  * - Floating point double precision 64-bit
    - +/-5.0E-324 to +/-1.7E+308 is allowed.
    - Stored in four consecutive 16-bit register per IEEE754. The values can be stored with ABCDEFGH - BADCFEHG endianness.

As showed in the table above the float and double types do not fit to the 16-bit register and reguire several consecutive registers be used to store the value. However, different manufacturers store the consecutive bytes in different order (not standardized). For example: The DCBA prefix means inversed Modbus format (BADC order on network format).

.. list-table:: Table 2 Modbus byte order for extended types
  :widths: 3 28
  :header-rows: 1

  * - Postfix
    - Format description
  * - ABCD
    - Big endian, high order byte first
  * - CDAB
    - Big endian, reversed register order (Little endian with byte swap)
  * - BADC
    - Little endian, reversed register order (Big endian with byte swap)
  * - DCBA
    - Little endian (Low order byte first)

The extended data types are used to define all possible combinations of groupped values are represented below and correspond to ``param_type`` field of the data dictionary as described in the table below:

.. list-table:: Table 3 Modbus extended data types of characteristics
  :widths: 6 28 10
  :header-rows: 1

  * - Type 
    - Format type description (common format)
    - Format type (network format)
  * - :cpp:enumerator:`PARAM_TYPE_U8`
    - compatibility type corresponds to :cpp:enumerator:`PARAM_TYPE_U8_A`
    - Unsigned integer 8 bit type
  * - :cpp:enumerator:`PARAM_TYPE_U16`
    - Unsigned integer 16 bit type, corresponds to :cpp:enumerator:`PARAM_TYPE_U16_AB`
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_U32`
    - Default unsigned integer 32 bit type, corresponds to :cpp:enumerator:`PARAM_TYPE_U32_ABCD`
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_FLOAT`
    - Default unsigned integer 32 bit type, corresponds to :cpp:enumerator:`PARAM_TYPE_FLOAT_ABCD`
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_ASCII`
    - Default ASCII string format
    - Packed ASCII string data
  * - :cpp:enumerator:`PARAM_TYPE_BIN`
    - Binary data type
    - Default type for binary packed data
  * - :cpp:enumerator:`PARAM_TYPE_I8_A`
    - I8 signed integer in low byte of register, high byte is zero
    - I8 signed integer LO
  * - :cpp:enumerator:`PARAM_TYPE_I8_B`
    - I8 signed integer in high byte of register, low byte is zero
    - I8 signed integer HI
  * - :cpp:enumerator:`PARAM_TYPE_U8_A`
    - U8 unsigned integer written to low byte of register, high byte is zero
    - U8 unsigned integer LO
  * - :cpp:enumerator:`PARAM_TYPE_U8_B`
    - U8 unsigned integer written to hi byte of register, low byte is zero
    - U8 unsigned integer HI
  * - :cpp:enumerator:`PARAM_TYPE_I16_AB`
    - I16 signed integer, big endian
    - Big endian
  * - :cpp:enumerator:`PARAM_TYPE_I16_BA`
    - I16 signed integer, little endian
    - Little endian
  * - :cpp:enumerator:`PARAM_TYPE_U16_AB`
    - U16 unsigned integer, big endian
    - Big endian
  * - :cpp:enumerator:`PARAM_TYPE_U16_BA`
    - U16 unsigned integer, little endian
    - Little endian
  * - :cpp:enumerator:`PARAM_TYPE_I32_ABCD`
    - I32 ABCD signed integer, big endian
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_I32_CDAB`
    - I32 CDAB signed integer, big endian, reversed register order
    - Big endian
  * - :cpp:enumerator:`PARAM_TYPE_I32_BADC`
    - I32 BADC signed integer, little endian, reversed register order
    - Little endian
  * - :cpp:enumerator:`PARAM_TYPE_I32_DCBA`
    - I32 DCBA signed integer, little endian
    - Big endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_U32_ABCD`
    - U32 ABCD unsigned integer, big endian
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_U32_CDAB`
    - U32 CDAB unsigned integer, big endian, reversed register order
    - Big endian
  * - :cpp:enumerator:`PARAM_TYPE_U32_BADC`
    - U32 BADC unsigned integer, little endian, reversed register order
    - Little endian
  * - :cpp:enumerator:`PARAM_TYPE_U32_DCBA`
    - U32 DCBA unsigned integer, little endian
    - Big endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_FLOAT_ABCD`
    - Float ABCD floating point, big endian
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_FLOAT_CDAB`
    - Float CDAB floating point, big endian, reversed register order
    - Big endian
  * - :cpp:enumerator:`PARAM_TYPE_FLOAT_BADC`
    - Float BADC floating point, little endian, reversed register order
    - Little endian
  * - :cpp:enumerator:`PARAM_TYPE_FLOAT_DCBA`
    - Float DCBA floating point, little endian
    - Big endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_I64_ABCDEFGH`
    - I64, ABCDEFGH signed integer, big endian
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_I64_HGFEDCBA`
    - I64, HGFEDCBA signed integer, little endian
    - Big endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_I64_GHEFCDAB`
    - I64, GHEFCDAB signed integer, big endian, reversed register order
    - Big endian
  * - :cpp:enumerator:`PARAM_TYPE_I64_BADCFEHG`
    - I64, BADCFEHG signed integer, little endian, reversed register order
    - Little endian
  * - :cpp:enumerator:`PARAM_TYPE_U64_ABCDEFGH`
    - U64, ABCDEFGH unsigned integer, big endian
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_U64_HGFEDCBA`
    - U64, HGFEDCBA unsigned integer, little endian
    - Big endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_U64_GHEFCDAB`
    - U64, GHEFCDAB unsigned integer, big endian, reversed register order
    - Big endian
  * - :cpp:enumerator:`PARAM_TYPE_U64_BADCFEHG`
    - U64, BADCFEHG unsigned integer, little endian, reversed register order
    - Little endian
  * - :cpp:enumerator:`PARAM_TYPE_DOUBLE_ABCDEFGH`
    - Double ABCDEFGH floating point, big endian
    - Little endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_DOUBLE_HGFEDCBA`
    - Double HGFEDCBA floating point, little endian
    - Big endian byte swap
  * - :cpp:enumerator:`PARAM_TYPE_DOUBLE_GHEFCDAB`
    - Double GHEFCDAB floating point, big endian, reversed register order
    - Big endian
  * - :cpp:enumerator:`PARAM_TYPE_DOUBLE_BADCFEHG`
    - Double BADCFEHG floating point, little endian, reversed register order
    - Little endian
    
.. note:: The support for the extended data types should be enabled using the option ``CONFIG_FMB_EXT_TYPE_SUPPORT`` in kconfig menu.

The below diagrams show how the extended data types appear on network layer.

.. blockdiag::  /../_static/diag_frame.diag
    :scale: 80%
    :caption: Modbus master response with ABCD frame
    :align: center

.. blockdiag:: /../_static/modbus_frame_examples.diag
    :scale: 80%
    :caption: Modbus frame packaging examples (16-bit, 32-bit, 64-bit data)
    :align: center

The approach showed above can be used to pack the data into MBAP frames used by Modbus TCP as well as for other types with similar size.

.. _modbus_master_slave_configuration_aspects:

Important Configuration Aspects
-------------------------------

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

The following sections give an overview of how to use the ESP_Modbus component found under `components/esp-modbus`. The sections cover initialization of a Modbus port, and the setup a master or slave device accordingly:

- :ref:`modbus_api_port_initialization`
- :ref:`modbus_api_slave_overview`
- :ref:`modbus_api_master_overview`
