| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C6 | ESP32-H2 | ESP32-P4 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |

# Esp-Modbus Master Basic Example

## Overview

Modbus **master** example for ESP-IDF is part of a series of examples that aim to teach newcomers how to use the Esp-Modbus API. It Covers: master controller setup and initialization, attach a **data dictionary**, and perform read/write requests over **Serial (RTU/ASCII)** or **TCP**.

## Table of Contents

- [Overview](#overview)
- [How to Set Up and Use the Example](#how-to-set-up-and-use-the-example)
  - [Setup](#setup)
    - [Quick Test with pyModbusTCP (PC as Slave)](#quick-test-with-pymodbustcp-pc-as-slave)
    - [Quick Test with pymodbus (PC as Serial Slave)](#quick-test-with-pymodbus-pc-as-serial-slave)
    - [Serial Communication](#serial-communication)
  - [Configure the Application](#configure-the-application)
    - [Serial Communication Configuration](#serial-communication-configuration)
    - [TCP Communication Configuration](#tcp-communication-configuration)
      - [Slave IP Address Configuration](#slave-ip-address-configuration)
  - [Build and Flash](#build-and-flash)
  - [Code Overview](#code-overview)
    - [Characteristic Identifier (CID)](#characteristic-identifier-cid)
    - [Data Dictionary](#data-dictionary)
      - [Read/write flow](#readwrite-flow)
- [Example Output](#example-output)


## How to Set Up and Use the Example

### Setup

This example can be used with:

- Two ESP32 boards (or compatible devices) that support UART or TCP communication, the second board flashed with the basic Slave example.
- Modbus emulation software for the Slave side (proprietary commercial license; [modbus tools](https://modbustools.com/) by Witte Software), for example:
  - [Modbus Slave](https://modbustools.com/modbus_slave.html)
- Local scripts simulating the Slave side: [ModbusSlaveTCPScript.py](ModbusSlaveTCPScript.py) for TCP and [ModbusSlaveSerialScript.py](ModbusSlaveSerialScript.py) for serial (RTU/ASCII).

#### Quick Test with pyModbusTCP (PC as Slave)

For a simpler setup without a second board or commercial Modbus software, you can run a Modbus TCP slave on your PC using [ModbusSlaveTCPScript.py](ModbusSlaveTCPScript.py). The script uses [pyModbusTCP](https://pymodbustcp.readthedocs.io/en/latest/quickstart/index.html) to emulate the Slave side while the ESP32 board runs the Master example.

1. **Install pyModbusTCP**

   ```bash
   pip3 install pyModbusTCP
   ```

2. **Configure the Master example**

   From the `basic_master` folder, run:

   ```bash
   idf.py menuconfig
   ```

   Set the following options:

   - **Component config → Modbus configuration → Enable Modbus stack support for TCP communication mode** (`FMB_COMM_MODE_TCP_EN`)
   - In the same menu, set **Modbus TCP port number** to `1502` (`FMB_TCP_PORT_DEFAULT`)
   - **Modbus Example TCP Configuration → Configure Modbus slave addresses from stdin** (`MB_SLAVE_IP_FROM_STDIN`)
   - **Example Connection Configuration → WiFi SSID** and **WiFi password** (`EXAMPLE_CONNECT_WIFI`, `EXAMPLE_WIFI_SSID`, `EXAMPLE_WIFI_PASSWORD`)

3. **Find your local network interface IP address**

   The Master board must connect to the IP address of the PC running the slave script:

   - **Windows (PowerShell):** `ipconfig`
   - **Linux (terminal):** `ip addr show`

4. **Start the slave script**

   From the `basic_master` folder, run:

   ```bash
   python3 ModbusSlaveTCPScript.py HOST PORT
   ```

   - `HOST` — bind address for the slave server (use `0.0.0.0` to listen on all interfaces, or your PC's local IP)
   - `PORT` — TCP port (use `1502` to match `FMB_TCP_PORT_DEFAULT`)

   Example:

   ```bash
   python3 ModbusSlaveTCPScript.py 0.0.0.0 1502
   ```

   The script starts a Modbus TCP slave with one holding register (address `40001` offset `0`, value `0`) and waits for the Master to connect. It prints whenever that register value changes.

5. **Flash the Master example**

   ```bash
   idf.py -p PORT flash monitor
   ```

6. **Enter the slave address when prompted**

   When the console asks for the slave address, type:

   ```
   IP 0=<YOUR_LOCAL_IP>;1502
   ```

   Replace `<YOUR_LOCAL_IP>` with the IP address found in step 3. Example: `IP 0=192.168.1.100;1502`

   **Note:** The PC running the script and the ESP32 board must be on the same network.

#### Quick Test with pymodbus (PC as Serial Slave)

For serial (RTU/ASCII) without a second board or commercial Modbus software, run a Modbus serial slave on your PC using [ModbusSlaveSerialScript.py](ModbusSlaveSerialScript.py). The script uses [pymodbus](https://pymodbus.readthedocs.io/) to emulate the Slave side while the ESP32 board runs the Master example.

**Hardware required:** a **UART-to-USB converter**  The converter provides the serial port that the script opens.

1. **Install pymodbus and pyserial**

   ```bash
   pip3 install pymodbus pyserial
   ```

2. **Wire the Master UART to the UART-to-USB converter**

   Keep in mind that for plain UART-to-USB converter the option RS485 half-duplex should be disabled.

   ```
   ESP Master                    UART-to-USB converter (PC)
   ────────────                    ─────────────────────────
   TXD (MB_UART_TXD menuconfig option) ----→ RXD
   RXD (MB_UART_RXD menuconfig option) ←---- TXD
   GND                                 ----→ GND
   ```

3. **Identify the converter serial port**

   Plug in only the UART-to-USB converter and note the device name:

   - **Linux:** `ls /dev/ttyUSB*` or `ls /dev/ttyACM*` (for example `/dev/ttyUSB0`)
   - **Windows:** Device Manager → Ports (COM & LPT) (for example `COM3`)

   This is **not** the same port used by `idf.py flash monitor` for the board console USB.

4. **Configure the Master example**

   From the `basic_master` folder, run:

   ```bash
   idf.py menuconfig
   ```

   Set the following options:

   - **Component config → Modbus configuration → Enable Modbus stack support for RTU mode** (`FMB_COMM_MODE_RTU_EN`)  
     (or ASCII mode if you will start the script with `--mode ascii`)
   - **Modbus Example Serial Configuration** → baud rate `115200` (`MB_UART_BAUD_RATE`), TX/RX pins matching your wiring, and **disable** RS485 half-duplex for a plain UART link

5. **Start the slave script**

   From the `basic_master` folder, run:

   ```bash
   python3 ModbusSlaveSerialScript.py PORT
   ```

   - `PORT` — serial device of the UART-to-USB converter (for example `/dev/ttyUSB0` or `COM3`)

   Optional arguments (defaults match the example Master):

   - `--baudrate` — UART baud rate (default: `115200`)
   - `--mode` — `rtu` or `ascii` (default: `rtu`)

   Example:

   ```bash
   python3 ModbusSlaveSerialScript.py /dev/ttyUSB0 --baudrate 115200 --mode rtu
   ```

   The script starts a Modbus serial slave (slave id `1`) with one holding register (address `40001` offset `0`, value `0`) and waits for Master requests. It prints whenever that register value changes.

6. **Flash the Master example**

   Use the board  USB port (not the UART-to-USB converter):

   ```bash
   idf.py -p PORT flash monitor
   ```

   **Note:** Master and script must use the same mode (RTU or ASCII) and baud rate. Slave address `1` matches `MB_SLAVE_ADDR1` in the example data dictionary.

#### Serial Communication

For two-board communication, plain UART or UART driving a RS485 can be used to connect the Master and Slave boards.

**RS485 Example Circuit Schematic:**

```
                VCC ---------------+                                +--------------- VCC
                                   |                                |
                           +-------x-------+                +-------x-------+
                RXD <------| RO            | DIFFERENTIAL   |             RO|-----> RXD
                           |              B|--------------- |B              |
                TXD ------>| DI   MAX483   |    \  /        |    MAX483   DI|<----- TXD
ESP32 Board                |               |   RS-485 side  |               |            
 (Master)             +--->| DE            |    /  \        |             DE|---+         (Slave)
                      |    |              A|--------------- |A              |   |
                RTS --+----| /RE           |    PAIR        |            /RE|---+-- RTS
                           +-------x-------+                +-------x-------+
                                                                                        
```
**Note:** The MAX483 line driver is used for example purposes; other compatible RS485 transceiver chips can be substituted.

**Alternative:** Emulate the Slave on a PC with [ModbusSlaveSerialScript.py](ModbusSlaveSerialScript.py). A UART-to-USB converter is required; see [Quick Test with pymodbus (PC as Serial Slave)](#quick-test-with-pymodbus-pc-as-serial-slave).


### Configure the Application
Start at the basic_master folder and run the following command on terminal to configure the Kconfig settings:

```
idf.py menuconfig
```

**Select one communication mode** in:  **Component config → Modbus configuration** menu

        [ ] <FMB_COMM_MODE_TCP_EN> Enable Modbus stack support for TCP communication mode
        [ ] <FMB_COMM_MODE_RTU_EN> Enable Modbus stack support for RTU mode
        [ ] <FMB_COMM_MODE_ASCII_EN> Enable Modbus stack support for ASCII mode

#### Serial Communication Configuration

For serial communication, after setting RTU or ASCII, configure the UART pins and settings in the **Modbus Example Serial Configuration** menu:  

Should be set in Modbus Example Configuration menu:

```
         <MB_UART_PORT_NUM> UART port number
         <MB_UART_BAUD_RATE> UART communication speed
         <MB_UART_RXD> UART RXD pin number
         <MB_UART_TXD> UART TXD pin number
         <MB_UART_RTS> UART RTS pin number
         <MB_USE_RS485_HALF_DUPLEX_EN> Enable RS485 driver in half-duplex mode
```

**Note:** If RS485 mode is selected, the UART RTS pin control the half duplex direction.

**Note:** If RS485 mode is not selected, the UART should be connected TX - RX and GND - GND between boards.

**Important:** Master and Slave must use the same communication mode (e.g., both RTU or both ASCII).

**UART Pin Reference Table:**


  |   UART Interface      | Kconfig                  | Default pins for  ESP32 (C6)            | Default pins for ESP32-S2 (S3, C3, C2, H2) |  External RS485 Driver Pin                         |
  | ----------------------|--------------------|-----------------------|---------------------------|---------------------------|
  | Transmit Data (TxD)   | MB_UART_TXD        | GPIO23                | GPIO9                     | DI                        |
  | Receive Data (RxD)    | MB_UART_RXD        | GPIO22                | GPIO8                     | RO                        |
  | Request To Send (RTS) | MB_UART_RTS        | GPIO18                | GPIO10                    | ~RE/DE                    |
  | Ground                | n/a                | GND                   | GND                       | GND                       |


**Note:** Each target chip has different GPIO pins available. Refer to the UART documentation for your selected target for more information.

#### TCP Communication Configuration

For TCP connection, select one of these communication options in **Example Connection Configuration** menu:

```
         [ ] <EXAMPLE_CONNECT_WIFI> connect using WiFi interface
         [ ] <EXAMPLE_CONNECT_ETHERNET> connect using Ethernet interface
         [ ] <EXAMPLE_CONNECT_PPP> connect using Point to Point interface
```

For WiFi connection, you can configure the Network SSID and password in menuconfig or manually.

#### Slave IP Address Configuration

There are three ways to configure how the Master example obtains Slave IP addresses:

1. **mDNS Discovery (Automatic):**
   - Enable `CONFIG_MB_MDNS_IP_RESOLVER` to automatically query for Modbus services provided by Slaves in the network.
   - Requires the same option enabled on each Slave with a unique Modbus Slave address configured in the Modbus Example Configuration menu.

2. **Manual Input via stdin:**
   - Enable `CONFIG_MB_SLAVE_IP_FROM_STDIN` and `CONFIG_MB_CONSOLE_HELPER_ENABLED` to define Slave IP addresses manually.
   - Follow the prompt format: `"Waiting IP<N> from stdin:"` and enter the IP address in the format `IP <N>=<IP_ADDRESS>;<PORT>`, where N = (configured Slave address - 1).
   - Example: `IP 0=192.168.1.21;1502`

   **Note:** Keep in mind the option selected, `EXAMPLE_CONNECT_IPV4` or `EXAMPLE_CONNECT_IPV6`.

3. **Hardcoded in Source Code:**
   - Manually configure Slave addresses in the `slave_ip_address_table` in the Master source code.


### Build and Flash

After configuring both Master and Slave communication options, build and flash each project:

**Note:** It is recommended to flash the Slave code first, then the Master code.


```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, press ``Ctrl-]``.)

See the [**Getting Started Guide**](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/index.html#get-started) for complete steps to configure and use ESP-IDF to build and flash projects.


### Code Overview

The ESP implementation of Modbus includes an abstraction layer called the Modbus Controller, which introduces key concepts:

#### Characteristic Identifier (CID)

A CID represents a specific Modbus register to be read or written on a Slave device. It encapsulates all necessary metadata about the register.

In this example, `CID_EX_0` is the only CID and maps to the register named `Example_register`.

#### Data Dictionary

The Data Dictionary is a list that defines all Modbus registers the Master will access on Slave devices in the network. Each entry is a CID (Characteristic ID), which represents a specific piece of data like temperature, voltage, or a configuration value—and maps it to the corresponding Modbus registers on the Slave. This abstraction simplifies the handling of register addresses, data formats, and function codes.
For more details, refer to the [ESP-IDF Modbus Master API Overview documentation](https://docs.espressif.com/projects/esp-modbus/en/main/esp32/master_api_overview.html).


##### Read/write flow

1. **`mbc_master_set_descriptor()`** — attach the data dictionary to the master handle (done in `master_init()`).
2. **`mbc_master_get_cid_info()`** — retrieve info from data dictionary (name, type, permissions).
3. **`mbc_master_get_parameter()`** / **`mbc_master_set_parameter()`** — perform the Modbus read or write.


Further reading: [Modbus master API overview](https://docs.espressif.com/projects/esp-modbus/en/latest/esp32/master_api_overview.html) and [ESP-Modbus documentation](https://docs.espressif.com/projects/esp-modbus/en/stable/esp32/).

## Example Output

Expected console output during execution:

```
I (308) BASIC_MODBUS_MASTER: Modbus master stack initialized...
I (318) BASIC_MODBUS_MASTER: Start Modbus basic example...
I (508) BASIC_MODBUS_MASTER: Master Id:0x3ffb5e68 Characteristic ID #0 Example_register value = 11 write successful.
I (658) BASIC_MODBUS_MASTER: Master Id:0x3ffb5e68 Characteristic ID #0 Example_register value = 11 read successful.
I (798) BASIC_MODBUS_MASTER: Master Id:0x3ffb5e68 Characteristic ID #0 Example_register value = 12 write successful.
I (948) BASIC_MODBUS_MASTER: Master Id:0x3ffb5e68 Characteristic ID #0 Example_register value = 12 read successful.
...
I (3178) BASIC_MODBUS_MASTER: Master Id:0x3ffb5e68 Characteristic ID #0 Example_register value = 20 write successful.
I (3178) BASIC_MODBUS_MASTER: Destroy master...
I (3178) main_task: Returned from app_main()
```




 

