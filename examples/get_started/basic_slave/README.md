| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C6 | ESP32-H2 | ESP32-P4 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |

# ESP-Modbus Slave Basic Example

## Overview

Modbus slave example for ESP-IDF is part of a series of examples that aim to teach newcomers how to use the Esp-Modbus API. It Covers: slave setup and initialization, Register area descriptor configuration, Responding to Modbus master read/write requests over Serial (RTU/ASCII) or TCP.


## Table of Contents

- [Overview](#overview)
- [How to Set Up and Use the Example](#how-to-set-up-and-use-the-example)
  - [Setup](#setup)
    - [Quick TCP Test with pymodbus (PC as TCP Master)](#quick-tcp-test-with-pymodbus-pc-as-tcp-master)
    - [Quick Serial Test with pymodbus (PC as Serial Master)](#quick-serial-test-with-pymodbus-pc-as-serial-master)
    - [Serial Communication](#serial-communication)
  - [Configure the Application](#configure-the-application)
    - [Serial Communication Configuration](#serial-communication-configuration)
    - [TCP Communication Configuration](#tcp-communication-configuration)
  - [Build and Flash](#build-and-flash)
  - [Code Overview](#code-overview)
- [Example Output](#example-output)

## How to Set Up and Use the Example

### Setup

This example can be used with:

- Two ESP32 boards (or compatible devices) that support UART or TCP communication, with the second board flashed with the [basic master example](../basic_master/).
- Modbus emulation software for the master side (proprietary commercial license; [Modbus tools](https://modbustools.com/) by Witte Software), for example:
  - [Modbus Poll](https://modbustools.com/modbus_poll.html)
- Local script simulating the master side: [ModbusMasterScript.py](ModbusMasterScript.py) for TCP or serial (RTU).


#### Quick TCP Test with pymodbus (PC as TCP Master)

For a simpler setup without a second board or commercial Modbus software, you can run a Modbus TCP master on your PC using [ModbusMasterScript.py](ModbusMasterScript.py). The script uses [pymodbus](https://pymodbus.readthedocs.io/en/latest/) to emulate the master side while the ESP32 board runs the slave example.

1. **Install pymodbus**

   ```bash
   pip3 install pymodbus
   ```

2. **Configure the slave example**

   From the `basic_slave` folder, run:

   ```bash
   idf.py menuconfig
   ```

   Set the following options:

   - **Component config → Modbus configuration → Enable Modbus stack support for TCP communication mode** (`FMB_COMM_MODE_TCP_EN`)
   - In the same menu, set **Modbus TCP port number** to `1502` (`FMB_TCP_PORT_DEFAULT`)
   - In the main menu, set **Modbus slave address** to `1` (`MB_SLAVE_ADDR`)
   - **Example Connection Configuration → Wi-Fi SSID** and **Wi-Fi password** (`EXAMPLE_CONNECT_WIFI`, `EXAMPLE_WIFI_SSID`, `EXAMPLE_WIFI_PASSWORD`)

   **Note:** Keep in mind the the mode selected, IPv4 or IPv6

3. **Flash the slave example**

   ```bash
   idf.py -p PORT flash monitor
   ```

4. **Start the master script**

   From the `basic_slave` folder, run:

   ```bash
   python3 ModbusMasterScript.py tcp HOST PORT
   ```

   - `HOST` — slave IP address for the master to connect to (the slave IP can be retrieved from the terminal log)
   - `PORT` — TCP port (use `1502` to match `FMB_TCP_PORT_DEFAULT`)
   - `--base_address` — optional register base address (default: `40001`)
   - `--uid` — optional slave unit ID (default: `1`)

   **Note:** Keep in mind that `--uid` is only considered in TCP mode if **Modbus TCP enable UID (Unit Identifier) support** (`FMB_TCP_UID_ENABLED`) is enabled in menuconfig. Otherwise the slave ignores the unit ID.

   Example:

   ```bash
   python3 ModbusMasterScript.py tcp 192.168.33.127 1502
   ```

   The script starts a Modbus TCP master that reads and writes the same holding register (address `40001`, offset `0`).

   

   **Note:** The PC running the script and the ESP32 board must be on the same network.

#### Quick Serial Test with pymodbus (PC as Serial Master)

For serial RTU without a second board or commercial Modbus software, run a Modbus serial master on your PC using [ModbusMasterScript.py](ModbusMasterScript.py). The script uses [pymodbus](https://pymodbus.readthedocs.io/) to emulate the master side while the ESP32 board runs the slave example.

**Hardware required:** a **UART-to-USB converter**. The converter provides the serial port that the script accesses.

1. **Install pymodbus and pyserial**

   ```bash
   pip3 install pymodbus pyserial
   ```

2. **Wire the slave board UART to the UART-to-USB converter**

   Keep in mind that for a plain UART-to-USB converter the RS485 half-duplex option should be disabled.

   ```text
   ESP Slave                    UART-to-USB converter (PC)
   ────────────                    ─────────────────────────
   TXD (MB_UART_TXD menuconfig option) ----→ RXD
   RXD (MB_UART_RXD menuconfig option) ←---- TXD
   GND                                 ----→ GND
   ```

3. **Identify the converter serial port**

   Plug in only the UART-to-USB converter and note the device name:

   - **Linux:** `ls /dev/ttyUSB*` or `ls /dev/ttyACM*` (for example `/dev/ttyUSB0`)
   - **Windows:** Device Manager → Ports (COM & LPT) (for example `COM3`)

   This is **not** the same port used by `idf.py flash monitor` for the ESP board.

4. **Configure the slave example**

   From the `basic_slave` folder, run:

   ```bash
   idf.py menuconfig
   ```

   Set the following options:

   - **Component config → Modbus configuration → Enable Modbus stack support for RTU mode** (`FMB_COMM_MODE_RTU_EN`)
   - **Modbus Serial Example Configuration** → baud rate `115200` (`MB_UART_BAUD_RATE`), TX/RX pins matching your wiring, and **disable** RS485 half-duplex for a plain UART link
   - In the main menu, set **Modbus slave address** to `1` (`MB_SLAVE_ADDR`)

5. **Flash the slave example**

   ```bash
   idf.py -p PORT flash monitor
   ```

6. **Start the master script**

   From the `basic_slave` folder, run:

   ```bash
   python3 ModbusMasterScript.py serial PORT
   ```

   - `PORT` — serial device of the UART-to-USB converter (for example `/dev/ttyUSB0` or `COM3`)

   Optional arguments (defaults match the basic slave example):

   - `--baudrate` — UART baud rate (default: `115200`)
   - `--base_address` — optional register base address (default: `40001`)
   - `--uid` — optional slave unit ID (default: `1`)

   Example:

   ```bash
   python3 ModbusMasterScript.py serial /dev/ttyUSB0
   ```

   The script starts a Modbus RTU master that reads and writes the same holding register (address `40001`, offset `0`).

#### Serial Communication

For two-board communication, plain UART or UART driving an RS485 transceiver can be used to connect the master and slave boards.

**RS485 Example Circuit Schematic:**

```text
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

**Alternative:** Emulate the master on a PC with [ModbusMasterScript.py](ModbusMasterScript.py) (`serial` mode). A UART-to-USB converter is required; see [Quick Serial Test with pymodbus (PC as Serial Master)](#quick-serial-test-with-pymodbus-pc-as-serial-master).

### Configure the Application

Start in the `basic_slave` folder and run the following command in the terminal to configure the Kconfig settings:

```bash
idf.py menuconfig
```

**Select only one communication mode** under **Component config → Modbus configuration**:

```text
        [ ] <FMB_COMM_MODE_TCP_EN> Enable Modbus stack support for TCP communication mode
        [ ] <FMB_COMM_MODE_RTU_EN> Enable Modbus stack support for RTU mode
        [ ] <FMB_COMM_MODE_ASCII_EN> Enable Modbus stack support for ASCII mode
```

Also set **Modbus slave address** (`MB_SLAVE_ADDR`) in the main example menu.

#### Serial Communication Configuration

For serial communication, after enabling RTU or ASCII, configure the UART pins and settings in the **Modbus Serial Example Configuration** menu:

```text
         <MB_UART_PORT_NUM> UART port number
         <MB_UART_BAUD_RATE> UART communication speed
         <MB_UART_RXD> UART RXD pin number
         <MB_UART_TXD> UART TXD pin number
         <MB_UART_RTS> UART RTS pin number
         <MB_USE_RS485_HALF_DUPLEX_EN> Enable RS485 driver in half-duplex mode
```

**Note:** If RS485 mode is selected, the UART RTS pin controls the half-duplex direction.

**Note:** If RS485 mode is not selected, connect UART TX–RX and GND–GND between boards.

**Important:** Master and slave must use the same communication mode (for example, both RTU or both ASCII).

**UART Pin Reference Table:**

| UART Interface        | Kconfig     | Default pins for ESP32 (C6) | Default pins for ESP32-S2 (S3, C3, C2, H2) | External RS485 Driver Pin |
| --------------------- | ----------- | --------------------------- | ----------------------------------------- | ------------------------- |
| Transmit Data (TxD)   | MB_UART_TXD | GPIO23                      | GPIO9                                     | DI                        |
| Receive Data (RxD)    | MB_UART_RXD | GPIO22                      | GPIO8                                     | RO                        |
| Request To Send (RTS) | MB_UART_RTS | GPIO18                      | GPIO10                                    | ~RE/DE                    |
| Ground                | n/a         | GND                         | GND                                       | GND                       |

**Note:** Each target chip has different GPIO pins available. Refer to the UART documentation for your selected target for more information.

#### TCP Communication Configuration

For TCP connection, select one of these communication options in the **Example Connection Configuration** menu:

```text
         [ ] <EXAMPLE_CONNECT_WIFI> connect using Wi-Fi interface
         [ ] <EXAMPLE_CONNECT_ETHERNET> connect using Ethernet interface
```

For Wi-Fi connection, configure the network SSID and password in menuconfig or manually.

### Build and Flash

After configuring this slave example (and the master side, if you use the [basic master example](../basic_master/)), build and flash the project:

**Note:** When using two boards, it is recommended to flash the slave first, then the master.

```bash
idf.py -p PORT flash monitor
```

(To exit the serial monitor, press `Ctrl-]`.)

See the [Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/index.html#get-started) for complete steps to configure and use ESP-IDF to build and flash projects.

### Code Overview

The ESP-Modbus slave flow in this example is:

1. `mbc_slave_create_serial()` / `mbc_slave_create_tcp()` — create the slave instance
2. `mbc_slave_set_descriptor()` — define each register area and initialize register values
3. `mbc_slave_start()` — start the slave stack
4. `mbc_slave_check_event()` — blocking call that waits for read/write events from the master
5. `mbc_slave_get_param_info()` — retrieve details of the master request into an `mb_param_info_t` structure
6. `mbc_slave_delete()` — shut down the slave instance (TCP also calls `destroy_services()`)

Further reading: [Modbus slave API overview](https://docs.espressif.com/projects/esp-modbus/en/stable/esp32/slave_api_overview.html) and [ESP-Modbus documentation](https://docs.espressif.com/projects/esp-modbus/en/stable/esp32/).

## Example Output

Expected console output during execution:

```text
I (5850) BASIC_MODBUS_SLAVE: Modbus slave stack initialized...
I (5860) BASIC_MODBUS_SLAVE: Start Modbus basic slave example...
I (94940) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG READ REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (95150) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG WRITE REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (96330) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG READ REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (96430) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG WRITE REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (97740) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG READ REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
...
I (97840) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG WRITE REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (98890) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG READ REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (98990) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG WRITE REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (100030) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG READ REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (100130) BASIC_MODBUS_SLAVE: Slave ID:0x3ffc8034 - HOLDING REG WRITE REG_AREA_ADDR:0x3ffbbc40 OFFSET:0 NUMBER_REG:1
I (106060) BASIC_MODBUS_SLAVE: Destroy slave...
I (106180) main_task: Returned from app_main()
```
