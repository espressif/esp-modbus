| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C6 | ESP32-H2 | ESP32-P4 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |

# Modbus TCP-to-SERIAL Gateway Example

## Overview

This example shows how to build a Modbus gateway with `esp-modbus` component.

Gateway functionality can be described as below:

- Modbus TCP slave on Wi-Fi or Ethernet.
- Modbus serial master on an RS485 bus.
- The Modbus request MBAP Unit ID (UID) forwarded as the downstream serial (RTU/ASCII) slave address.

The gateway accepts Modbus TCP requests and forwards supported Modbus function codes to serial slaves. The TCP response is generated from the serial response.

Modbus multi slave segment connection schematic:
```
    UID#1  (RS485 serial Modbus network segment)
    +-----------+
    |  Modbus   |
    |  Serial   |---<>--+
    |  Slave 1  |       |
    +-----------+       |      +-------------------------------------+
    UID#2               |      |        Modbus TCP gateway           |
    +-----------+       |      | +-----------+        +-----------+  |      +-------------+
    |  Modbus   |       |      | |  Modbus   |        |  Modbus   |  |      |   Modbus    |
    |  Serial   |---<>--+---<>-+-|  Serial   |---<>---| TCP Slave |--+--<>--|  TCP Master |
    |  Slave  2 |       |      | |  Master   |        |           |  |      |             |
    +-----------+       |      | +-----------+        +-----------+  |      +-------------+
                        |      +-------------------------------------+
    UID#N         RS485 interface                             TCP-IP Network connection
    +-----------+       |                                   (Ethernet or WiFi connection)
    |  Modbus   |       |
    |  Serial   |---<>--+
    |  Slave N  |
    +-----------+
```

## Supported Function Codes

The example forwards these standard function codes:

- `0x01` Read Coils
- `0x02` Read Discrete Inputs
- `0x03` Read Holding Registers
- `0x04` Read Input Registers
- `0x05` Write Single Coil
- `0x06` Write Single Register
- `0x0F` Write Multiple Coils
- `0x10` Write Multiple Registers
- `0x17` Read/Write Multiple Registers

Note: Support for other function codes can be added as needed by writing additional custom handlers.

Serial timeouts are converted to Modbus gateway exceptions in the TCP response.

## How It Works: Custom Handlers

The gateway works by overriding the TCP slave's standard handler for each function code listed above with its own small handler (a `forward_*` function). The init helper `init_tcp_slave()` calls `install_gateway_handler()` once per function code, and each call registers that code's `forward_*` function directly with `mbc_set_handler()`, so esp-modbus routes matching requests straight to it. `restore_gateway_handler()` puts the previous handler back (or removes the entry if there was none) when the gateway shuts down.

For every request, its `forward_*` handler:

1. Reads the destination UID with `mbc_slave_get_request_uid()` (see [Gateway UID Mode](#gateway-uid-mode)).
2. Re-sends the same request to the serial slave via `mbc_master_send_request()`.
3. Writes the serial slave's response (or a timeout) back into the same buffer that held the TCP request, turning it into the TCP response.

Note: The custom handler `forward_*` functions cover the supported function codes: reads and writes of the same shape, such as coils and discrete inputs, or single coil and single register, share one handler.

Implementation details:

- The gateway needs the UID, which lives in the MBAP header that prepends the PDU. However, custom handlers are part of `mb_object` and only get a pointer to the PDU itself (function code + payload), not the MBAP header, so the handler cannot read the UID directly from the frame pointer. Walking backward from the PDU pointer to reach the header would depend on internal buffer layout and is not a supported approach, so the example instead calls `mbc_slave_get_request_uid()`, the helper meant for this purpose.

- Register values need a small byte-swap between the TCP PDU (big-endian) and the buffer expected by `mbc_master_send_request()` (native layout); that is what `gateway_pdu_be_to_reg_buffer()` / `gateway_reg_buffer_to_pdu_be()` do.

## Gateway UID Mode

This example enables `CONFIG_FMB_TCP_UID_ENABLED=y` and sets `CONFIG_MB_GATEWAY_TCP_UID=0` by default.

In this configuration, TCP slave UID `0` works as a wildcard for gateway use. Any MBAP UID received from a TCP client is accepted by the TCP slave and passed to the custom handler. The handler then forwards that UID as the serial slave address.

The example rejects UID `0` inside the handler because a Modbus TCP request expects a response, while serial broadcast requests do not.

## Hardware Required

- The example requires one ESP32 board that supports UART (RS485) and TCP communication as a gateway device, the second board flashed with the [Serial Slave example](https://github.com/espressif/esp-modbus/tree/main/examples/serial/mb_serial_slave).

- This example can be used with the [Modbus TCP Master example](https://github.com/espressif/esp-modbus/tree/main/examples/tcp/mb_tcp_master) or with third-party software used as a Modbus TCP Master (proprietary commercial license; [modbus tools](https://modbustools.com/) by Witte Software), for example: [Modbus Master](https://www.modbustools.com/modbus_poll.html).

Use one ESP32 board as the gateway and one or more Modbus (RTU/ASCII) slaves on an RS485 bus. The ESP32 boards require an RS485 transceiver such as MAX483 (3V logic) or similar be connected as below.

Default RS485 pins for serial slave board:

```
  ------------------------------------------------------------------------------------------------------------------------------
  |  UART Interface       | #define            | Default pins for      | Default pins for          | External RS485 Driver Pin |
  |                       |                    | ESP32 (C6)            | ESP32-S2 (S3, C3, C2, H2) |                           |
  | ----------------------|--------------------|-----------------------|---------------------------|---------------------------|
  | Transmit Data (TxD)   | CONFIG_MB_UART_TXD | GPIO23                | GPIO9                     | DI                        |
  | Receive Data (RxD)    | CONFIG_MB_UART_RXD | GPIO22                | GPIO8                     | RO                        |
  | Request To Send (RTS) | CONFIG_MB_UART_RTS | GPIO18                | GPIO10                    | ~RE/DE                    |
  | Ground                | n/a                | GND                   | GND                       | GND                       |
  ------------------------------------------------------------------------------------------------------------------------------
```

Connect RTS to the RS485 transceiver `DE` and `/RE` pins.

## Configure the project

```bash
idf.py set-target esp32
idf.py menuconfig
```
In `menuconfig`, configure:

- Network interface and Wi-Fi/Ethernet settings through `Example Connection Configuration`.
- TCP port `Modbus TCP to Serial Gateway Configuration -> Modbus TCP port number` and TCP UID support through the Modbus component option `Component config -> Modbus configuration -> Modbus TCP enable UID`.
- Gateway UART port, pins, baud rate, and request limits through `Modbus TCP to Serial Gateway Configuration`.
- Configure the Serial Slave example UID on the other board `Example Connection Configuration -> Modbus slave address`. The TCP requests from the external Modbus TCP Master with this UID will be forwarded to this slave address in Modbus Serial Slave.

## Build and Flash

Flash the gateway example into the board with connected RS485 adapter:

```bash
idf.py -p PORT build flash monitor
```

Connect the Modbus Serial Slave board, configure and flash. Refer to [Serial Slave Example](https://github.com/espressif/esp-modbus/blob/main/examples/serial/mb_serial_slave/README.md) for more information.


## Test

- Start the gateway, then use a Modbus TCP client pointed at the ESP32 IP address and configured port (default: `1502`).
- Connect the RS485 line driver of the gateway board to the Modbus segment where the Modbus Serial Slave(s) are connected.

Example expectations:

- TCP request with UID `1` is forwarded to serial (RTU/ASCII) slave address `1`.
- TCP request with UID `2` is forwarded to serial (RTU/ASCII) slave address `2`.
- If the downstream slave does not respond, the TCP client receives a Modbus gateway exception.

## Design Notes

- This example is intentionally a gateway, not a register mirror: the TCP slave has no register areas of its own configured. All forwarded values pass straight through to the serial slaves via the custom handlers described above.
- Generic vendor-specific raw PDU passthrough is not implemented here. That would require a deeper raw request/response API on the serial master side, since `mbc_master_send_request()` currently only exposes structured requests for the function codes listed above.
- The forwarding code is kept in the example's `main` component so users can read the full gateway flow in one file.

```log
I (4496) example_connect: Got IPv4 event: Interface "example_netif_sta" address: 192.168.99.252
I (4496) example_common: Connected to example_netif_sta
I (4506) example_common: - IPv4 address: 192.168.99.252,
I (4506) wifi:Set ps type: 0, coexist: 0

I (4516) uart: queue free spaces: 20
I (4516) mb_port.serial: mbm_rtu@0x3ffc7d98, suspend port from task.
I (4526) MB_TCP2SERIAL_GATEWAY: 0x3ffc7d98, Downstream serial master started on UART2 at 115200 baud.
I (4596) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Modbus TCP gateway is created.
I (4606) port.utils: Socket (#54), listener  on port: 1502, errno=0
I (4606) mb_port.tcp.slave: loop:0x3ffcd688  mbs_on_ready: fd: -1, bind is done
I (4606) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Modbus TCP slave started on port 1502, gateway UID 0.
I (4616) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Modbus TCP gateway is running.
I (4616) main_task: Returned from app_main()
I (6456) port.utils: Socket (#55), accept client connection from address[port]: 192.168.99.254[57896]
I (6676) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x04, addr: 0, count: 5, ESP_OK
I (6806) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read bits success, UID: 1, fc: 0x01, addr: 0, count: 10, ESP_OK
I (7456) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x03, addr: 0, count: 10, ESP_OK
I (7776) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x04, addr: 0, count: 5, ESP_OK
I (7906) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read bits success, UID: 1, fc: 0x01, addr: 0, count: 10, ESP_OK
I (8556) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x03, addr: 0, count: 10, ESP_OK
I (8776) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x04, addr: 0, count: 5, ESP_OK
I (8996) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read bits success, UID: 1, fc: 0x01, addr: 0, count: 10, ESP_OK
I (9656) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x03, addr: 0, count: 10, ESP_OK
I (9776) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x04, addr: 0, count: 5, ESP_OK
I (9996) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read bits success, UID: 1, fc: 0x01, addr: 0, count: 10, ESP_OK
I (10656) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x03, addr: 0, count: 10, ESP_OK
I (10776) MB_TCP2SERIAL_GATEWAY: 0x3ffcbd54, Forward read registers success, UID: 1, fc: 0x04, addr: 0, count: 5, ESP_OK
E (544186) mb_port.tcp.slave: 0x3ffcd418, node #0, socket(#55)(192.168.99.254), communication fail, err=-11, drop connection.
```