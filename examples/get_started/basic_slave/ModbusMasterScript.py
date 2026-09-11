#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Unlicense OR CC0-1.0
# Script using pyModbus library to simulate Modbus RTU or TCP  Master side

from pymodbus.client import ModbusSerialClient, ModbusTcpClient
from time import sleep
import argparse

parser = argparse.ArgumentParser()

subparsers = parser.add_subparsers(
    dest="mode",
    required=True,
    help="Selecting Serial or TCP mode for the script simulator",
)

parser.add_argument(
    "--base_address",
    type=int,
    default=40001,
    help="Base register address to be accessed in Slave example",
)

parser.add_argument(
    "--uid",
    type=int,
    default=1,
    help="Slave unit id to connect to",
)

serial_parser = subparsers.add_parser("serial")
serial_parser.add_argument(
    "PORT",
    help="Serial port where Slave Board is connected (ex /dev/ttyUSB0)",
)
serial_parser.add_argument(
    "--baudrate",
    type=int,
    default=115200,
    help="UART baud rate (default: 115200, matches MB_UART_BAUD_RATE)",
)

tcp_parser = subparsers.add_parser("tcp")
tcp_parser.add_argument("HOST")  # Slave IP to be connected
tcp_parser.add_argument("PORT", type=int)

args = parser.parse_args()

if args.mode == "serial":
    # Creates a Modbus RTU master connecting to slave board
    client = ModbusSerialClient(
        port=args.PORT,
        baudrate=args.baudrate,
        parity="N",
        stopbits=1,
        bytesize=8,
        timeout=1,
    )
elif args.mode == "tcp":
    # Creates a Modbus master connecting to slave host address
    client = ModbusTcpClient(args.HOST, port=args.PORT)


# Modbus docs use 4xxxx addresses for holding registers (e.g. 40001); pyModbus library use 0-based PDU offsets.
# PDU address = (40001 + offset) - 40001
HOLDING_REGISTER_ADDRESS_BASE_RANGE = args.base_address
HOLDING_REGISTER_ACCESSED = 0
HOLDING_REGISTER_ADDRESS = (
    HOLDING_REGISTER_ADDRESS_BASE_RANGE + HOLDING_REGISTER_ACCESSED
) - HOLDING_REGISTER_ADDRESS_BASE_RANGE


def modbus_master_sim():
    if not client.connect():
        if args.mode == "serial":
            print(f"Master client unable to connect to slave at PORT: {args.PORT}")
        elif args.mode == "tcp":
            print(
                f"Master client unable to establish connection with slave IP {args.HOST}:{args.PORT}"
            )
        return

    if args.mode == "serial":
        print(f"Master client connected to slave at PORT: {args.PORT}")
    elif args.mode == "tcp":
        print(f"Master client connected with slave IP:{args.HOST}:{args.PORT}")

    MASTER_MAX_RETRY = 10

    for request in range(MASTER_MAX_RETRY):
        result = client.read_holding_registers(
            address=HOLDING_REGISTER_ADDRESS, count=1, device_id=args.uid
        )

        if not result.isError():
            print(
                f"Read successful - Holding register address {HOLDING_REGISTER_ADDRESS_BASE_RANGE} = {result.registers[0]}"
            )
        else:
            print(f"Read error: {result}")

        result = client.write_register(
            address=HOLDING_REGISTER_ADDRESS,
            value=result.registers[0] + 1,
            device_id=args.uid,
        )

        if not result.isError():
            print(
                f"Write successful - Holding register address {HOLDING_REGISTER_ADDRESS_BASE_RANGE} = {result.registers[0]}"
            )
        else:
            print(f"Write error: {result}")

        sleep(1)

    print("\n Shutting Down Modbus Master (Client) ...")
    client.close()
    print("Modbus Master (Client) is offline")


if __name__ == "__main__":
    modbus_master_sim()
