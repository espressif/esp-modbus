#!/usr/bin/python3

# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Unlicense OR CC0-1.0
# Script using pymodbus library to simulate Modbus Serial Slave side

import argparse

from pymodbus.framer import FramerType
from pymodbus.server import StartSerialServer
from pymodbus.simulator import DataType, SimData, SimDevice

parser = argparse.ArgumentParser()
parser.add_argument(
    "PORT",
    help="Serial port connected to the Master (ex /dev/ttyUSB0)",
)
parser.add_argument(
    "--baudrate",
    type=int,
    default=115200,
    help="UART baud rate (default: 115200, matches MB_UART_BAUD_RATE)",
)
parser.add_argument(
    "--mode",
    choices=["rtu", "ascii"],
    default="rtu",
    help="Modbus serial communication mode (default: rtu)",
)
args = parser.parse_args()


SLAVE_ID = 1


# Modbus docs use 4xxxx addresses for holding registers (e.g. 40001); libraries use 0-based PDU offsets.
# PDU address = (40001 + offset) - 40001
HOLDING_REGISTER_ADDRESS_BASE_RANGE = 40001
HOLDING_REGISTER_ACCESSED = 0
HOLDING_REGISTER_ADDRESS = (
    HOLDING_REGISTER_ADDRESS_BASE_RANGE + HOLDING_REGISTER_ACCESSED
) - HOLDING_REGISTER_ADDRESS_BASE_RANGE

HOLDING_REGISTER_VALUE = 0

state_holding_register = [HOLDING_REGISTER_VALUE]


async def on_register_access(
    function_code,
    start_address,
    address,
    count,
    current_registers,
    set_values,
):
    """Print whenever the Master reads or writes the holding register."""
    global state_holding_register

    if set_values is not None:
        state_holding_register = list(set_values)
        print(
            f"Holding register address {HOLDING_REGISTER_ADDRESS_BASE_RANGE} = "
            + str(state_holding_register)
        )


def modbus_slave_sim():
    framer = FramerType.RTU if args.mode == "rtu" else FramerType.ASCII

    # Shared register area with a single holding register at address 40001 offset 0.
    device = SimDevice(
        id=SLAVE_ID,
        simdata=[
            SimData(
                address=HOLDING_REGISTER_ADDRESS,
                count=1,
                values=HOLDING_REGISTER_VALUE,
                datatype=DataType.REGISTERS,
            )
        ],
        action=on_register_access,
    )

    print(
        f"Starting Modbus serial slave on {args.PORT} "
        f"(baudrate={args.baudrate}, slave_id={SLAVE_ID}, mode={args.mode})"
    )
    print("Holding Registers set")
    print("Waiting Master request..")

    try:
        StartSerialServer(
            context=device,
            port=args.PORT,
            baudrate=args.baudrate,
            framer=framer,
            bytesize=8,
            parity="N",
            stopbits=1,
        )
    except KeyboardInterrupt:
        print("\n Shutting Down Modbus Slave (server) ...")
    finally:
        print("Modbus Slave (server) is offline")


if __name__ == "__main__":
    modbus_slave_sim()
