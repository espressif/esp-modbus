#!/usr/bin/python3

# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Unlicense OR CC0-1.0
# Script using pyModbusTCP library to simulate Modbus Slave side
from pyModbusTCP.server import ModbusServer
from time import sleep
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("HOST")
parser.add_argument("PORT", type=int)
args = parser.parse_args()

# Modbus docs use 4xxxx addresses for holding registers (e.g. 40001); libraries use 0-based PDU offsets.
# PDU address = (40001 + offset) - 40001
HOLDING_REGISTER_ADDRESS_BASE_RANGE = 40001
HOLDING_REGISTER_ACCESSED = 0
HOLDING_REGISTER_ADDRESS = (
    HOLDING_REGISTER_ADDRESS_BASE_RANGE + HOLDING_REGISTER_ACCESSED
) - HOLDING_REGISTER_ADDRESS_BASE_RANGE

HOLDING_REGISTER_VALUE = 0

# Create an instance of ModbusServer listening on all network interfaces on this machine.
modbus_slave = ModbusServer(args.HOST, args.PORT, no_block=True)


def modbus_slave_sim():
    print(f"Starting Modbus slave on {args.HOST}:{args.PORT}")
    modbus_slave.start()

    state_holding_register = [HOLDING_REGISTER_VALUE]
    modbus_slave.data_bank.set_holding_registers(
        HOLDING_REGISTER_ADDRESS, [HOLDING_REGISTER_VALUE]
    )
    print("Holding Registers set")
    print("Waiting Master request..")

    try:
        while True:
            current = modbus_slave.data_bank.get_holding_registers(
                HOLDING_REGISTER_ADDRESS
            )

            if state_holding_register != current and current is not None:
                state_holding_register = current
                print(
                    f"Holding register address {HOLDING_REGISTER_ADDRESS_BASE_RANGE} = "
                    + str(state_holding_register)
                )

            sleep(0.5)

    except KeyboardInterrupt:
        print("\n Shutting Down Modbus Slave (server) ...")

    finally:
        modbus_slave.stop()
        print("Modbus Slave (server) is offline")


if __name__ == "__main__":
    modbus_slave_sim()
