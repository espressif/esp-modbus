# Serial master teardown tests

Build for an ESP32 and run in ESP32 QEMU or on a board. The tests run automatically at boot and use UART 1 without external wiring. A synthetic receive event goes through the real UART worker and a held callback runs on the real ESP Timer task. Each test checks that deletion times out with the driver still owned, and succeeds after the held producer is released. The timer test is skipped if the SDK lacks the blocking ESP Timer stop API.
