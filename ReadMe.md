
## Requirements

- **Python Version**: 3.11
- **Hardware Device**: nRF52840 Dongle
- **Operating System**: Linux (Ubuntu/Debian recommended)

## Quick Start

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Flash Firmware to nRF52840 Dongle

Flash the firmware files from the `Firmware` directory to the nRF52840 Dongle:

```bash
# Use nrfjprog or other tools to flash firmware
# firmware.hex - Main firmware
# s140_nrf52_6.1.1_softdevice.hex - SoftDevice firmware
```

**Note**: Make sure to flash the SoftDevice first, then flash the main firmware.

### 3. Configure Test Parameters

Modify the corresponding configuration file according to your test device:

- **ST Device**: `Config/ST/config.py`
- **NRF Device**: `Config/NRF/config.py` (if exists)
- **Zerphy Device**: `Config/Zerphy/config.py` (if exists)

Main configuration items include:
- `port_name`: Serial port device path (e.g., `/dev/ttyACM0`)
- `unprovisioned_device_address`: MAC address of the device under test
- `key_path`: Key file path
- Other device-related parameters

### 4. Run Test Cases

```bash
# ST device test cases
python Test_Case/ST/pubkey_point_random.py

# NRF device test cases
python Test_Case/NRF/18.confirmation_state_desync.py
```

## Project Structure

```
BLE_Mesh/
├── Config/                 # Configuration files directory
│   ├── ST/                # ST device configuration
│   ├── NRF/               # NRF device configuration
│   └── Zerphy/            # Zerphy device configuration
├── Firmware/              # nRF52840 Dongle firmware
│   ├── firmware.hex
│   └── s140_nrf52_6.1.1_softdevice.hex
├── Test_Case/             # Test cases directory
│   ├── ST/                # ST device test cases
│   └── NRF/               # NRF device test cases
├── Send_Packet/           # Packet construction and sending module
├── libs/                  # Third-party libraries and tools
├── Result/                # Test results output directory
└── requirements.txt       # Python dependencies list
```

## Test Cases Description

### ST Device Test Cases

- `pubkey_point_random.py`: Public key point validation attack test, testing device's handling capability for invalid public keys

### NRF Device Test Cases

- `18.confirmation_state_desync.py`: Confirmation state synchronization attack test

## Configuration

Each device's configuration file contains the following main parameters:

```python
device = {
    "port_name": "/dev/ttyACM0",              # Serial port device path
    "unprovisioned_device_address": "...",     # Target device MAC address
    "key_path": "...",                         # Key file path
    "logs_pcap": True,                         # Whether to log pcap files
    "pcap_filename": "...",                    # Pcap file path
    # ... other parameters
}
```

## Troubleshooting

### 1. Serial Port Permission Issues

If you encounter serial port permission errors, add the user to the dialout group:

```bash
sudo usermod -a -G dialout $USER
# Then log out and log back in
```

### 2. Device Not Found

- Verify that the nRF52840 Dongle is properly connected
- Check if the `port_name` configuration is correct
- Use `ls /dev/ttyACM*` to view available serial ports

### 3. Import Errors

Make sure to run test scripts from the project root directory, or set the Python path correctly.

## Development Guidelines

- Test cases should be placed in the corresponding device subdirectory under `Test_Case/`
- When adding new device configurations, create corresponding configuration files in the `Config/` directory
- Packet construction logic is in the `Send_Packet/` directory


