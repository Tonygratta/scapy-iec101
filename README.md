# scapy-iec101
Simple implementation of IEC 60870-5-101 using Scapy and pySerial

To run a sample simulated device:

> `python3 -m iec101_simple_device`

The script *iec101_simple_device.py* will try to open the serial port */dev/ttyS0* and awaits for a serial connection from a client. It uses the FT 1.2 Frame format as defined in the IEC 60870-5-101 standard to communicate with the ''controller,'' responding with a *0xe5* single-byte command. Every received frame is logged in a file named *iec101_{unix time in seconds}.log*
