# NFCGate Server
This is the NFCGate server application using Python 3 and the Google [Protobuf](https://github.com/google/protobuf/) library, version 3.

To run, simply start the server using `python server.py`. You can then connect to the server using the IP address of your device and the default port of 5566.  
The server features a plugin system for data filtering. When starting the server, you can specify a list of plugins to be loaded as parameters, e.g. `python server.py log`. For an example, see the shipped `mod_log.py` plugin.

## Security

To achieve the lowest possible latency when relaying, the server application expects to be run in an isolated environment, where only authorized devices can connect.
That is why no authentication exists on the server side by default. DO NOT run the server on a public network or over the internet.
For confidentiality (not authentication!) use TLS via the `--tls_cert` and `--tls_key` options.

## Supported Setups

For the standard setup, we ran the server on a trusted laptop and connected both devices via WiFi AP to the laptop.
In order to minimize the latency between the devices, we have successfully connected two nearby devices via Bluetooth tethering or WiFi hotspot, hosting the server application via Termux on the hotspot device.
