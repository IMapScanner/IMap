# IMap

## Overview
We identify the challenges that current network scanners meet, and propose IMap, a fast and scalable in-network scanner with programmable switches. 

IMap includes a probe packet generation module, which is responsible to generate high-speed probe packets with random address and adaptive rate, and a response packet processing module, which processes the response packets in a correct and efficient manner.

To use IMap, operators should first specify the scanning address spaces and scanning port ranges beforehand. Then IMap control plane programs parse these configurations and issue the parsed parameters into the IMap packet processing logics. After that, IMap data plane programs generate high-speed probe packets and process the corresponding response packets accordingly. Finally, the scanning results, i.e., the information extracted from the response packets, are written into a persistent database, such as the Redis in-memory data store employed in this repo. The whole workflow of IMap is displayed as follow.

<div align=center>
<img src="https://raw.githubusercontent.com/IMapScanner/IMap/master/IMap-workflow.png" width="60%" height="60%">
</div>

## Repository Structure
`src`: The source code of IMap
- `src/iconfig.h`: The usual configurations of IMap
- `src/server`: The source code of backend agent running on the storage server
- `src/switch`: The source code of IMap switch part including control plane and data plane
    - `src/switch/p4src`: The source code of IMap's data plane
    - `src/switch/*.h, *.c`: The source code of IMap's control plane


## Installation
### Deploy on the server with DPDK NIC
```sh
# 0. Prepare the environment for compiling
# Install the stable version of DPDK (we use dpdk-stable-20.11.1) and bind the
# NIC connected to the switch with DPDK driver
# 1. Install and start Redis
sudo apt update && sudo apt install redis-server
sudo systemctl start redis
# 2. Download the source code of IMap
git clone https://github.com/IMapScanner/IMap
# 3. Compile IMap
cd IMap
make server
```
### Deploy on the Barefoot Tofino switch
```sh
# 0. Prepare the environment for compiling
# Set the environment variable $SDE and $SDE_INSTALL, and download
# the p4_build.sh from Barefoot and put it into $SDE.
# 1. Download the source code of IMap
git clone https://github.com/IMapScanner/IMap
# 2. Configure and compile IMap
cd IMap 
# Then modify src/iconfig.h according to your configuration and specify
# the scanning address spaces and scanning port ranges in src/switch/imap.c
make switch
```

## Start the IMap scanner
### Start the IMap result server on the server
```sh
sudo ./imap-result-server -l 0-7 -n 8 -- -p 1
```
### Start the IMap scanner on the switch
```sh
./imap --probe-port-range 1:65535 --ip-list ip.txt --rate 55000000
```
