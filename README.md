# IMap
In-Network Mapper (Scanner)

## Overview

## Repository Structure

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
git clone https://github.com/EricDracula/IMap
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
git clone https://github.com/EricDracula/IMap
# 2. Configure and compile IMap
cd IMap # Then modify src/iconfig.h according to your configuration
make switch
```

## Start the IMap scanner
### Start the IMap result server on the server
```sh
sudo ./imap-result-server -l 0-7 -n 8 -- -p 1
```
### Start the IMap scanner on the switch
```sh
./imap --probe-port-range 0:65535 --rate 45000000
```
