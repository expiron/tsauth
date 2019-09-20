# TsinghuaAuth
[![License](https://img.shields.io/badge/License-GPL--3.0-brightgreen.svg?style=flat-square)](https://opensource.org/licenses/GPL-3.0)
[![Build Status](https://img.shields.io/azure-devops/build/expiron/8113b02a-1bac-4bcd-8931-dae889949b7a/32/master?style=flat-square&label=Azure%20Pipelines&logo=azure-pipelines)](https://dev.azure.com/expiron/TsinghuaAuth/_build/latest?definitionId=32&branchName=master)

A tiny client for Tsinghua network AAA (Authentication, Authorization, Accounting) system.
# Build and Install
- ## Ubuntu 18.04
1. Install dependencies
```bash
sudo apt-get update
sudo apt-get install build-essential cmake
sudo apt-get install libmbedtls-dev libcurl4-openssl-dev libjson-c-dev
```
2. Clone sources
```bash
git clone https://github.com/expiron/tsauth.git
```
3. Build
```bash
mkdir -p tsauth/build && cd tsauth/build
cmake ..
make -j 1 V=sc
```
4. Install to `/usr/local/bin`
```bash
sudo make install
```
5. Enjoy it
```bash
tsauth --help
```
# Usage
```
TsinghuaAuth v0.3.5

    A tiny client for Tsinghua network AAA system

Usage:
    tsauth [OPTIONS] --status
    tsauth [OPTIONS] [--login] [-d <IP>] -u <username> -p <password>
    tsauth [OPTIONS] --logout [-d <IP>] -u <username>

Options:
    -4, --ipv4                     Authorize IPv4 network only
    -6, --ipv6                     Authorize IPv6 network only
    -d, --addr <IP address>        Specify the IP address to authorize
        --http                     Use HTTP for requests instead of HTTPS
        --inside                   Authorize campus internal network only
    -i, --login                    Perform login operation (default)
    -o, --logout                   Perform logout operation
    -u, --username <username>      Tsinghua username or ID number
    -p, --password <plaintext>     Password in plaintext
    -s, --status                   Show current status
    -t, --timeout <seconds>        Timeout of each request (default: 1)
    -v, --verbose                  Show detailed information
    -h, -?, --help                 Show usage and quit
        --version                  Show version string and quit
```
## Examples
- Authentication for current device
```bash
tsauth [--login] -u username -p password
```
- Authentication only for campus internal network
```bash
tsauth -u username -p password --inside
```
- Authentication only for IPv6(IPv4)
```bash
tsauth -u username -p password --ipv6(--ipv4)
```
- Authentication for specified IP address
```bash
tsauth -d ip -u username -p password
```
- Logout
```bash
tsauth -ou username
```
- Logout for specified IP address
```bash
tsauth -ou username -d ip
```
- Show current logon status
```bash
tsauth --status
```
# Limitation
- `--ipv4`, `--ipv6` options don't work when `-d` option is specified. Only the IP address specified will be sent to auth server. `tsauth` can't find any IPv4(v6) address associates with the specified address.
But when specifies `--ipv4` and `--ipv6` at the same time, the IP address specified will be authenticated in double-stack mode.
- `tsauth` doesn't work in the networks using `net.tsinghua.edu.cn` for authentication. As `net.tsinghua.edu.cn` will be deprecated in the future, `tsauth` doesn't implement this feature.
