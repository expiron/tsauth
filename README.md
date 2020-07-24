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
TsinghuaAuth v0.4.4

    A tiny client for Tsinghua network AAA system

Usage:
    tsauth [OPTIONS] [--login] [-d <IP>] -u <username> -p <password>
    tsauth [OPTIONS] --logout [-d <IP>] -u <username>

Options:
    -d, --addr <IP address>        Specify the IP address to authorize
        --http                     Use HTTP for requests instead of HTTPS
        --inside                   Authorize campus internal network only
    -i, --login                    Perform login operation (default)
    -o, --logout                   Perform logout operation
    -u, --username <username>      Tsinghua username or ID number
    -p, --password <plaintext>     Password in plaintext
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
# Limitation
- It seems that all the IPs will be authenticated in double-stack mode.
`--ipv4`, `--ipv6` options are deprecated.
- `tsauth` doesn't work in the networks using `net.tsinghua.edu.cn` for authentication. As `net.tsinghua.edu.cn` will be deprecated in the future, `tsauth` doesn't implement this feature.
