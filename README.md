# Web Baseline Analyzer (User Manual)

Web Baseline Analyzer aims to audit Apache 2.4 servers on Ubuntu 20.04 systems, and remediate the issues found if the remedy option is enabled. 

## Table Of Contents

- [Web Baseline Analyzer (User Manual)](#web-baseline-analyzer-user-manual)
  * [Table Of Contents](#table-of-contents)
  * [Description](#description)
  * [Getting Started](#getting-started)
    + [Dependencies](#dependencies)
    + [Requirements](#requirements)
    + [Executing program](#executing-program)
  * [Tips](#tips)
  * [Authors](#authors)

## Description

Auditing and remediation will be done based on the CIS Apache HTTP Server 2.4 Benchmark. As the benchmark is based on Red Hat Linux, the tool will use the Ubuntu equivalent of some of the commands found in the benchmark.

Every section in the benchmark will be covered. To reduce complexity, the user can choose which section to cover, instead of going through all sections at once. More details will be covered in the sub-section [Executing program](#executing-program).

## Getting Started

### Dependencies

- Ubuntu 20.04
- Apache 2.4
- Python 3

### Requirements

- Internet connection (for installing missing packages if required)
- Root permissions

### Executing program

1. Become root
```
sudo bash
```
2. Run the script without additional arguments to audit the local system and check for issues.
```
python3 Baseline-Analyzer.py
```

3. Run the script with the `-r` argument to remediate the issues found.

```
python3 Baseline-Analyzer.py -r
```

4. To choose a section to cover, simply enter the number required (i.e Section 1 requires the number 1). This reduces complexity and helps users to focus on one section at a time, instead of going through all 12 sections at once and getting lost in the process.

## Tips

- Always run the script first to identify issues, before running with the `-r` option.
- SELinux is made for Red Had Linux and other derivatives, and setting it to enforcing mode can cause stability issues. If possible, use AppArmor instead.

## Authors

- Ng Wei Liang

- Ooi Chee Han

- Justin Soh

- Aqil Ahmad Subahan
