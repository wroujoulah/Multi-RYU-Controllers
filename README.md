# Multi-RYU Controllers for Software-Defined Networks

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OpenFlow](https://img.shields.io/badge/OpenFlow-1.3-blue.svg)](https://opennetworking.org/sdn-resources/openflow/)
[![Status](https://img.shields.io/badge/Status-Archived-red.svg)]()

⚠️ **Note: This project is no longer maintained** but remains available for educational purposes.

A comprehensive Software-Defined Networking (SDN) solution implementing multiple RYU controllers with different routing strategies and real-time network monitoring capabilities. This project was developed as a graduation project at FITE, focusing on efficient network traffic management and load balancing.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Architecture](#architecture)
- [Usage](#usage)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Overview

This project provides a suite of SDN controllers built on the RYU framework, each implementing different path selection and routing strategies. The system includes comprehensive network monitoring capabilities, making it suitable for research, educational purposes, and experimental network deployments.

### Key Benefits
- Multiple routing strategies to suit different network requirements
- Real-time network monitoring and statistics
- Flexible traffic management
- Load balancing capabilities
- Easy integration with OpenFlow-compatible switches

## Features

### Controller Implementation
| Controller | Description | Key Features |
|------------|-------------|--------------|
| Shortest Path | Basic shortest path routing | - Dijkstra's algorithm<br>- Single path routing<br>- Hop count based |
| Random Shortest Path | Load balancing through randomization | - Multiple path support<br>- Random path selection<br>- Flow timeout mechanism |
| Multi-Shortest Path | Equal-cost multipath routing | - Group table utilization<br>- Simultaneous path usage<br>- Advanced load balancing |
| Least Consumption Path | Resource-aware routing | - Link utilization monitoring<br>- Adaptive path selection<br>- Resource optimization |
| Least Consumption Multi-Shortest Path | Combined approach | - Dynamic weight assignment<br>- Resource awareness<br>- Multiple path support |

### Monitoring Components

#### Flow-Based Monitor (`network_monitor_flow.py`)
- Individual flow statistics tracking
- Per-flow bandwidth monitoring
- Port statistics collection
- Link state monitoring
- Performance metrics calculation

#### Group-Based Monitor (`network_monitor_group.py`)
- Group table statistics
- Aggregated traffic monitoring
- Port group associations
- Load distribution tracking
- Real-time utilization metrics

## System Requirements

### Hardware Requirements
- Compatible OpenFlow switches (physical or virtual)
- Minimum 2GB RAM for controller
- 1GB free disk space

### Software Requirements
```
- Python 2.7+
- RYU SDN Framework
- NetworkX library
- OpenFlow 1.3
- Mininet (for testing)
```

### Optional Requirements
- Wireshark (for packet analysis)
- Network graphing tools
- Performance monitoring tools

## Installation

1. Set up the Python environment:
```bash
# Create and activate virtual environment (recommended)
python -m venv sdn-env
source sdn-env/bin/activate  # Linux/Mac
# or
.\sdn-env\Scripts\activate   # Windows
```

2. Install required packages:
```bash
pip install ryu networkx eventlet
```

3. Clone and set up the project:
```bash
git clone https://github.com/wroujoulah/Multi-RYU-Controllers.git
cd Multi-RYU-Controllers
```

4. Verify installation:
```bash
ryu-manager --version
```

## Architecture

```plaintext
┌──────────────────────────────────────┐
│           RYU Controllers            │
├──────────────┬───────────┬──────────┤
│  Routing     │ Monitoring│  Network │
│  Strategies  │  Modules  │ Analysis │
└──────────┬───┴───────────┴────┬─────┘
           │                     │
           ▼                     ▼
┌──────────────────────────────────────┐
│            OpenFlow 1.3              │
└──────────────────┬──────────────────┘
                   │
┌──────────────────────────────────────┐
│        Network Infrastructure        │
└──────────────────────────────────────┘
```

## Usage

### Basic Controller Launch
```bash
# Flow-based monitoring
ryu-manager Shortest_Path_controller.py network_monitor_flow.py

# Group-based monitoring
ryu-manager Multi_Shortest_Path_controller.py network_monitor_group.py
```

### Advanced Usage Examples

1. Basic shortest path routing:
```bash
ryu-manager Shortest_Path_controller.py network_monitor_flow.py --verbose
```

2. Load-balanced routing:
```bash
ryu-manager Random_Shortest_Path_controller.py network_monitor_flow.py --observe-links
```

3. Resource-aware routing:
```bash
ryu-manager Least_Consumption_Path_controller.py network_monitor_group.py --enable-stats
```

## Documentation

### Controller Configuration
Each controller can be configured through the following parameters:
- Flow timeout values
- Path selection weights
- Monitoring intervals
- Statistics collection frequency

### Network Monitoring
The monitoring modules provide:
- Real-time traffic statistics
- Bandwidth utilization reports
- Port status information
- Link state monitoring
- Performance metrics

### Troubleshooting
Common issues and solutions:
1. Controller connection issues
   - Verify OpenFlow version compatibility
   - Check network connectivity
   - Ensure proper port configuration

2. Performance issues
   - Adjust monitoring intervals
   - Optimize flow table management
   - Check resource utilization

## Contributing

We welcome contributions to improve the project:

1. Fork the repository
2. Create a feature branch
3. Commit your changes with clear messages
4. Push to your branch
5. Create a Pull Request

### Coding Standards
- Follow PEP 8 guidelines
- Include docstrings for new functions
- Add unit tests for new features
- Update documentation as needed

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributors

- Abdulhadi Bitar
- Eyad Arnabeh
- Mhd Wissam Alroujoulah ([@wroujoulah](https://github.com/wroujoulah))

## Acknowledgments

- Project Supervisor: Dr. Eyad Al-Khayat
- FITE (Faculty of Information Technology Engineering)
- RYU SDN Framework Community
- NetworkX Development Team

---

## Project Status

This project is currently archived and no longer maintained. While the code remains available for educational and reference purposes, no active development or support is provided. Users are encouraged to fork the repository if they wish to extend or modify the functionality for their own use.

For questions about the project's historical development or academic context, please refer to the original documentation or contact the authors through the university.
