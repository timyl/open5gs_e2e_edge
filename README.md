# Open5GS E2E edge UPF

## Overview

A customized Open5GS 2.7.2 implementation for private end-to-end testing and vendor NF compatibility validation. the project needs to be run together with open5gs_e2e_core project

## Description of what this customization does

- **Enhancement UPF for GBR QoS flow controlling**: please refer to release note


## Testing Scenarios 

- PDU session establishment procedures
- Non-GBR and GBR QoS flow validation
- DNN-based routing and network slice selection
- Location-based signaling and tracking area management
- Basic MEC workflow integration (Edge UPF project involved for QoS management)

## Installation

Based on Open5GS 2.7.2. Follow the standard Open5GS compilation and installation process:

```bash
git clone https://github.com/timyl/open5gs_e2e_edge.git
cd open5gs_e2e_edge
```

Refer to [official Open5GS documentation](https://open5gs.org/open5gs/docs/) for detailed build instructions.

## Related Projects

- **open5gs_e2e_core**: 5G core functionality for distributed MEC scenarios

## License

GNU Affero General Public License v3.0 (GNU AGPL v3.0)
