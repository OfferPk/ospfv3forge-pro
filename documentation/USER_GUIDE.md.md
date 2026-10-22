# OSPFv3Forge Pro v1.0.0 — User Guide & NetDevOps Manual

## 1\. Web Studio Quickstart

1. Open `source-code/index.html` in any modern web browser.  
2. Select an industry preset from the top bar:  
   - **Zero-Trust 5G IPv6 Core**: Pure IPv6 backbone with RFC 4552 IPsec AH (SHA-256), 100G auto-cost reference bandwidth, BFD sub-50ms, and LFA fast reroute (Grade A+).  
   - **Multi-AF Spine-Leaf Fabric**: Multi-Address Family IPv4/IPv6 using Instance IDs 0 & 64, Totally Stubby Area, IPsec ESP (AES-GCM), and Terabit reference bandwidth (Grade A).  
   - **Vulnerable Unhardened OSPFv3**: Unauthenticated OSPFv3, default 100 Mbps reference bandwidth, dead timer 40s, virtual-links, and missing passive-interface (Grade F).  
3. Review the **10-Point Zero-Trust Scorecard** to evaluate routing security posture and review automated remediation recommendations.  
4. Inspect the **High-Speed Interface Cost Metric Table**:  
   - Change the reference bandwidth to observe how legacy 100 Mbps collapses 1G to 400G interfaces to Cost 1, while 100 Gbps correctly differentiates links.  
5. Review the **RFC 5340 OSPFv3 / RFC 4552 IPsec Binary Dissector**:  
   - Inspect the 24-byte IPsec Authentication Header (AH) wrapping around the 40-byte OSPFv3 Hello packet with decoded fields.  
6. Export synthesized production configurations for **Cisco IOS-XE**, **Arista EOS**, **Juniper Junos**, **Linux FRR**, and **Prometheus**.

---

## 2\. DevSecOps CLI Tool (`ospfv3forge-cli.py`)

The standalone Python CLI runs on Python 3.8+ with zero third-party dependencies.

### 2.1 Encoding OSPFv3 Hello Packets with IPsec AH

python3 build/ospfv3forge-cli.py encode \\

  \--router-id 10.0.0.1 \\

  \--area-id 0.0.0.0 \\

  \--instance-id 0 \\

  \--ipsec \\

  \--spi 1000

### 2.2 Sizing Interface Cost Metrics

python3 build/ospfv3forge-cli.py costs \--ref-bw 100000

Output:

\=== OSPFv3 Interface Cost Matrix (Reference Bandwidth: 100,000 Mbps) \===

Interface Speed Bandwidth       Calculated Cost    Status

\-----------------------------------------------------------------

100 Mbps            100 Mbps        1000            DIFFERENTIATED (Accurate)

1 Gbps            1,000 Mbps         100            DIFFERENTIATED (Accurate)

10 Gbps          10,000 Mbps          10            DIFFERENTIATED (Accurate)

25 Gbps          25,000 Mbps           4            DIFFERENTIATED (Accurate)

40 Gbps          40,000 Mbps           2            DIFFERENTIATED (Accurate)

100 Gbps        100,000 Mbps           1            COLLAPSED TO 1 (Hazard)

400 Gbps        400,000 Mbps           1            COLLAPSED TO 1 (Hazard)

### 2.3 Running Zero-Trust CI/CD Audits

\# Validating production configuration (Exits code 0\)

python3 build/ospfv3forge-cli.py audit \-c build/presets/zero-trust-5g-ipv6-core.json \--strict

\# Validating vulnerable configuration (Exits code 1\)

python3 build/ospfv3forge-cli.py audit \-c build/presets/vulnerable-unhardened-ospfv3.json \--strict

---

## 3\. GitHub Actions CI/CD Pipeline Gate

Add this workflow to your NetDevOps repository (`.github/workflows/ospfv3-audit.yml`):

name: Zero-Trust OSPFv3 Architecture Gate

on:

  pull\_request:

    paths:

      \- 'routing/ospfv3/\*\*'

      \- 'configs/core/\*\*'

jobs:

  ospfv3-audit:

    runs-on: ubuntu-latest

    steps:

      \- name: Checkout Code

        uses: actions/checkout@v4

      \- name: Set up Python

        uses: actions/setup-python@v5

        with:

          python-version: '3.11'

      \- name: Run OSPFv3Forge Strict Audit Gate

        run: |

          python3 build/ospfv3forge-cli.py audit \-c build/presets/zero-trust-5g-ipv6-core.json \--strict