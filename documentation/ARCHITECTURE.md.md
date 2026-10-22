# OSPFv3Forge Pro v1.0.0 — Architecture & Engineering Manual

## 1\. Executive Summary: The Evolution from OSPFv2 to OSPFv3

Open Shortest Path First (OSPF) is the primary Interior Gateway Protocol (IGP) powering enterprise backbones, service provider transport rings, and datacenter underlays. While OSPFv2 (RFC 2328\) was architected strictly for IPv4, the Internet Engineering Task Force (IETF) standardized **OSPFv3 in RFC 5340** to deliver native routing for IPv6.

OSPFv3 is not merely OSPFv2 with 128-bit addresses; it represents a fundamental architectural redesign:

1. **Per-Link Operation (vs. Per-Subnet)**: OSPFv3 runs on the link (broadcast domain or point-to-point circuit) rather than the IP subnet. Routers on the same physical link can run different subnets and still form neighbors.  
2. **Neighbor Adjacencies Over IPv6 Link-Local (`fe80::/10`)**: All OSPFv3 protocol packets (except Virtual-Links) are addressed to and sourced from IPv6 link-local addresses. Next-hops in the routing table point to link-local addresses rather than global unicast addresses.  
3. **Separation of Topology from Addressing**: In OSPFv2, Router (Type 1\) and Network (Type 2\) LSAs carried both topology information and IPv4 prefix subnets. In OSPFv3, Type 1 and Type 2 LSAs carry *only topological link-state graphs with zero prefix data*. Network addresses are decoupled into new LSA types:  
   - **Type 8 (Link-LSA)**: Flooded link-locally; carries the router's link-local address and list of IPv6 prefixes on that link.  
   - **Type 9 (Intra-Area-Prefix-LSA)**: Flooded area-wide; associates prefixes with the corresponding Router or Network LSA.  
4. **Multi-Address Family Support (RFC 5838\)**: OSPFv3 multiplexes both IPv6 and IPv4 unicast routing over the same transport by leveraging 8-bit Instance IDs (0-31 for IPv6, 64-95 for IPv4).

---

## 2\. The Great Authentication Pivot: RFC 4552 IPsec

In OSPFv2, routers authenticate neighbors using fields embedded directly in the OSPF packet header (Auth Type and 64-bit Auth Data/Cryptographic Sequence Number).

**In OSPFv3, the IETF completely removed all authentication fields from the protocol header.** RFC 5340 mandates that authentication and confidentiality must be provided externally at the network layer using **IPsec Authentication Header (AH) or Encapsulating Security Payload (ESP)** per **RFC 4552**.

\+------------------------------------+

| IPv6 Header (Next Header \= 51/AH)   |

\+------------------------------------+

| IPsec AH Header (Next Header \= 89\) |  \<-- RFC 4552 Cryptographic Integrity

| SPI (32-bit), Seq (32-bit), ICV    |

\+------------------------------------+

| OSPFv3 Header (Type, Length, RID)  |  \<-- RFC 5340 Routing Payload

| Hello / DBD / LSR / LSU / LSAck    |

\+------------------------------------+

### The Security Threat of Unauthenticated OSPFv3

Because configuring manual IPsec Security Associations (SAs) across disparate multi-vendor routers is complex, many organizations deploy OSPFv3 unauthenticated. This exposes the entire enterprise core to **rogue router injection**:

- Any host or VM on an access VLAN can send an unauthenticated OSPFv3 Hello, form a full adjacency with the distribution switch, and inject poisoned Intra-Area-Prefix LSAs, hijacking or blackholing corporate traffic.  
- OSPFv3Forge Pro enforces RFC 4552 IPsec AH/ESP and "passive-interface default" to eliminate this attack surface.

---

## 3\. High-Speed Auto-Cost Reference Bandwidth Sizing

The OSPF cost metric is defined as: \$\$\\text{Cost} \= \\max\\left(1, \\left\\lfloor \\frac{\\text{Reference Bandwidth}}{\\text{Interface Bandwidth}} \\right\\rfloor\\right)\$\$

In legacy implementations, the default reference bandwidth is \$100\\text{ Mbps}\$ (\$10^8\\text{ bps}\$). On modern networks:

- \$100\\text{ Mbps} \\rightarrow \\text{Cost } 1\$  
- \$1\\text{ Gbps} \\rightarrow \\text{Cost } 1\$ *(Truncated\!)*  
- \$10\\text{ Gbps} \\rightarrow \\text{Cost } 1\$ *(Truncated\!)*  
- \$100\\text{ Gbps} \\rightarrow \\text{Cost } 1\$ *(Truncated\!)*  
- \$400\\text{ Gbps} \\rightarrow \\text{Cost } 1\$ *(Truncated\!)*

**The Traffic Polarization Hazard**: If a 1G link and a 400G link both have Cost 1, OSPF performs equal-cost multipath (ECMP) load balancing across them 50/50, catastrophically saturating the 1G link while the 400G link sits at 0.25% utilization\!

OSPFv3Forge Pro sizes reference bandwidth to at least **\$100\\text{ Gbps}\$** (\$100,000\\text{ Mbps}\$) or **\$4\\text{ Tbps}\$** (\$4,000,000\\text{ Mbps}\$): \$\$\\text{Cost}*{400G} \= 10, \\quad \\text{Cost}*{100G} \= 40, \\quad \\text{Cost}*{10G} \= 400, \\quad \\text{Cost}*{1G} \= 4000\$\$

---

## 4\. Sub-Second Convergence: BFD & Loop-Free Alternates (LFA)

1. **Bidirectional Forwarding Detection (RFC 5880\)**: Default OSPFv3 Dead Intervals (40 seconds) cause extensive voice/video/data dropped sessions during physical link cuts. BFD negotiates 50ms heartbeat timers, detecting link failure in \$\< 150\\text{ ms}\$ and triggering instant local SPF recalculation.  
2. **Loop-Free Alternates (RFC 5286\)**: Standard OSPF recalculates SPF globally upon topology change (\$100\\text{ ms} \- 2\\text{ s}\$). LFA pre-computes an alternate loop-free backup path in the FIB before failure occurs: \$\$D(N, D) \< D(N, S) \+ D(S, D)\$\$ Traffic fails over to the backup link in \$\< 50\\text{ ms}\$.

---

## 5\. 10-Point Zero-Trust OSPFv3 Audit Rubric

1. **RFC 4552 IPsec Authentication (12 pts)**: Enforce AH SHA-256 or ESP AES-GCM.  
2. **Passive-Interface Default (12 pts)**: Suppress Hellos on all client/access ports.  
3. **Reference Bandwidth Sizing (10 pts)**: Prevent 100M/1G/10G/100G cost collapsing.  
4. **Sub-Second BFD Convergence (10 pts)**: Sub-50ms peer failure detection.  
5. **Loop-Free Alternate (LFA) FRR (10 pts)**: Pre-computed sub-50ms repair paths.  
6. **Area 0 Backbone Continuity (10 pts)**: Contiguous Area 0 without fragile virtual-links.  
7. **IPv6 Link-Local Hygiene (10 pts)**: Predictable `fe80::` addressing without EUI-64 churn.  
8. **Multi-AF Instance Isolation (10 pts)**: Isolated Instance IDs (0 for IPv6, 64 for IPv4).  
9. **Control Plane Policing (CoPP) (9 pts)**: Hardware rate-limiting for IP Protocol 89\.  
10. **Max-Metric Router LSA on Reload (7 pts)**: Delay transit traffic until BGP settles.