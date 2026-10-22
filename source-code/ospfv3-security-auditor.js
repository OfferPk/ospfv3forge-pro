/**
 * OSPFv3Forge Pro - 10-Point Zero-Trust OSPFv3 Security & Resilience Auditor
 * Standards & References:
 * - RFC 5340: OSPF for IPv6
 * - RFC 5838: Support of Address Families in OSPFv3
 * - RFC 4552: Authentication/Confidentiality for OSPFv3 (IPsec)
 * - RFC 5880: Bidirectional Forwarding Detection (BFD)
 * - RFC 5286: Loop-Free Alternates (LFA) Fast Reroute
 * - RFC 6987: OSPF Stub Router Advertisement (Max-Metric)
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.OSPFv3SecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Run 10-Point Zero-Trust Audit on OSPFv3 Architecture
   * @param {Object} cfg - Configuration parameters
   * @returns {Object} Score, Grade, and Detailed Findings
   */
  function auditOSPFv3Architecture(cfg) {
    const findings = [];
    let totalScore = 0;

    // 1. IPsec Authentication & Confidentiality (RFC 4552)
    const ipsecActive = !!cfg.ipsecAuthEnabled;
    const ipsecMode = cfg.ipsecMode || 'AH_SHA256'; // AH_SHA256, ESP_GCM
    let authScore = 0;
    let authStatus = 'FAIL';
    let authDesc = '';

    if (ipsecActive && ipsecMode === 'ESP_GCM') {
      authScore = 12;
      authStatus = 'PASS';
      authDesc = 'Zero-Trust Standard: IPsec ESP (AES-GCM) active. Provides both cryptographic authentication and full payload confidentiality across links.';
    } else if (ipsecActive) {
      authScore = 10;
      authStatus = 'PASS';
      authDesc = 'RFC 4552 IPsec AH (SHA-256) active. Cryptographic integrity and anti-replay protection verified on all OSPFv3 packets.';
    } else {
      authScore = 0;
      authStatus = 'CRITICAL';
      authDesc = 'CRITICAL DEFECT: Unauthenticated OSPFv3! RFC 5340 removed native passwords; unauthenticated adjacencies allow any rogue endpoint to inject malicious LSAs (MITM routing takeover).';
    }
    findings.push({
      id: 'IPSEC_AUTHENTICATION',
      name: 'IPsec Cryptographic Authentication & Integrity (RFC 4552)',
      score: authScore,
      maxScore: 12,
      status: authStatus,
      description: authDesc,
      remediation: authScore < 10 ? 'Configure IPsec AH or ESP ("ospfv3 authentication ipsec spi <ID> sha256 <KEY>") on all inter-router links.' : null
    });
    totalScore += authScore;

    // 2. Passive-Interface Default on Access Links
    const passiveDefault = !!cfg.passiveInterfaceDefault;
    let passScore = 0;
    let passStatus = 'PASS';
    let passDesc = '';

    if (passiveDefault) {
      passScore = 12;
      passStatus = 'PASS';
      passDesc = '"passive-interface default" enforced. OSPFv3 Hellos and LSAs are suppressed on all host-facing VLANs, preventing rogue adjacency formation.';
    } else {
      passScore = 0;
      passStatus = 'CRITICAL';
      passDesc = 'FAIL: Explicit passive-interface default is missing! OSPFv3 Hellos are transmitted onto client access ports, exposing internal network topology.';
    }
    findings.push({
      id: 'PASSIVE_INTERFACE_DEFAULT',
      name: 'Passive-Interface Default & Access Port Isolation',
      score: passScore,
      maxScore: 12,
      status: passStatus,
      description: passDesc,
      remediation: passScore < 12 ? 'Apply "passive-interface default" in OSPFv3 process, and explicitly enable only trunk/inter-router links.' : null
    });
    totalScore += passScore;

    // 3. High-Speed Reference Bandwidth Calibration
    const refBwMbps = parseInt(cfg.refBandwidthMbps, 10) || 100;
    let refScore = 0;
    let refStatus = 'PASS';
    let refDesc = '';

    if (refBwMbps >= 1000000) {
      refScore = 10;
      refStatus = 'PASS';
      refDesc = `Terabit Reference Bandwidth (${refBwMbps} Mbps / ${(refBwMbps / 1000000).toFixed(1)} Tbps). Differentiates 10G, 25G, 100G, and 400G core links with accurate metrics.`;
    } else if (refBwMbps >= 100000) {
      refScore = 8;
      refStatus = 'PASS';
      refDesc = `100G Reference Bandwidth (${refBwMbps} Mbps). Differentiates links up to 100G, but 400G links will tie at cost 1.`;
    } else {
      refScore = 2;
      refStatus = 'CRITICAL';
      refDesc = `CRITICAL HAZARD: Default 100 Mbps reference bandwidth! 1G, 10G, 100G, and 400G interfaces all collapse to Cost 1, causing severe traffic polarization and link saturation.`;
    }
    findings.push({
      id: 'REFERENCE_BANDWIDTH',
      name: 'High-Speed Auto-Cost Reference Bandwidth Sizing',
      score: refScore,
      maxScore: 10,
      status: refStatus,
      description: refDesc,
      remediation: refScore < 8 ? 'Set "auto-cost reference-bandwidth 100000" (or 4000000 for 400G backbones) across all routers.' : null
    });
    totalScore += refScore;

    // 4. Sub-Second BFD Fast Convergence (RFC 5880)
    const bfdActive = !!cfg.bfdEnabled;
    let bfdScore = 0;
    let bfdStatus = 'PASS';
    let bfdDesc = '';

    if (bfdActive) {
      bfdScore = 10;
      bfdStatus = 'PASS';
      bfdDesc = 'Bidirectional Forwarding Detection (BFD) enabled for OSPFv3. Sub-50ms link failure detection triggers instant SPF recalculation.';
    } else {
      bfdScore = 0;
      bfdStatus = 'FAIL';
      bfdDesc = 'FAIL: OSPFv3 relies on default 40-second Dead Intervals. Physical link or optic degradation causes prolonged 40s traffic blackouts.';
    }
    findings.push({
      id: 'BFD_CONVERGENCE',
      name: 'Sub-Second BFD Fast Convergence (RFC 5880)',
      score: bfdScore,
      maxScore: 10,
      status: bfdStatus,
      description: bfdDesc,
      remediation: bfdScore < 10 ? 'Enable "ospfv3 bfd" on all core backbone and interconnect interfaces.' : null
    });
    totalScore += bfdScore;

    // 5. Loop-Free Alternate (LFA) Fast Reroute (RFC 5286)
    const lfaActive = !!cfg.lfaEnabled;
    let lfaScore = 0;
    let lfaStatus = 'PASS';
    let lfaDesc = '';

    if (lfaActive) {
      lfaScore = 10;
      lfaStatus = 'PASS';
      lfaDesc = 'IP Fast Reroute (LFA / Remote-LFA) active. Pre-computed backup next-hops enable sub-50ms traffic restoration without waiting for global SPF.';
    } else {
      lfaScore = 3;
      lfaStatus = 'WARN';
      lfaDesc = 'LFA Fast Reroute is disabled. Network must wait for full SPF computation and FIB download upon topology changes (100ms–2s delay).';
    }
    findings.push({
      id: 'LFA_FAST_REROUTE',
      name: 'Loop-Free Alternate (LFA) Fast Reroute (RFC 5286)',
      score: lfaScore,
      maxScore: 10,
      status: lfaStatus,
      description: lfaDesc,
      remediation: lfaScore < 10 ? 'Enable "fast-reroute per-prefix" (or Junos equivalent) on core routing processes.' : null
    });
    totalScore += lfaScore;

    // 6. Area 0 Backbone Continuity & Virtual-Link Defense
    const areaDesign = cfg.areaType || 'NORMAL'; // NORMAL, STUB, TOTALLY_STUBBY, NSSA
    const virtualLinks = !!cfg.hasVirtualLinks;
    let areaScore = 0;
    let areaStatus = 'PASS';
    let areaDesc = '';

    if (!virtualLinks && (areaDesign === 'TOTALLY_STUBBY' || areaDesign === 'NSSA')) {
      areaScore = 10;
      areaStatus = 'PASS';
      areaDesc = `Optimized ${areaDesign} area architecture. LSDB size clamped by replacing Type 3/4/5 LSAs with default routes; contiguous Area 0 backbone.`;
    } else if (!virtualLinks) {
      areaScore = 8;
      areaStatus = 'PASS';
      areaDesc = 'Contiguous Area 0 backbone with normal multi-area design. No fragile virtual-links detected.';
    } else {
      areaScore = 0;
      areaStatus = 'CRITICAL';
      areaDesc = 'CRITICAL FRAGILITY: OSPF Virtual-Links in use! Discontinuous Area 0 backbones rely on tunneled adjacencies prone to routing loops and MTU blackholing.';
    }
    findings.push({
      id: 'AREA_BACKBONE_INTEGRITY',
      name: 'Area 0 Backbone Continuity & Virtual-Link Elimination',
      score: areaScore,
      maxScore: 10,
      status: areaStatus,
      description: areaDesc,
      remediation: areaScore < 8 ? 'Redesign physical or GRE/MPLS underlay topology to eliminate all OSPF virtual-links.' : null
    });
    totalScore += areaScore;

    // 7. IPv6 Link-Local Peering Hygiene (RFC 5340)
    const linkLocalConfigured = cfg.linkLocalDeterministic !== false;
    let llScore = 0;
    let llStatus = 'PASS';
    let llDesc = '';

    if (linkLocalConfigured) {
      llScore = 10;
      llStatus = 'PASS';
      llDesc = 'Deterministic Link-Local addresses (e.g. fe80::1) assigned per interface. Eliminates EUI-64 MAC churn and troubleshooting ambiguity.';
    } else {
      llScore = 4;
      llStatus = 'WARN';
      llDesc = 'Random SLAAC/EUI-64 link-local addresses used. Troubleshooting traceroutes and next-hop reachability is prone to human error.';
    }
    findings.push({
      id: 'LINK_LOCAL_HYGIENE',
      name: 'IPv6 Link-Local Peering Hygiene & Addressing (RFC 5340)',
      score: llScore,
      maxScore: 10,
      status: llStatus,
      description: llDesc,
      remediation: llScore < 10 ? 'Assign explicit, predictable link-local addresses ("ipv6 address fe80::1 link-local") on core links.' : null
    });
    totalScore += llScore;

    // 8. Multi-Address Family (Multi-AF) Isolation (RFC 5838)
    const multiAf = !!cfg.multiAddressFamily;
    const instanceIsolation = cfg.instanceIsolation !== false;
    let afScore = 0;
    let afStatus = 'PASS';
    let afDesc = '';

    if (multiAf && instanceIsolation) {
      afScore = 10;
      afStatus = 'PASS';
      afDesc = 'RFC 5838 Multi-AF active. IPv4 and IPv6 routing instances run on separate Instance IDs (0 for IPv6, 64 for IPv4) with strict LSDB separation.';
    } else if (multiAf) {
      afScore = 5;
      afStatus = 'WARN';
      afDesc = 'Multi-AF enabled, but instance IDs are overlapping or ambiguous across address families.';
    } else {
      afScore = 8;
      afStatus = 'PASS';
      afDesc = 'Pure IPv6 OSPFv3 architecture. Dedicated routing protocol plane with zero cross-family leakage.';
    }
    findings.push({
      id: 'MULTI_AF_ISOLATION',
      name: 'Multi-Address Family (Multi-AF) Instance Isolation (RFC 5838)',
      score: afScore,
      maxScore: 10,
      status: afStatus,
      description: afDesc,
      remediation: afScore < 8 ? 'Use standardized instance ID blocks (0-31 for IPv6, 64-95 for IPv4) per RFC 5838.' : null
    });
    totalScore += afScore;

    // 9. Control Plane Policing (CoPP) for Protocol 89
    const coppActive = !!cfg.coppEnabled;
    let coppScore = 0;
    let coppStatus = 'PASS';
    let coppDesc = '';

    if (coppActive) {
      coppScore = 9;
      coppStatus = 'PASS';
      coppDesc = 'Control Plane Policing (CoPP) actively rate-limits IP Protocol 89 (OSPF). Protects supervisor CPU against Hello flooding and LSA storms.';
    } else {
      coppScore = 0;
      coppStatus = 'FAIL';
      coppDesc = 'FAIL: No CoPP protection for OSPF Protocol 89. Malicious endpoints can flood multicast ff02::5 to exhaust router CPU.';
    }
    findings.push({
      id: 'COPP_RATE_LIMITING',
      name: 'Control Plane Policing (CoPP) for IP Protocol 89',
      score: coppScore,
      maxScore: 9,
      status: coppStatus,
      description: coppDesc,
      remediation: coppScore < 9 ? 'Classify Protocol 89 in CoPP and apply hardware policer (e.g. 2000 pps).' : null
    });
    totalScore += coppScore;

    // 10. Max-Metric Router LSA on Reload (RFC 6987)
    const maxMetric = !!cfg.maxMetricOnStartup;
    let mmScore = 0;
    let mmStatus = 'PASS';
    let mmDesc = '';

    if (maxMetric) {
      mmScore = 7;
      mmStatus = 'PASS';
      mmDesc = 'RFC 6987 Max-Metric Router LSA active on reload. Delays transit traffic until BGP converges and routing tables settle.';
    } else {
      mmScore = 2;
      mmStatus = 'WARN';
      mmDesc = 'Max-metric on reload unconfigured. Router will attract transit traffic immediately upon boot before BGP has finished converging.';
    }
    findings.push({
      id: 'MAX_METRIC_ROUTER_LSA',
      name: 'Max-Metric Router LSA on Startup (RFC 6987)',
      score: mmScore,
      maxScore: 7,
      status: mmStatus,
      description: mmDesc,
      remediation: mmScore < 7 ? 'Configure "max-metric router-lsa on-startup 600" to prevent post-reboot traffic blackholing.' : null
    });
    totalScore += mmScore;

    // Compute Overall Grade
    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 90) grade = 'A';
    else if (totalScore >= 80) grade = 'B';
    else if (totalScore >= 70) grade = 'C';
    else if (totalScore >= 60) grade = 'D';

    return {
      totalScore,
      maxScore: 100,
      percentage: totalScore,
      grade,
      passed: totalScore >= 80,
      summary: `OSPFv3 Architecture Security Rating: ${grade} (${totalScore}/100 points). ${totalScore >= 80 ? 'Production Ready.' : 'Remediation Required.'}`,
      findings
    };
  }

  return {
    auditOSPFv3Architecture
  };
}));
