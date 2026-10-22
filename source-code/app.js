/**
 * OSPFv3Forge Pro - Web Application Controller
 */

(function () {
  'use strict';

  // Industry Presets
  const PRESETS = {
    core5g: {
      name: 'Zero-Trust 5G IPv6 Core (Cisco/Arista)',
      routerId: '10.0.0.1',
      processId: 1,
      areaId: '0.0.0.0',
      areaType: 'NORMAL',
      coreInterface: 'TenGigabitEthernet0/0/1',
      accessVlan: 100,
      refBandwidthMbps: 100000, // 100G RefBW
      instanceId: 0,
      ipsecAuthEnabled: true,
      ipsecMode: 'AH_SHA256',
      ipsecSpi: 1000,
      passiveInterfaceDefault: true,
      bfdEnabled: true,
      lfaEnabled: true,
      coppEnabled: true,
      maxMetricOnStartup: true,
      linkLocalDeterministic: true,
      multiAddressFamily: false,
      hasVirtualLinks: false
    },
    spineleaf: {
      name: 'Multi-AF Spine-Leaf Fabric (Juniper/FRR)',
      routerId: '10.100.1.1',
      processId: 10,
      areaId: '0.0.0.10',
      areaType: 'TOTALLY_STUBBY',
      coreInterface: 'et-0/0/1.0',
      accessVlan: 200,
      refBandwidthMbps: 4000000, // 4 Tbps RefBW
      instanceId: 64, // Multi-AF IPv4
      ipsecAuthEnabled: true,
      ipsecMode: 'ESP_GCM',
      ipsecSpi: 2000,
      passiveInterfaceDefault: true,
      bfdEnabled: true,
      lfaEnabled: true,
      coppEnabled: true,
      maxMetricOnStartup: true,
      linkLocalDeterministic: true,
      multiAddressFamily: true,
      instanceIsolation: true,
      hasVirtualLinks: false
    },
    vulnerable: {
      name: 'Vulnerable Unhardened OSPFv3',
      routerId: '192.168.1.1',
      processId: 1,
      areaId: '0.0.0.0',
      areaType: 'NORMAL',
      coreInterface: 'GigabitEthernet0/1',
      accessVlan: 10,
      refBandwidthMbps: 100, // Default 100M
      instanceId: 0,
      ipsecAuthEnabled: false,
      ipsecMode: 'NONE',
      ipsecSpi: 0,
      passiveInterfaceDefault: false,
      bfdEnabled: false,
      lfaEnabled: false,
      coppEnabled: false,
      maxMetricOnStartup: false,
      linkLocalDeterministic: false,
      multiAddressFamily: false,
      hasVirtualLinks: true
    }
  };

  let activeTab = 'cisco';

  // DOM Elements
  const elRouterId = document.getElementById('input-router-id');
  const elProcessId = document.getElementById('input-process-id');
  const elAreaId = document.getElementById('input-area-id');
  const elAreaType = document.getElementById('select-area-type');
  const elCoreIface = document.getElementById('input-core-iface');
  const elAccessVlan = document.getElementById('input-access-vlan');
  const elRefBw = document.getElementById('input-ref-bw');
  const elAfInstance = document.getElementById('select-af-instance');
  const elBadgeAfMode = document.getElementById('badge-af-mode');

  const elChkIpsec = document.getElementById('chk-ipsec');
  const elIpsecSpi = document.getElementById('input-ipsec-spi');
  const elIpsecMode = document.getElementById('select-ipsec-mode');
  const elChkPassiveDefault = document.getElementById('chk-passive-default');
  const elChkBfd = document.getElementById('chk-bfd');
  const elChkLfa = document.getElementById('chk-lfa');
  const elChkCopp = document.getElementById('chk-copp');
  const elChkMaxMetric = document.getElementById('chk-max-metric');

  const elBadgeRefBwStatus = document.getElementById('badge-ref-bw-status');
  const elCostTableBody = document.getElementById('cost-table-body');

  const elValDeadInterval = document.getElementById('val-dead-interval');
  const elValBfdFailover = document.getElementById('val-bfd-failover');
  const elValLfaRepair = document.getElementById('val-lfa-repair');
  const elValRefRatio = document.getElementById('val-ref-ratio');

  const elScoreBanner = document.getElementById('score-banner');
  const elScoreGrade = document.getElementById('score-grade');
  const elScoreTitle = document.getElementById('score-title');
  const elScoreSummary = document.getElementById('score-summary');
  const elFindingsContainer = document.getElementById('findings-container');

  const elBadgePacketProto = document.getElementById('badge-packet-proto');
  const elPacketHexDump = document.getElementById('packet-hex-dump');
  const elSynthOutput = document.getElementById('synth-output');
  const elBtnCopy = document.getElementById('btn-copy-config');

  function getFormConfig() {
    return {
      routerId: elRouterId.value.trim(),
      processId: parseInt(elProcessId.value, 10) || 1,
      areaId: elAreaId.value.trim(),
      areaType: elAreaType.value,
      coreInterface: elCoreIface.value.trim(),
      accessVlan: parseInt(elAccessVlan.value, 10) || 100,
      refBandwidthMbps: parseInt(elRefBw.value, 10) || 100000,
      instanceId: parseInt(elAfInstance.value, 10) || 0,
      ipsecAuthEnabled: elChkIpsec.checked,
      ipsecMode: elIpsecMode.value,
      ipsecSpi: parseInt(elIpsecSpi.value, 10) || 1000,
      passiveInterfaceDefault: elChkPassiveDefault.checked,
      bfdEnabled: elChkBfd.checked,
      lfaEnabled: elChkLfa.checked,
      coppEnabled: elChkCopp.checked,
      maxMetricOnStartup: elChkMaxMetric.checked,
      linkLocalDeterministic: true,
      multiAddressFamily: parseInt(elAfInstance.value, 10) >= 64,
      instanceIsolation: true,
      hasVirtualLinks: false
    };
  }

  function applyPreset(presetKey) {
    const p = PRESETS[presetKey];
    if (!p) return;

    elRouterId.value = p.routerId;
    elProcessId.value = p.processId;
    elAreaId.value = p.areaId;
    elAreaType.value = p.areaType;
    elCoreIface.value = p.coreInterface;
    elAccessVlan.value = p.accessVlan;
    elRefBw.value = p.refBandwidthMbps;
    elAfInstance.value = p.instanceId;

    elChkIpsec.checked = p.ipsecAuthEnabled;
    elIpsecSpi.value = p.ipsecSpi;
    elIpsecMode.value = p.ipsecMode;
    elChkPassiveDefault.checked = p.passiveInterfaceDefault;
    elChkBfd.checked = p.bfdEnabled;
    elChkLfa.checked = p.lfaEnabled;
    elChkCopp.checked = p.coppEnabled;
    elChkMaxMetric.checked = p.maxMetricOnStartup;

    document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`btn-preset-${presetKey}`);
    if (btn) btn.classList.add('active');

    updateAll();
  }

  function updateAll() {
    const cfg = getFormConfig();

    // 1. AF Badge
    if (cfg.instanceId >= 64) {
      elBadgeAfMode.textContent = `Multi-AF IPv4 (Instance ${cfg.instanceId})`;
      elBadgeAfMode.className = 'badge badge-purple';
    } else {
      elBadgeAfMode.textContent = `Pure IPv6 (Instance ${cfg.instanceId})`;
      elBadgeAfMode.className = 'badge badge-cyan';
    }

    // 2. Cost Table Calculation
    const costs = OSPFv3ProtocolEngine.calculateInterfaceCosts(cfg.refBandwidthMbps);
    elCostTableBody.innerHTML = '';
    let hasTruncated = false;

    costs.forEach(c => {
      if (c.isTruncatedToOne) hasTruncated = true;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-weight: 600;">${c.speed}</td>
        <td style="color: var(--text-muted);">${c.bandwidthMbps.toLocaleString()} Mbps</td>
        <td style="font-family: var(--font-mono); font-weight: bold; color: ${c.isTruncatedToOne ? 'var(--accent-rose)' : 'var(--accent-cyan)'};">${c.ospfCost}</td>
        <td><span class="badge ${c.isTruncatedToOne ? 'badge-rose' : 'badge-green'}">${c.isTruncatedToOne ? 'COLLAPSED TO 1' : 'DIFFERENTIATED'}</span></td>
      `;
      elCostTableBody.appendChild(tr);
    });

    if (hasTruncated) {
      elBadgeRefBwStatus.textContent = 'Polarization Hazard';
      elBadgeRefBwStatus.className = 'badge badge-rose';
    } else {
      elBadgeRefBwStatus.textContent = 'Accurate Metrics';
      elBadgeRefBwStatus.className = 'badge badge-green';
    }

    // 3. Metrics Row
    elValDeadInterval.textContent = cfg.bfdEnabled ? '< 50 ms (BFD)' : '40 sec';
    elValBfdFailover.textContent = cfg.bfdEnabled ? 'Active (50ms)' : 'Disabled';
    elValLfaRepair.textContent = cfg.lfaEnabled ? 'Sub-50ms (LFA)' : 'Full SPF Recalc';
    elValRefRatio.textContent = `${(cfg.refBandwidthMbps / 1000).toLocaleString()} Gbps`;

    // 4. 10-Point Audit
    const audit = OSPFv3SecurityAuditor.auditOSPFv3Architecture(cfg);
    elScoreGrade.textContent = audit.grade;
    elScoreTitle.textContent = `${audit.totalScore} / ${audit.maxScore} Points (${audit.passed ? 'Passed' : 'Failed'})`;
    elScoreSummary.textContent = audit.summary;
    elScoreBanner.className = `score-badge-large ${audit.passed ? 'grade-A' : 'grade-F'}`;

    elFindingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = `finding-item ${f.status.toLowerCase()}`;
      item.innerHTML = `
        <div class="finding-title">
          <span>${f.name}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxScore} pts</span>
        </div>
        <div class="finding-desc">${f.description}</div>
        ${f.remediation ? `<div class="finding-remediation">Remediation: ${f.remediation}</div>` : ''}
      `;
      elFindingsContainer.appendChild(item);
    });

    // 5. Binary Hex Wireframe Inspection
    const pktBytes = OSPFv3ProtocolEngine.encodeOSPFv3Packet({
      type: 1, // Hello
      routerId: cfg.routerId,
      areaId: cfg.areaId,
      instanceId: cfg.instanceId,
      enableIpsecAh: cfg.ipsecAuthEnabled,
      ipsecSpi: cfg.ipsecSpi
    });

    elBadgePacketProto.textContent = cfg.ipsecAuthEnabled ? 'IPsec AH + OSPFv3 Hello' : 'OSPFv3 Hello (Cleartext)';
    elPacketHexDump.textContent = OSPFv3ProtocolEngine.formatHexDump(pktBytes);

    // 6. Synthesizer Output
    renderSynthesizer(cfg);
  }

  function renderSynthesizer(cfg) {
    let code = '';
    if (activeTab === 'cisco') {
      code = OSPFv3ConfigSynthesizer.generateCisco(cfg);
    } else if (activeTab === 'arista') {
      code = OSPFv3ConfigSynthesizer.generateArista(cfg);
    } else if (activeTab === 'junos') {
      code = OSPFv3ConfigSynthesizer.generateJunos(cfg);
    } else if (activeTab === 'frr') {
      code = OSPFv3ConfigSynthesizer.generateFRR(cfg);
    } else if (activeTab === 'prom') {
      code = OSPFv3ConfigSynthesizer.generatePrometheus(cfg);
    }
    elSynthOutput.textContent = code;
  }

  // Event Listeners
  document.getElementById('btn-preset-core5g').addEventListener('click', () => applyPreset('core5g'));
  document.getElementById('btn-preset-spineleaf').addEventListener('click', () => applyPreset('spineleaf'));
  document.getElementById('btn-preset-vulnerable').addEventListener('click', () => applyPreset('vulnerable'));
  document.getElementById('btn-recalculate').addEventListener('click', updateAll);

  [elRouterId, elProcessId, elAreaId, elAreaType, elCoreIface, elAccessVlan, elRefBw, elAfInstance,
   elChkIpsec, elIpsecSpi, elIpsecMode, elChkPassiveDefault, elChkBfd, elChkLfa, elChkCopp, elChkMaxMetric
  ].forEach(input => {
    input.addEventListener('change', updateAll);
  });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      activeTab = e.target.getAttribute('data-tab');
      renderSynthesizer(getFormConfig());
    });
  });

  elBtnCopy.addEventListener('click', () => {
    navigator.clipboard.writeText(elSynthOutput.textContent).then(() => {
      elBtnCopy.textContent = 'Copied!';
      setTimeout(() => { elBtnCopy.textContent = 'Copy Config'; }, 2000);
    });
  });

  // Initialize
  applyPreset('core5g');
})();
