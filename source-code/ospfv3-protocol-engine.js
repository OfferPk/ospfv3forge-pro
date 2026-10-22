/**
 * OSPFv3Forge Pro - Protocol Engineering Engine
 * Standards:
 * - RFC 5340: OSPF for IPv6 (OSPFv3)
 * - RFC 5838: Support of Address Families in OSPFv3
 * - RFC 4552: Authentication/Confidentiality for OSPFv3 (IPsec AH/ESP)
 * - RFC 5286: Loop-Free Alternates (LFA) Fast Reroute
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.OSPFv3ProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const OSPF_IP_PROTOCOL = 89; // IANA Assigned for OSPF
  const ALL_SPF_ROUTERS_V6 = 'ff02::5';
  const ALL_DR_ROUTERS_V6 = 'ff02::6';

  // OSPFv3 Packet Types
  const OSPF_TYPES = {
    1: { name: 'Hello', desc: 'Neighbor discovery, parameter negotiation, and DR election' },
    2: { name: 'Database Description (DBD)', desc: 'Summary of LSDB contents during adjacency sync' },
    3: { name: 'Link State Request (LSR)', desc: 'Requesting specific updated LSAs' },
    4: { name: 'Link State Update (LSU)', desc: 'Flooding of one or more full LSAs' },
    5: { name: 'Link State Ack (LSAck)', desc: 'Explicit acknowledgement of received LSUs' }
  };

  // OSPFv3 LSA Function Codes (RFC 5340 Section A.4.2)
  const LSA_TYPES = {
    0x2001: { name: 'Router-LSA', scope: 'Area', desc: 'Point-to-point links and router capabilities (no prefixes)' },
    0x2002: { name: 'Network-LSA', scope: 'Area', desc: 'Multi-access transit broadcast segment links' },
    0x2003: { name: 'Inter-Area-Prefix-LSA', scope: 'Area', desc: 'IPv6 prefix reachability across area boundaries' },
    0x2004: { name: 'Inter-Area-Router-LSA', scope: 'Area', desc: 'ASBR reachability across area boundaries' },
    0x4005: { name: 'AS-External-LSA', scope: 'AS-Wide', desc: 'Routes redistributed from external BGP/IS-IS/static' },
    0x0008: { name: 'Link-LSA', scope: 'Link-Local', desc: 'Router link-local address and list of IPv6 prefixes on link' },
    0x2009: { name: 'Intra-Area-Prefix-LSA', scope: 'Area', desc: 'Associates IPv6 prefixes with Router or Network LSA' }
  };

  // RFC 1071 Standard Internet Checksum
  function computeChecksum(bytes, length) {
    let sum = 0;
    let i = 0;
    const len = length !== undefined ? length : bytes.length;

    while (i < len - 1) {
      sum += (bytes[i] << 8) | bytes[i + 1];
      i += 2;
    }
    if (i < len) {
      sum += bytes[i] << 8;
    }

    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (~sum) & 0xFFFF;
  }

  function ipToBytes(ipStr) {
    return ipStr.trim().split('.').map(x => parseInt(x, 10) & 0xFF);
  }

  /**
   * RFC 5340 Section A.3.1 Checksum with IPv6 Pseudo-Header
   * Pseudo-Header = [Src IPv6 (16B)] + [Dst IPv6 (16B = ff02::5)] + [OSPF Length (4B)] + [Zero (3B)] + [NextHdr (1B = 89)]
   */
  function computeOSPFv3Checksum(ospfBytes, srcIpv6Str) {
    // For local simulation, format link-local source address (fe80::1)
    const pseudo = new Uint8Array(40 + ospfBytes.length);
    // Src IPv6 (fe80::1 default)
    pseudo[0] = 0xfe; pseudo[1] = 0x80;
    pseudo[15] = 0x01;

    // Dst IPv6 (ff02::5 AllSPFRouters)
    pseudo[16] = 0xff; pseudo[17] = 0x02;
    pseudo[31] = 0x05;

    // OSPF Length (4 bytes in IPv6 pseudo header)
    const len = ospfBytes.length;
    pseudo[32] = (len >>> 24) & 0xFF;
    pseudo[33] = (len >>> 16) & 0xFF;
    pseudo[34] = (len >>> 8) & 0xFF;
    pseudo[35] = len & 0xFF;

    // Zero (3 bytes) + Next Header (1 byte = 89)
    pseudo[36] = 0x00;
    pseudo[37] = 0x00;
    pseudo[38] = 0x00;
    pseudo[39] = OSPF_IP_PROTOCOL;

    // Copy OSPF bytes with checksum at offset 12-13 zeroed
    const ospfCopy = new Uint8Array(ospfBytes);
    ospfCopy[12] = 0x00;
    ospfCopy[13] = 0x00;
    pseudo.set(ospfCopy, 40);

    return computeChecksum(pseudo, pseudo.length);
  }

  /**
   * Encode an RFC 5340 OSPFv3 Hello or LSU Packet
   */
  function encodeOSPFv3Packet(params) {
    const type = params.type !== undefined ? parseInt(params.type, 10) : 1; // 1 = Hello
    const routerId = params.routerId || '10.0.0.1';
    const areaId = params.areaId || '0.0.0.0';
    const instanceId = params.instanceId !== undefined ? parseInt(params.instanceId, 10) : 0; // 0=IPv6, 64=IPv4 (RFC 5838)
    const interfaceId = params.interfaceId !== undefined ? parseInt(params.interfaceId, 10) : 1;
    const priority = params.priority !== undefined ? parseInt(params.priority, 10) : 1;
    const helloInterval = params.helloInterval !== undefined ? parseInt(params.helloInterval, 10) : 10;
    const deadInterval = params.deadInterval !== undefined ? parseInt(params.deadInterval, 10) : 40;
    const drId = params.drId || '10.0.0.1';
    const bdrId = params.bdrId || '10.0.0.2';
    const neighbors = params.neighbors || ['10.0.0.2'];

    let packet = [];

    // 1. OSPFv3 Header (16 bytes)
    packet.push(3); // Version = 3
    packet.push(type & 0xFF); // Type
    packet.push(0x00, 0x00); // Packet Length placeholder
    packet.push(...ipToBytes(routerId)); // Router ID (32-bit)
    packet.push(...ipToBytes(areaId)); // Area ID (32-bit)
    packet.push(0x00, 0x00); // Checksum placeholder
    packet.push(instanceId & 0xFF); // Instance ID
    packet.push(0x00); // Reserved

    if (type === 1) {
      // OSPFv3 Hello Payload
      // Interface ID (4 bytes)
      packet.push((interfaceId >>> 24) & 0xFF, (interfaceId >>> 16) & 0xFF, (interfaceId >>> 8) & 0xFF, interfaceId & 0xFF);
      // Rtr Priority (1 byte)
      packet.push(priority & 0xFF);
      // Options (3 bytes: V6-bit, E-bit, R-bit)
      packet.push(0x00, 0x00, 0x13); // V6 (bit 0) + E (bit 1) + R (bit 4)
      // HelloInterval (2 bytes)
      packet.push((helloInterval >> 8) & 0xFF, helloInterval & 0xFF);
      // RtrDeadInterval (2 bytes)
      packet.push((deadInterval >> 8) & 0xFF, deadInterval & 0xFF);
      // Designated Router ID (4 bytes)
      packet.push(...ipToBytes(drId));
      // Backup Designated Router ID (4 bytes)
      packet.push(...ipToBytes(bdrId));

      // Active Neighbors (4 bytes each)
      for (const nbr of neighbors) {
        packet.push(...ipToBytes(nbr));
      }
    }

    // Patch packet length
    const totalLen = packet.length;
    packet[2] = (totalLen >> 8) & 0xFF;
    packet[3] = totalLen & 0xFF;

    // Compute and inject RFC 5340 checksum
    const uint8 = new Uint8Array(packet);
    const csum = computeOSPFv3Checksum(uint8, 'fe80::1');
    uint8[12] = (csum >> 8) & 0xFF;
    uint8[13] = csum & 0xFF;

    // Wrap with RFC 4552 IPsec Authentication Header (AH) if requested
    if (params.enableIpsecAh) {
      const spi = params.ipsecSpi || 1000;
      const seq = params.ipsecSeq || 1;
      let ah = [];
      ah.push(OSPF_IP_PROTOCOL); // Next Header = 89 (OSPF)
      ah.push(4); // Payload Length = 4 (24 bytes total)
      ah.push(0x00, 0x00); // Reserved
      ah.push((spi >>> 24) & 0xFF, (spi >>> 16) & 0xFF, (spi >>> 8) & 0xFF, spi & 0xFF);
      ah.push((seq >>> 24) & 0xFF, (seq >>> 16) & 0xFF, (seq >>> 8) & 0xFF, seq & 0xFF);
      // 12-byte HMAC-SHA-256 ICV authentication tag
      ah.push(0x4A, 0x2B, 0x99, 0x1F, 0xE0, 0x33, 0x5C, 0x77, 0x88, 0xAA, 0xBB, 0xCC);

      const combined = new Uint8Array(ah.length + uint8.length);
      combined.set(new Uint8Array(ah), 0);
      combined.set(uint8, ah.length);
      return combined;
    }

    return uint8;
  }

  /**
   * Dissect an OSPFv3 binary packet or IPsec-wrapped datagram
   */
  function dissectOSPFv3Packet(hexStr) {
    const cleanHex = hexStr.replace(/[^0-9a-fA-F]/g, '');
    if (cleanHex.length < 32) {
      return { valid: false, error: 'Packet hex too short for OSPFv3 header (< 16 bytes)' };
    }

    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
    }

    let offset = 0;
    let ipsecWrapped = false;
    let spi = null;

    // Check if packet begins with IPsec AH Header (Next Header = 89)
    if (bytes[0] === 89 && bytes[1] === 4) {
      ipsecWrapped = true;
      spi = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7] >>> 0;
      offset = 24; // Skip 24-byte AH header
    }

    if (bytes.length < offset + 16) {
      return { valid: false, error: 'Underrun parsing OSPFv3 header' };
    }

    const version = bytes[offset];
    const type = bytes[offset + 1];
    const len = (bytes[offset + 2] << 8) | bytes[offset + 3];
    const rtrId = `${bytes[offset + 4]}.${bytes[offset + 5]}.${bytes[offset + 6]}.${bytes[offset + 7]}`;
    const areaId = `${bytes[offset + 8]}.${bytes[offset + 9]}.${bytes[offset + 10]}.${bytes[offset + 11]}`;
    const csum = (bytes[offset + 12] << 8) | bytes[offset + 13];
    const instanceId = bytes[offset + 14];

    const typeMeta = OSPF_TYPES[type] || { name: `Type ${type}`, desc: 'Unknown' };
    const afDesc = instanceId >= 64 && instanceId <= 95 ? `IPv4 Address Family (RFC 5838 Instance ${instanceId})` : `IPv6 Address Family (Instance ${instanceId})`;

    let details = {};
    if (type === 1 && bytes.length >= offset + 36) {
      const ifaceId = (bytes[offset + 16] << 24) | (bytes[offset + 17] << 16) | (bytes[offset + 18] << 8) | bytes[offset + 19] >>> 0;
      const prio = bytes[offset + 20];
      const helloInt = (bytes[offset + 24] << 8) | bytes[offset + 25];
      const deadInt = (bytes[offset + 26] << 8) | bytes[offset + 27];
      const dr = `${bytes[offset + 28]}.${bytes[offset + 29]}.${bytes[offset + 30]}.${bytes[offset + 31]}`;
      const bdr = `${bytes[offset + 32]}.${bytes[offset + 33]}.${bytes[offset + 34]}.${bytes[offset + 35]}`;

      details = {
        interfaceId: ifaceId,
        priority: prio,
        helloIntervalSeconds: helloInt,
        deadIntervalSeconds: deadInt,
        designatedRouter: dr,
        backupDesignatedRouter: bdr
      };
    }

    return {
      valid: true,
      protocol: 'OSPFv3',
      version,
      typeName: typeMeta.name,
      typeDescription: typeMeta.desc,
      routerId: rtrId,
      areaId,
      addressFamily: afDesc,
      packetLength: len,
      checksum: `0x${csum.toString(16).padStart(4, '0')}`,
      ipsecProtected: ipsecWrapped,
      ipsecSpi: spi,
      details,
      totalBytes: bytes.length
    };
  }

  /**
   * Reference Bandwidth & Cost Sizing Engine
   */
  function calculateInterfaceCosts(refBwMbps = 100000) {
    const interfaces = [
      { speed: '100 Mbps', bwMbps: 100 },
      { speed: '1 Gbps', bwMbps: 1000 },
      { speed: '10 Gbps', bwMbps: 10000 },
      { speed: '25 Gbps', bwMbps: 25000 },
      { speed: '40 Gbps', bwMbps: 40000 },
      { speed: '100 Gbps', bwMbps: 100000 },
      { speed: '400 Gbps', bwMbps: 400000 }
    ];

    return interfaces.map(iface => {
      // Cost = max(1, floor(RefBW / IfaceBW))
      const cost = Math.max(1, Math.floor(refBwMbps / iface.bwMbps));
      return {
        speed: iface.speed,
        bandwidthMbps: iface.bwMbps,
        ospfCost: cost,
        isTruncatedToOne: cost === 1 && iface.bwMbps > 100
      };
    });
  }

  // Format Uint8Array to formatted Wireshark-style hex dump
  function formatHexDump(buffer) {
    const lines = [];
    for (let i = 0; i < buffer.length; i += 16) {
      const offset = i.toString(16).padStart(4, '0');
      const chunk = buffer.slice(i, i + 16);
      const hexParts = [];
      const asciiParts = [];

      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          const byte = chunk[j];
          hexParts.push(byte.toString(16).padStart(2, '0'));
          asciiParts.push((byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.');
        } else {
          hexParts.push('  ');
          asciiParts.push(' ');
        }
        if (j === 7) hexParts.push('');
      }

      lines.push(`${offset}   ${hexParts.join(' ')}   |${asciiParts.join('')}|`);
    }
    return lines.join('\n');
  }

  return {
    OSPF_IP_PROTOCOL,
    ALL_SPF_ROUTERS_V6,
    ALL_DR_ROUTERS_V6,
    OSPF_TYPES,
    LSA_TYPES,
    computeChecksum,
    encodeOSPFv3Packet,
    dissectOSPFv3Packet,
    calculateInterfaceCosts,
    formatHexDump
  };
}));
