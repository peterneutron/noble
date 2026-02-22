#!/usr/bin/env node
'use strict';

const path = require('path');

function parseArgs(argv) {
  const options = {
    deviceId: undefined,
    extended: true,
    allowDuplicates: true,
    summaryIntervalSec: 30,
    debugHci: false,
    logDiscoveries: false
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];

    if (arg === '--help' || arg === '-h') {
      options.help = true;
      continue;
    }
    if (arg === '--debug-hci') {
      options.debugHci = true;
      continue;
    }
    if (arg === '--log-discoveries') {
      options.logDiscoveries = true;
      continue;
    }
    if (arg === '--no-duplicates') {
      options.allowDuplicates = false;
      continue;
    }
    if (arg === '--device-id' && next != null) {
      options.deviceId = Number.parseInt(next, 10);
      i++;
      continue;
    }
    if (arg.startsWith('--device-id=')) {
      options.deviceId = Number.parseInt(arg.slice('--device-id='.length), 10);
      continue;
    }
    if (arg === '--summary-interval' && next != null) {
      options.summaryIntervalSec = Number.parseInt(next, 10);
      i++;
      continue;
    }
    if (arg.startsWith('--summary-interval=')) {
      options.summaryIntervalSec = Number.parseInt(arg.slice('--summary-interval='.length), 10);
      continue;
    }
    if (arg === '--extended' && next != null) {
      options.extended = parseBoolean(next, options.extended);
      i++;
      continue;
    }
    if (arg.startsWith('--extended=')) {
      options.extended = parseBoolean(arg.slice('--extended='.length), options.extended);
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  if (!Number.isInteger(options.summaryIntervalSec) || options.summaryIntervalSec <= 0) {
    throw new Error(`Invalid --summary-interval: ${options.summaryIntervalSec}`);
  }
  if (options.deviceId != null && !Number.isInteger(options.deviceId)) {
    throw new Error(`Invalid --device-id: ${options.deviceId}`);
  }

  return options;
}

function parseBoolean(value, defaultValue) {
  const normalized = String(value).toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'on' || normalized === 'yes') {
    return true;
  }
  if (normalized === 'false' || normalized === '0' || normalized === 'off' || normalized === 'no') {
    return false;
  }
  return defaultValue;
}

function printHelp() {
  console.log(`Usage: node tools/noble-hci-watch.js [options]

Continuously scans with the local noble checkout and prints/classifies hci.js packet warnings.

Options:
  --device-id <n>          HCI adapter index (same as NOBLE_HCI_DEVICE_ID)
  --extended <bool>        Enable extended scanning (default: true)
  --summary-interval <s>   Periodic summary interval in seconds (default: 30)
  --no-duplicates          Disable duplicate advertisements (default: duplicates enabled)
  --debug-hci              Enable DEBUG=hci output
  --log-discoveries        Print each discovery (can be noisy)
  -h, --help               Show this help
`);
}

function createCounters() {
  return {
    startedAt: Date.now(),
    warningsTotal: 0,
    hciIllegalTotal: 0,
    hciIllegalByKind: new Map(),
    discoveries: 0,
    discoveriesByAddress: new Map(),
    stateChanges: 0,
    scanStarts: 0,
    scanStops: 0
  };
}

function classifyHciWarning(message) {
  if (!message.includes('Caught illegal')) {
    return null;
  }
  if (message.includes('processLeExtendedAdvertisingReport')) {
    if (message.includes('too short')) {
      return 'ext_adv_too_short';
    }
    if (message.includes('eir length')) {
      return 'ext_adv_eir_oversize';
    }
    if (message.includes('buffer overflow')) {
      return 'ext_adv_buffer_overflow';
    }
    return 'ext_adv_other';
  }
  if (message.includes('onSocketData')) {
    if (message.includes('LE meta packet')) {
      return 'socket_le_meta_malformed';
    }
    if (message.includes('HCI event packet')) {
      return 'socket_event_too_short';
    }
    if (message.includes('ACL packet')) {
      return 'socket_acl_malformed';
    }
    return 'socket_other';
  }
  if (message.includes('processCmdCompleteEvent')) {
    return 'cmd_complete_malformed';
  }
  return 'other_illegal_packet';
}

function topEntries(map, limit = 10) {
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function installWarningTap(counters) {
  const originalWarn = console.warn;

  console.warn = function patchedWarn(...args) {
    try {
      const text = args.map((value) => {
        if (typeof value === 'string') return value;
        if (value instanceof Error) return value.stack || value.message;
        return String(value);
      }).join(' ');

      counters.warningsTotal += 1;
      const kind = classifyHciWarning(text);
      if (kind) {
        counters.hciIllegalTotal += 1;
        counters.hciIllegalByKind.set(kind, (counters.hciIllegalByKind.get(kind) || 0) + 1);
        const ts = new Date().toISOString();
        originalWarn.call(console, `[${ts}] [hci-illegal:${kind}]`, ...args);
        return;
      }
    } catch (err) {
      originalWarn.call(console, '[noble-hci-watch] warning tap error:', err);
    }

    return originalWarn.apply(console, args);
  };

  return () => {
    console.warn = originalWarn;
  };
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`[noble-hci-watch] ${error.message}`);
    printHelp();
    process.exitCode = 1;
    return;
  }

  if (options.help) {
    printHelp();
    return;
  }

  if (process.platform !== 'linux') {
    console.error(`[noble-hci-watch] This tool is intended for Linux hosts. Current platform: ${process.platform}`);
  }

  if (options.debugHci) {
    const currentDebug = process.env.DEBUG || '';
    process.env.DEBUG = currentDebug ? `${currentDebug},hci` : 'hci';
  }

  const counters = createCounters();
  const restoreWarn = installWarningTap(counters);
  const nobleRoot = path.resolve(__dirname, '..');
  const withBindings = require(path.join(nobleRoot, 'lib/resolve-bindings'));
  const nobleInstance = withBindings('hci', {
    deviceId: options.deviceId,
    extended: options.extended
  });

  const summaryTimer = setInterval(() => {
    printSummary(counters);
  }, options.summaryIntervalSec * 1000);
  if (typeof summaryTimer.unref === 'function') {
    summaryTimer.unref();
  }

  let shuttingDown = false;

  const cleanup = async (reason) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[noble-hci-watch] stopping (${reason})`);

    clearInterval(summaryTimer);
    try {
      if (typeof nobleInstance.stopScanningAsync === 'function') {
        await nobleInstance.stopScanningAsync();
      } else if (typeof nobleInstance.stopScanning === 'function') {
        nobleInstance.stopScanning(() => {});
      }
    } catch (error) {
      console.error('[noble-hci-watch] stopScanning failed:', error.message || error);
    }

    printSummary(counters, true);
    restoreWarn();
  };

  process.on('SIGINT', () => {
    cleanup('SIGINT').finally(() => process.exit(0));
  });
  process.on('SIGTERM', () => {
    cleanup('SIGTERM').finally(() => process.exit(0));
  });

  nobleInstance.on('stateChange', async (state) => {
    counters.stateChanges += 1;
    console.log(`[noble-hci-watch] state=${state}`);

    if (state !== 'poweredOn') {
      return;
    }

    try {
      await nobleInstance.startScanningAsync([], options.allowDuplicates);
      console.log(`[noble-hci-watch] scanning started allowDuplicates=${options.allowDuplicates} extended=${options.extended} deviceId=${options.deviceId ?? 'default'}`);
    } catch (error) {
      console.error('[noble-hci-watch] startScanning failed:', error.message || error);
    }
  });

  nobleInstance.on('scanStart', () => {
    counters.scanStarts += 1;
  });
  nobleInstance.on('scanStop', () => {
    counters.scanStops += 1;
    console.log('[noble-hci-watch] scan stopped');
  });

  nobleInstance.on('warning', (message) => {
    // noble already logs these via console.warn, but keep an explicit line for context.
    console.log(`[noble-hci-watch] noble warning event: ${message}`);
  });

  nobleInstance.on('discover', (peripheral) => {
    counters.discoveries += 1;
    const address = peripheral && peripheral.address ? peripheral.address : 'unknown';
    counters.discoveriesByAddress.set(address, (counters.discoveriesByAddress.get(address) || 0) + 1);

    if (!options.logDiscoveries) {
      return;
    }

    const localName = peripheral && peripheral.advertisement && peripheral.advertisement.localName
      ? peripheral.advertisement.localName
      : '';
    console.log(`[discover] address=${address} rssi=${peripheral.rssi} connectable=${peripheral.connectable} name=${localName}`);
  });

  process.on('uncaughtException', (error) => {
    console.error('[noble-hci-watch] uncaughtException:', error.stack || error);
  });
  process.on('unhandledRejection', (reason) => {
    console.error('[noble-hci-watch] unhandledRejection:', reason && reason.stack ? reason.stack : reason);
  });

  console.log(`[noble-hci-watch] using local noble at ${nobleRoot}`);
  console.log(`[noble-hci-watch] options: ${JSON.stringify({
    deviceId: options.deviceId ?? null,
    extended: options.extended,
    allowDuplicates: options.allowDuplicates,
    summaryIntervalSec: options.summaryIntervalSec,
    debugHci: options.debugHci,
    logDiscoveries: options.logDiscoveries
  })}`);

  // Trigger noble initialization.
  void nobleInstance.state;
}

function printSummary(counters, final = false) {
  const elapsedSec = Math.max(1, Math.floor((Date.now() - counters.startedAt) / 1000));
  const illegalTop = topEntries(counters.hciIllegalByKind, 10);
  const discoveryTop = topEntries(counters.discoveriesByAddress, 5);

  console.log(`[noble-hci-watch] ${final ? 'final ' : ''}summary elapsed=${elapsedSec}s discoveries=${counters.discoveries} uniqueDevices=${counters.discoveriesByAddress.size} warnings=${counters.warningsTotal} hciIllegal=${counters.hciIllegalTotal} scanStarts=${counters.scanStarts} scanStops=${counters.scanStops}`);

  if (illegalTop.length > 0) {
    console.log('[noble-hci-watch] illegal packet counts:', illegalTop.map(([kind, count]) => `${kind}=${count}`).join(' '));
  }
  if (discoveryTop.length > 0) {
    console.log('[noble-hci-watch] top devices:', discoveryTop.map(([addr, count]) => `${addr}=${count}`).join(' '));
  }
}

main().catch((error) => {
  console.error('[noble-hci-watch] fatal:', error.stack || error);
  process.exit(1);
});
