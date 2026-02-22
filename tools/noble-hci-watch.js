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
    debugGap: false,
    logDiscoveries: false,
    simulate: false,
    simulateOnMs: 15000,
    simulateOffMs: 500
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
    if (arg === '--debug-gap') {
      options.debugGap = true;
      continue;
    }
    if (arg === '--debug-both') {
      options.debugHci = true;
      options.debugGap = true;
      continue;
    }
    if (arg === '--log-discoveries') {
      options.logDiscoveries = true;
      continue;
    }
    if (arg === '--simulate') {
      options.simulate = true;
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
    if (arg === '--simulate-on-ms' && next != null) {
      options.simulateOnMs = Number.parseInt(next, 10);
      i++;
      continue;
    }
    if (arg.startsWith('--simulate-on-ms=')) {
      options.simulateOnMs = Number.parseInt(arg.slice('--simulate-on-ms='.length), 10);
      continue;
    }
    if (arg === '--simulate-off-ms' && next != null) {
      options.simulateOffMs = Number.parseInt(next, 10);
      i++;
      continue;
    }
    if (arg.startsWith('--simulate-off-ms=')) {
      options.simulateOffMs = Number.parseInt(arg.slice('--simulate-off-ms='.length), 10);
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
  if (!Number.isInteger(options.simulateOnMs) || options.simulateOnMs < 100) {
    throw new Error(`Invalid --simulate-on-ms: ${options.simulateOnMs}`);
  }
  if (!Number.isInteger(options.simulateOffMs) || options.simulateOffMs < 0) {
    throw new Error(`Invalid --simulate-off-ms: ${options.simulateOffMs}`);
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

function addDebugNamespaces(currentValue, namespaces) {
  const set = new Set(
    String(currentValue || '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean)
  );

  for (const namespace of namespaces) {
    if (namespace) {
      set.add(namespace);
    }
  }

  return [...set].join(',');
}

function printHelp() {
  console.log(`Usage: node tools/noble-hci-watch.js [options]

Continuously scans with the local noble checkout and prints/classifies hci.js packet warnings.

Options:
  --device-id <n>          HCI adapter index (same as NOBLE_HCI_DEVICE_ID)
  --extended <bool>        Enable extended scanning (default: true)
  --summary-interval <s>   Periodic summary interval in seconds (default: 30)
  --no-duplicates          Disable duplicate advertisements (default: duplicates enabled)
  --simulate               Simulate plugin-like scan pause/resume cycling
  --simulate-on-ms <ms>    Simulated scan-on window (default: 15000)
  --simulate-off-ms <ms>   Simulated scan-off/settle window (default: 500)
  --debug-hci              Enable DEBUG=hci output
  --debug-gap              Enable DEBUG=gap output
  --debug-both             Enable both DEBUG=hci and DEBUG=gap output
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
    scanStops: 0,
    simulateCycles: 0,
    simulatePauseCount: 0,
    simulateResumeCount: 0
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

  if (options.debugHci || options.debugGap) {
    const namespaces = [];
    if (options.debugHci) {
      namespaces.push('hci');
    }
    if (options.debugGap) {
      namespaces.push('gap');
    }
    process.env.DEBUG = addDebugNamespaces(process.env.DEBUG, namespaces);
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
  let simulateTimer = null;
  let simulateRunning = false;
  let adapterPoweredOn = false;
  let scanExpectedOn = false;

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const stopScanSafe = async (reason) => {
    try {
      if (typeof nobleInstance.stopScanningAsync === 'function') {
        await nobleInstance.stopScanningAsync();
      } else if (typeof nobleInstance.stopScanning === 'function') {
        nobleInstance.stopScanning(() => {});
      }
      if (reason) {
        console.log(`[noble-hci-watch] scan stop requested (${reason})`);
      }
    } catch (error) {
      console.error('[noble-hci-watch] stopScanning failed:', error.message || error);
    }
  };

  const startScanSafe = async (reason) => {
    try {
      await nobleInstance.startScanningAsync([], options.allowDuplicates);
      if (reason) {
        console.log(`[noble-hci-watch] scan start requested (${reason}) allowDuplicates=${options.allowDuplicates}`);
      }
      return true;
    } catch (error) {
      console.error('[noble-hci-watch] startScanning failed:', error.message || error);
      return false;
    }
  };

  const runSimulateLoop = async () => {
    if (simulateRunning || !options.simulate || !adapterPoweredOn || shuttingDown) {
      return;
    }
    simulateRunning = true;
    console.log(`[noble-hci-watch] simulate mode enabled onMs=${options.simulateOnMs} offMs=${options.simulateOffMs}`);

    while (!shuttingDown && options.simulate && adapterPoweredOn) {
      if (!scanExpectedOn) {
        scanExpectedOn = await startScanSafe('simulate resume');
        counters.simulateResumeCount += 1;
      }
      if (shuttingDown || !adapterPoweredOn) break;
      await sleep(options.simulateOnMs);
      if (shuttingDown || !adapterPoweredOn) break;

      if (scanExpectedOn) {
        counters.simulatePauseCount += 1;
        counters.simulateCycles += 1;
        await stopScanSafe('simulate pause');
        scanExpectedOn = false;
      }
      if (shuttingDown || !adapterPoweredOn) break;
      if (options.simulateOffMs > 0) {
        await sleep(options.simulateOffMs);
      }
    }

    simulateRunning = false;
  };

  const cleanup = async (reason) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[noble-hci-watch] stopping (${reason})`);

    clearInterval(summaryTimer);
    if (simulateTimer) {
      clearTimeout(simulateTimer);
      simulateTimer = null;
    }
    await stopScanSafe('cleanup');

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
    adapterPoweredOn = state === 'poweredOn';
    if (!adapterPoweredOn) {
      scanExpectedOn = false;
    }

    if (state !== 'poweredOn') {
      return;
    }

    if (options.simulate) {
      if (simulateTimer) {
        clearTimeout(simulateTimer);
      }
      simulateTimer = setTimeout(() => {
        void runSimulateLoop();
      }, 0);
      return;
    }
    scanExpectedOn = await startScanSafe('initial');
    if (scanExpectedOn) {
      console.log(`[noble-hci-watch] scanning started allowDuplicates=${options.allowDuplicates} extended=${options.extended} deviceId=${options.deviceId ?? 'default'}`);
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
    simulate: options.simulate,
    simulateOnMs: options.simulateOnMs,
    simulateOffMs: options.simulateOffMs,
    debugHci: options.debugHci,
    debugGap: options.debugGap,
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
  if (counters.simulateCycles > 0 || counters.simulatePauseCount > 0 || counters.simulateResumeCount > 0) {
    console.log(`[noble-hci-watch] simulate cycles=${counters.simulateCycles} pauses=${counters.simulatePauseCount} resumes=${counters.simulateResumeCount}`);
  }

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
