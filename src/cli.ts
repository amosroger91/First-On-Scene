#!/usr/bin/env node
/**
 * First-On-Scene CLI (optional analyst-side launcher).
 *
 * This is a thin, cross-platform wrapper that invokes the native orchestrator
 * (scripts/win/fos.ps1 or scripts/nix/fos.sh). The native scripts are the real
 * engine and have ZERO dependencies; this launcher is a convenience only and is
 * NOT required to run First-On-Scene.
 */

import { Command } from 'commander';
import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import Ajv from 'ajv';
import { PlatformDetector } from './modules/platform';

const program = new Command();
const pkg = require('../package.json');
const rootDir = path.resolve(__dirname, '..');

function runNative(extraArgs: string[]): number {
  const platform = PlatformDetector.detectPlatform();
  const scriptDir = PlatformDetector.getScriptDirectory(rootDir);
  const entry = path.join(scriptDir, PlatformDetector.getEntryScriptName());

  let cmd: string;
  let args: string[];
  if (platform === 'windows') {
    cmd = 'powershell.exe';
    args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', entry, ...extraArgs];
  } else {
    cmd = 'bash';
    args = [entry, ...extraArgs];
  }
  const res = spawnSync(cmd, args, { stdio: 'inherit' });
  return res.status ?? 1;
}

/** Map cross-platform CLI options onto the platform's native flag style. */
function nativeArgs(opts: any): string[] {
  const win = PlatformDetector.detectPlatform() === 'windows';
  const a: string[] = [];
  if (opts.mode) a.push(win ? '-Mode' : '--mode', opts.mode);
  if (opts.bundle) a.push(win ? '-BundlePath' : '--bundle', opts.bundle);
  if (opts.caseDir) a.push(win ? '-CaseDir' : '--case-dir', opts.caseDir);
  if (opts.brandName) a.push(win ? '-BrandName' : '--brand', opts.brandName);
  if (opts.enableLocalAi) a.push(win ? '-EnableLocalAI' : '--enable-local-ai');
  if (opts.noAction) a.push(win ? '-NoAction' : '--no-action');
  return a;
}

program
  .name('fos-triage')
  .description('First-On-Scene - cross-platform launcher for the native triage engine')
  .version(pkg.version);

program
  .command('run', { isDefault: true })
  .description('Collect + triage + report + seal (full pipeline)')
  .option('--brand-name <name>', 'Branding for the report')
  .option('--case-dir <path>', 'Output case directory')
  .option('--enable-local-ai', 'Add a local-only Ollama narrative (advisory)')
  .option('--no-action', 'Do not invoke the decision action scripts')
  .action((opts) => process.exit(runNative(nativeArgs({ mode: 'full', ...opts }))));

program
  .command('collect')
  .description('Collect artifacts only (for offline analysis)')
  .option('--case-dir <path>', 'Output case directory')
  .action((opts) => process.exit(runNative(nativeArgs({ mode: 'collect', ...opts }))));

program
  .command('analyze')
  .description('Analyze a previously collected bundle')
  .requiredOption('--bundle <path>', 'Path to bundle.json')
  .option('--case-dir <path>', 'Output case directory')
  .option('--brand-name <name>', 'Branding for the report')
  .option('--enable-local-ai', 'Add a local-only Ollama narrative (advisory)')
  .option('--no-action', 'Do not invoke the decision action scripts')
  .action((opts) => process.exit(runNative(nativeArgs({ mode: 'analyze', ...opts }))));

program
  .command('validate <bundle>')
  .description('Validate a bundle.json against the artifact schema')
  .action((bundle: string) => {
    const schema = JSON.parse(fs.readFileSync(path.join(rootDir, 'schemas', 'artifact_schema.json'), 'utf-8'));
    const data = JSON.parse(fs.readFileSync(bundle, 'utf-8'));
    const ajv = new Ajv({ allErrors: true, strict: false });
    const validate = ajv.compile(schema);
    if (validate(data)) {
      console.log('VALID: bundle conforms to artifact_schema.json');
      process.exit(0);
    } else {
      console.error('INVALID:');
      for (const e of validate.errors ?? []) console.error(`  ${e.instancePath || '/'} ${e.message}`);
      process.exit(1);
    }
  });

program
  .command('info')
  .description('Show platform detection and paths')
  .action(() => {
    console.log(`First-On-Scene ${pkg.version}`);
    console.log(`Platform:    ${PlatformDetector.getPlatformDisplayName()}`);
    console.log(`Script dir:  ${PlatformDetector.getScriptDirectory(rootDir)}`);
    console.log(`Entry:       ${PlatformDetector.getEntryScriptName()}`);
    console.log(`Node:        ${process.version}`);
    console.log('Note: the native scripts run standalone; this launcher is optional.');
  });

program.parse(process.argv);
