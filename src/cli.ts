#!/usr/bin/env node
/**
 * First-On-Scene CLI Entry Point
 * Cross-platform AI-powered incident response triage toolkit
 */

import { Command } from 'commander';
import * as path from 'path';
import { PlatformDetector } from './modules/platform';

const program = new Command();

// Get package version
const packageJson = require('../package.json');

program
  .name('fos-triage')
  .description('AI-Powered Incident Response Triage for Windows/Linux/macOS')
  .version(packageJson.version);

program
  .command('collect')
  .description('Collect forensic artifacts from a target system')
  .option('-c, --computer-name <hostname>', 'Target computer hostname (for remote collection)')
  .option('-l, --local', 'Force local collection (default if no hostname specified)', true)
  .option('--brand-name <name>', 'Custom brand name for reports', 'First-On-Scene')
  .option('--logo-path <path>', 'Path to custom logo for reports')
  .option('--enable-defender', 'Enable Windows Defender if disabled before scan')
  .option('--run-rkill', 'Run rkill before collection (modifies system state)')
  .action(async (options) => {
    console.log('🔍 First-On-Scene - Forensic Data Collection\n');

    try {
      // Detect platform
      const platform = PlatformDetector.detectPlatform();
      console.log(`Platform detected: ${PlatformDetector.getPlatformDisplayName()}`);

      // Platform support check
      if (platform !== 'windows' && platform !== 'linux' && platform !== 'darwin') {
        console.error(`❌ Error: Platform ${platform} is not supported.`);
        process.exit(1);
      }

      console.log('\n⚠️  Note: Full collection implementation coming in Phase 1.');
      console.log('   Current Phase 0 establishes the architectural foundation.\n');

      console.log('Options received:');
      console.log(`  - Target: ${options.computerName || 'localhost (local)'}`);
      console.log(`  - Brand: ${options.brandName}`);
      console.log(`  - Enable Defender: ${options.enableDefender || false}`);
      console.log(`  - Run Rkill: ${options.runRkill || false}`);

      console.log('\n✅ Phase 0 (Architecture Setup) complete!');
      console.log('   Next: Implement Phase 1 (Node.js Orchestrator Core)');

    } catch (error) {
      if (error instanceof Error) {
        console.error(`\n❌ Error: ${error.message}`);
      }
      process.exit(1);
    }
  });

program
  .command('analyze')
  .description('Analyze collected artifacts using AI triage')
  .option('-i, --input <path>', 'Path to collected artifacts directory', './results')
  .action(async (options) => {
    console.log('🤖 First-On-Scene - AI Triage Analysis\n');
    console.log('⚠️  Analysis implementation coming in Phase 3.');
    console.log(`   Input directory: ${options.input}\n`);
  });

program
  .command('info')
  .description('Display system information and platform detection')
  .action(() => {
    console.log('📊 First-On-Scene System Information\n');

    try {
      const platform = PlatformDetector.detectPlatform();
      const rootDir = path.resolve(__dirname, '..');

      console.log(`Platform: ${PlatformDetector.getPlatformDisplayName()} (${platform})`);
      console.log(`Supported: ${PlatformDetector.isPlatformSupported() ? 'Yes' : 'No'}`);
      console.log(`Shell Executable: ${PlatformDetector.getShellExecutable()}`);
      console.log(`Script Directory: ${PlatformDetector.getScriptDirectory(rootDir)}`);
      console.log(`Collection Script: ${PlatformDetector.getCollectionScriptName()}`);
      console.log(`Node.js Version: ${process.version}`);
      console.log(`Installation Path: ${rootDir}\n`);

      console.log('📋 Project Status:');
      console.log('  ✅ Phase 0: Architecture Setup (COMPLETE)');
      console.log('  ⏳ Phase 1: Node.js Orchestrator Core (PENDING)');
      console.log('  ⏳ Phase 2: Native Script Refactoring (PENDING)');
      console.log('  ⏳ Phase 3: AI Triage & Analysis (PENDING)');
      console.log('  ⏳ Phase 4: Distribution & Packaging (PENDING)\n');

    } catch (error) {
      if (error instanceof Error) {
        console.error(`Error: ${error.message}`);
      }
      process.exit(1);
    }
  });

// Parse command-line arguments
program.parse(process.argv);

// Show help if no command specified
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
