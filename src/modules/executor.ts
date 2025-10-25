/**
 * Script Executor Module
 * Executes native platform scripts (PowerShell/Bash) with timeout and output capture
 */

import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';

export interface ExecutorOptions {
  /** Timeout in milliseconds (default: 600000 = 10 minutes) */
  timeout?: number;
  /** Working directory for script execution */
  cwd?: string;
  /** Environment variables to pass to the script */
  env?: NodeJS.ProcessEnv;
  /** Additional arguments to pass to the script */
  args?: string[];
}

export interface ExecutionResult {
  /** Standard output from the script */
  stdout: string;
  /** Standard error output from the script */
  stderr: string;
  /** Exit code of the process */
  exitCode: number | null;
  /** Whether the process was killed due to timeout */
  timedOut: boolean;
  /** Execution duration in milliseconds */
  duration: number;
}

export class ScriptExecutor extends EventEmitter {
  private defaultTimeout = 600000; // 10 minutes

  /**
   * Execute a native script and capture its output
   * @param shellExecutable Path to shell executable (powershell.exe or /bin/bash)
   * @param scriptPath Path to the script file to execute
   * @param options Execution options
   * @returns Promise that resolves with execution results
   */
  async execute(
    shellExecutable: string,
    scriptPath: string,
    options: ExecutorOptions = {}
  ): Promise<ExecutionResult> {
    const timeout = options.timeout || this.defaultTimeout;
    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      const args = this.buildScriptArgs(shellExecutable, scriptPath, options.args);

      const child: ChildProcess = spawn(shellExecutable, args, {
        cwd: options.cwd || process.cwd(),
        env: { ...process.env, ...options.env },
        windowsHide: true,
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;

      // Set up timeout
      const timeoutHandle = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');

        // Force kill after 5 seconds if still running
        setTimeout(() => {
          if (!child.killed) {
            child.kill('SIGKILL');
          }
        }, 5000);
      }, timeout);

      // Capture stdout
      if (child.stdout) {
        child.stdout.on('data', (data: Buffer) => {
          const chunk = data.toString();
          stdout += chunk;
          this.emit('stdout', chunk);
        });
      }

      // Capture stderr
      if (child.stderr) {
        child.stderr.on('data', (data: Buffer) => {
          const chunk = data.toString();
          stderr += chunk;
          this.emit('stderr', chunk);
        });
      }

      // Handle process exit
      child.on('close', (exitCode: number | null) => {
        clearTimeout(timeoutHandle);
        const duration = Date.now() - startTime;

        const result: ExecutionResult = {
          stdout,
          stderr,
          exitCode,
          timedOut,
          duration,
        };

        if (timedOut) {
          reject(new Error(`Script execution timed out after ${timeout}ms`));
        } else if (exitCode !== 0 && exitCode !== null) {
          // Non-zero exit code, but still return results
          this.emit('non-zero-exit', exitCode);
        }

        resolve(result);
      });

      // Handle process errors
      child.on('error', (error: Error) => {
        clearTimeout(timeoutHandle);
        reject(new Error(`Failed to execute script: ${error.message}`));
      });
    });
  }

  /**
   * Build command-line arguments for the shell
   * @param shellExecutable Shell executable name
   * @param scriptPath Path to script
   * @param additionalArgs Additional arguments
   * @returns Array of command-line arguments
   */
  private buildScriptArgs(
    shellExecutable: string,
    scriptPath: string,
    additionalArgs?: string[]
  ): string[] {
    if (shellExecutable.toLowerCase().includes('powershell')) {
      // PowerShell arguments
      const args = [
        '-ExecutionPolicy', 'Bypass',
        '-NoProfile',
        '-File', scriptPath
      ];

      if (additionalArgs && additionalArgs.length > 0) {
        args.push(...additionalArgs);
      }

      return args;
    } else {
      // Bash/shell arguments
      const args = [scriptPath];

      if (additionalArgs && additionalArgs.length > 0) {
        args.push(...additionalArgs);
      }

      return args;
    }
  }

  /**
   * Parse JSON output from stdout, with error handling
   * @param stdout Raw stdout string
   * @returns Parsed JSON object
   */
  parseOutput<T = unknown>(stdout: string): T {
    try {
      return JSON.parse(stdout.trim()) as T;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to parse script output as JSON: ${error.message}\n\nOutput:\n${stdout.substring(0, 500)}`);
      }
      throw error;
    }
  }

  /**
   * Execute script and parse its JSON output in one step
   * @param shellExecutable Shell executable
   * @param scriptPath Script path
   * @param options Execution options
   * @returns Parsed JSON output
   */
  async executeAndParse<T = unknown>(
    shellExecutable: string,
    scriptPath: string,
    options: ExecutorOptions = {}
  ): Promise<T> {
    const result = await this.execute(shellExecutable, scriptPath, options);

    if (result.timedOut) {
      throw new Error('Script execution timed out');
    }

    if (result.exitCode !== 0) {
      throw new Error(`Script exited with code ${result.exitCode}. stderr: ${result.stderr}`);
    }

    return this.parseOutput<T>(result.stdout);
  }
}
