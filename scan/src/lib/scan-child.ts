import { spawn, type SpawnOptions } from 'node:child_process';

// Runs a child as the leader of its own process group, so a stop can be
// forwarded to the child and everything it spawned, and to nothing else. The
// group id is recorded at spawn; it is the only target this module signals.

export interface SpawnedChild {
  done: Promise<number>;
  pgid: number | null;
  // Forwards sig to the recorded group, then SIGKILLs it if the child has not
  // closed after graceMs. Resolves once the child has closed.
  stop(sig: NodeJS.Signals): Promise<void>;
}

export interface SpawnGroupedOpts {
  env: NodeJS.ProcessEnv;
  stdio?: SpawnOptions['stdio'];
  graceMs: number;
  spawnFn?: typeof spawn;
  killFn?: (pid: number, sig: NodeJS.Signals) => void;
  setTimeoutFn?: typeof setTimeout;
  clearTimeoutFn?: typeof clearTimeout;
}

export function spawnGrouped(cmd: string, args: string[], o: SpawnGroupedOpts): SpawnedChild {
  const spawnFn = o.spawnFn ?? spawn;
  const killFn = o.killFn ?? ((pid, sig) => { process.kill(pid, sig); });
  const setT = o.setTimeoutFn ?? setTimeout;
  const clearT = o.clearTimeoutFn ?? clearTimeout;

  const child = spawnFn(cmd, args, { stdio: o.stdio ?? 'inherit', env: o.env, detached: true });
  const pid = child.pid;
  const pgid = typeof pid === 'number' && Number.isInteger(pid) && pid > 1 ? pid : null;

  let closed = false;
  let resolveDone!: (code: number) => void;
  const done = new Promise<number>((res) => { resolveDone = res; });
  const finish = (code: number): void => { if (closed) return; closed = true; resolveDone(code); };
  child.on('close', (code) => finish(code ?? -1));
  child.on('error', () => finish(-1));

  const signal = (sig: NodeJS.Signals): void => {
    if (pgid === null || closed) return;
    try { killFn(-pgid, sig); } catch { /* group already gone */ }
  };

  let stopping: Promise<void> | null = null;
  const stop = (sig: NodeJS.Signals): Promise<void> => {
    if (stopping) return stopping;
    if (closed) return (stopping = Promise.resolve());
    signal(sig);
    const timer = setT(() => signal('SIGKILL'), o.graceMs);
    stopping = done.then(() => { clearT(timer); });
    return stopping;
  };

  return { done, pgid, stop };
}
