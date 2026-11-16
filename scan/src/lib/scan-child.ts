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
  pollMs?: number;            // how often to probe the group after the leader closed, default 100 ms
  spawnFn?: typeof spawn;
  killFn?: (pid: number, sig: NodeJS.Signals | 0) => void;
  setTimeoutFn?: typeof setTimeout;
  clearTimeoutFn?: typeof clearTimeout;
}

// After SIGKILL, give up waiting for the group to empty after this many polls
// (members stuck in uninterruptible sleep must not hold the worker forever).
const MAX_POLLS_AFTER_KILL = 100;

export function spawnGrouped(cmd: string, args: string[], o: SpawnGroupedOpts): SpawnedChild {
  const spawnFn = o.spawnFn ?? spawn;
  const killFn = o.killFn ?? ((pid, sig) => { process.kill(pid, sig); });
  const setT = o.setTimeoutFn ?? setTimeout;
  const clearT = o.clearTimeoutFn ?? clearTimeout;
  const pollMs = o.pollMs ?? 100;

  const child = spawnFn(cmd, args, { stdio: o.stdio ?? 'inherit', env: o.env, detached: true });
  const pid = child.pid;
  const pgid = typeof pid === 'number' && Number.isInteger(pid) && pid > 1 ? pid : null;

  let leaderClosed = false;
  let exitCode = -1;
  let stopRequested = false;
  let finished = false;
  let resolveDone!: (code: number) => void;
  const done = new Promise<number>((res) => { resolveDone = res; });
  let resolveLeader!: () => void;
  const leaderP = new Promise<void>((res) => { resolveLeader = res; });
  const finish = (): void => { if (finished) return; finished = true; resolveDone(exitCode); };
  const onLeaderClose = (code: number): void => {
    if (leaderClosed) return;
    leaderClosed = true; exitCode = code; resolveLeader();
    // On a normal exit, leftovers are not this module's business; after a stop
    // the group is waited on in stop().
    if (!stopRequested) finish();
  };
  child.on('close', (code) => onLeaderClose(code ?? -1));
  child.on('error', () => onLeaderClose(-1));

  const signal = (sig: NodeJS.Signals): void => {
    if (pgid === null) return;
    try { killFn(-pgid, sig); } catch { /* group already gone */ }
  };
  // Only the recorded group is probed. ESRCH means it is empty; any other
  // outcome (alive, or EPERM) counts as still occupied.
  const groupAlive = (): boolean => {
    if (pgid === null) return false;
    try { killFn(-pgid, 0); return true; }
    catch (e) { return (e as NodeJS.ErrnoException).code !== 'ESRCH'; }
  };

  let stopping: Promise<void> | null = null;
  const stop = (sig: NodeJS.Signals): Promise<void> => {
    if (stopping) return stopping;
    if (finished) return (stopping = Promise.resolve());
    stopRequested = true;
    let killed = false;
    signal(sig);
    const timer = setT(() => { killed = true; signal('SIGKILL'); }, o.graceMs);
    stopping = (async () => {
      await leaderP;
      let polls = 0;
      while (groupAlive() && polls < MAX_POLLS_AFTER_KILL) {
        if (killed) polls++;
        await new Promise<void>((res) => { setT(res, pollMs); });
      }
      clearT(timer);
      finish();
    })();
    return stopping;
  };

  return { done, pgid, stop };
}
