/*
 * A small pool of Web Workers that hash file contents in parallel.
 *
 * pool.hash(entry) has the same contract as hashInline in seal.js, so it plugs into
 * hashEntries as `hashContent`. Jobs queue until a worker is free. If workers are
 * unavailable, createHashPool returns null and the caller hashes inline instead.
 */

export function createHashPool(size = Math.min(navigator.hardwareConcurrency || 2, 8)) {
  let workers;
  try {
    workers = Array.from({ length: size }, () => new Worker(new URL('./hash-worker.js', import.meta.url)));
  } catch {
    return null;
  }

  const idle = [...workers];
  const queue = [];
  const running = new Map();   // worker -> job
  let nextId = 0;

  const finish = (worker, settle) => {
    const job = running.get(worker);
    running.delete(worker);
    idle.push(worker);
    if (job) settle(job);
    pump();
  };

  for (const w of workers) {
    w.onmessage = ({ data }) => finish(w, (job) =>
      data.error ? job.reject(new Error(data.error)) : job.resolve({ digest: data.digest, size: data.size }));
    w.onerror = (e) => { e.preventDefault(); finish(w, (job) => job.reject(new Error(e.message || 'hash worker failed'))); };
  }

  function pump() {
    while (idle.length && queue.length) {
      const job = queue.shift();
      const w = idle.pop();
      running.set(w, job);
      w.postMessage({ id: job.id, file: job.file, bytes: job.bytes });
    }
  }

  return {
    size,
    async hash(entry) {
      // In-memory entries (the demo) have no File, so their bytes are sent instead.
      const file = entry.file ?? null;
      const bytes = file ? null : entry.bytes ?? await entry.read();
      return new Promise((resolve, reject) => {
        queue.push({ id: nextId++, file, bytes, resolve, reject });
        pump();
      });
    },
  };
}
