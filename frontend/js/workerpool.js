/**
 * A small pool of crypto workers with backpressure.
 *
 * The pool never holds more than `size` segments in flight, so resident memory
 * is bounded by the segment size times the pool size regardless of how large
 * the file is (C.4 / NF.5).  Callers await `run()`, which resolves only once a
 * worker is free, which is what applies the backpressure.
 */

export class WorkerPool {
  /**
   * @param {string} scriptUrl module worker script
   * @param {number} size number of workers
   */
  constructor(scriptUrl, size = defaultPoolSize()) {
    this.scriptUrl = scriptUrl;
    this.size = Math.max(1, size);
    this.workers = [];
    this.idle = [];
    this.queue = [];
    this.pending = new Map();
    this.nextId = 1;
    this.terminated = false;
  }

  _spawn() {
    const worker = new Worker(this.scriptUrl, { type: 'module' });
    worker.onmessage = (event) => {
      const { id, type } = event.data;
      const entry = this.pending.get(id);
      if (!entry) return;

      if (type === 'progress') {
        if (entry.onProgress) entry.onProgress(event.data.fraction);
        return;
      }

      this.pending.delete(id);
      this._release(worker);

      if (type === 'error') {
        const error = new Error(event.data.message);
        error.failedIndex = event.data.failedIndex;
        entry.reject(error);
      } else {
        entry.resolve(event.data);
      }
    };
    worker.onerror = (event) => {
      // A worker that dies takes its outstanding job with it; fail that job
      // rather than hanging, and replace the worker.
      for (const [id, entry] of this.pending) {
        if (entry.worker === worker) {
          this.pending.delete(id);
          entry.reject(new Error(event.message || 'The crypto worker stopped unexpectedly.'));
        }
      }
      this.workers = this.workers.filter((w) => w !== worker);
      this.idle = this.idle.filter((w) => w !== worker);
      worker.terminate();
    };
    this.workers.push(worker);
    return worker;
  }

  _acquire() {
    if (this.idle.length > 0) return Promise.resolve(this.idle.pop());
    if (this.workers.length < this.size) return Promise.resolve(this._spawn());
    return new Promise((resolve) => this.queue.push(resolve));
  }

  _release(worker) {
    const waiting = this.queue.shift();
    if (waiting) waiting(worker);
    else this.idle.push(worker);
  }

  /**
   * Send one job and await its result.
   * @param {object} job serialisable job payload
   * @param {Transferable[]} transfer buffers to move rather than copy
   * @param {(fraction:number)=>void} [onProgress]
   */
  async run(job, transfer = [], onProgress = null) {
    if (this.terminated) throw new Error('The worker pool has been shut down.');
    const worker = await this._acquire();
    const id = this.nextId;
    this.nextId += 1;

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onProgress, worker });
      try {
        worker.postMessage({ ...job, id }, transfer);
      } catch (error) {
        this.pending.delete(id);
        this._release(worker);
        reject(error);
      }
    });
  }

  terminate() {
    this.terminated = true;
    for (const worker of this.workers) worker.terminate();
    this.workers = [];
    this.idle = [];
    this.queue = [];
    for (const [, entry] of this.pending) {
      entry.reject(new Error('The operation was cancelled.'));
    }
    this.pending.clear();
  }
}

export function defaultPoolSize() {
  const cores = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 4;
  // Four workers already saturate AES-NI on typical hardware, and each one
  // costs a resident segment buffer.
  return Math.min(4, Math.max(1, cores - 1));
}
