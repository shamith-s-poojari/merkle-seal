// Hashes one file per message off the main thread, so the page stays responsive.
// Reading the File here also keeps its bytes out of the main thread's memory.
self.onmessage = async ({ data: { id, file, bytes } }) => {
  try {
    const buffer = file ? await file.arrayBuffer() : bytes;
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buffer));
    self.postMessage({ id, digest, size: buffer.byteLength }, [digest.buffer]);
  } catch (err) {
    self.postMessage({ id, error: err?.message || String(err) });
  }
};
