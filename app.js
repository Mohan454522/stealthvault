/* ═══════════════════════════════════════════════════════════════════════
   STEALTHVAULT v6 — Definitive Rewrite
   ─────────────────────────────────────────────────────────────────────
   FORMAT V6 (why it's correct):

   [COVER IMAGE BYTES]      ← arbitrary length, stored explicitly
   [PAYLOAD HEADER]         ← MAGIC + SALT + FILE_COUNT + encrypted metadata
   [PAYLOAD DATA]           ← sequential encrypted chunks, all files
   [COVER_SIZE  : 8 bytes]  ← uint64 LE  — exact byte count of cover image
   [HEADER_SIZE : 4 bytes]  ← uint32 LE  — exact byte count of payload header
   [END_MARKER  : 8 bytes]  ← unique magic sequence

   KEY INVARIANT — chunk positions are computed by arithmetic, not scanning:
     dataStart = COVER_SIZE + HEADER_SIZE
     for each file i, chunk j:
       chunkOffset = dataStart + Σ_{prev chunks} (4 + plainLen + 28)
       chunkEncLen = plainLen + 28   (12 IV + plaintext + 16 GCM tag, always exact)

   This means readMeta never has to scan gigabytes of chunk data.
   It reads the trailer (20 bytes), then the header (always tiny, just metadata),
   and computes every chunk position from file sizes alone.
═══════════════════════════════════════════════════════════════════════ */
'use strict';

// ═══════════════════════════════════════════════════════════════════════
// EMBEDDED CRYPTO WORKER  (Blob URL — works from file:// with no server)
// ═══════════════════════════════════════════════════════════════════════
const WORKER_SRC = `
'use strict';
let K = null;
async function dk(pw, salt) {
  const raw = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt:new Uint8Array(salt), iterations:310000, hash:'SHA-256'},
    raw, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
  );
}
async function enc(buf) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, K, buf);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), 12);
  return out.buffer;
}
async function dec(buf) {
  return crypto.subtle.decrypt({name:'AES-GCM', iv:new Uint8Array(buf,0,12)}, K, new Uint8Array(buf,12));
}
self.onmessage = async ({data:{t,id,...d}}) => {
  try {
    if      (t==='init') { K=await dk(d.pw,d.salt); self.postMessage({id,ok:1}); }
    else if (t==='enc')  { const r=await enc(d.b); self.postMessage({id,ok:1,r},[r]); }
    else if (t==='dec')  { const r=await dec(d.b); self.postMessage({id,ok:1,r},[r]); }
    else if (t==='rst')  { K=null; self.postMessage({id,ok:1}); }
  } catch(e) { self.postMessage({id,ok:0,e:e.message}); }
};`;

// ─── Single worker wrapper ────────────────────────────────────────────
class CryptoWorker {
  constructor() {
    const u = URL.createObjectURL(new Blob([WORKER_SRC],{type:'application/javascript'}));
    this._w = new Worker(u); URL.revokeObjectURL(u);
    this._p = new Map(); this._n = 0;
    this._w.onmessage = ({data}) => {
      const cb = this._p.get(data.id); if (!cb) return;
      this._p.delete(data.id);
      data.ok ? cb.res(data) : cb.rej(new Error(data.e || 'Worker error'));
    };
  }
  _q(t, extra={}, tr=[]) {
    return new Promise((res,rej) => { const id=++this._n; this._p.set(id,{res,rej}); this._w.postMessage({t,id,...extra},tr); });
  }
  init(pw, saltArr)  { return this._q('init',{pw, salt:saltArr}); }
  async enc(buf)     { const d=await this._q('enc',{b:buf},[buf]); return new Uint8Array(d.r); }
  async dec(buf)     { const d=await this._q('dec',{b:buf},[buf]); return new Uint8Array(d.r); }
  rst()              { return this._q('rst'); }
  kill()             { this._w.terminate(); }
}

// ─── Worker pool — round-robin across N workers ───────────────────────
class WorkerPool {
  constructor(n) { this.ws=Array.from({length:n},()=>new CryptoWorker()); this._i=0; }
  async init(pw, saltArr) { await Promise.all(this.ws.map(w=>w.init(pw,saltArr))); }
  enc(buf) { const w=this.ws[this._i]; this._i=(this._i+1)%this.ws.length; return w.enc(buf); }
  dec(buf) { const w=this.ws[this._i]; this._i=(this._i+1)%this.ws.length; return w.dec(buf); }
  async rst() { await Promise.all(this.ws.map(w=>w.rst())); }
}

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS & CONFIG
// ═══════════════════════════════════════════════════════════════════════
// V6 format markers
const MAGIC      = new Uint8Array([0x53,0x56,0x4C,0x54,0x00,0x06,0x00,0x00]); // "SVLT\0\6\0\0"
const END_MARKER = new Uint8Array([0xDE,0xAD,0x56,0x36,0x00,0x00,0xDE,0xAD]); // unique, cannot appear in JPEG
const TRAILER_SZ = 20; // COVER_SIZE(8) + HEADER_SIZE(4) + END_MARKER(8)

const ENC_OVERHEAD = 12 + 16; // AES-GCM IV(12) + GCM tag(16) = 28 bytes, always exact

// Available chunk sizes (MB → bytes)
const CHUNK_SIZE_OPTIONS = [16, 32, 64, 128, 256].map(mb => mb * 1024 * 1024);

// ── CONFIG: loaded from localStorage, editable from the Settings panel ──
// IMPORTANT: chunk size is also stored inside each encrypted file's header,
// so decryption always reads the stored value — not this setting.
// This setting only affects NEW encryptions.
const CONFIG_KEY = 'sv-config-v1';
const CONFIG_DEFAULTS = {
  chunkSizeMB:   64,    // MB per chunk for new encryptions
  workerCount:   Math.min(4, navigator.hardwareConcurrency || 2),
  skipSeconds:   10,    // video skip interval (arrow keys & buttons)
  autoPlayNext:  true,  // auto-play next item when video ends
  autoPlayDelay: 3,     // seconds countdown before auto-next
  prefetchAhead: 2,     // how many items to prefetch beyond current
  previewLimitMB:2048,  // files larger than this (MB) show "too large" in viewer
};

function loadConfig() {
  try { return { ...CONFIG_DEFAULTS, ...JSON.parse(localStorage.getItem(CONFIG_KEY) || '{}') }; }
  catch { return { ...CONFIG_DEFAULTS }; }
}
function saveConfig(cfg) {
  localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg));
}
let CONFIG = loadConfig();

// Derived live values (recalculated whenever CONFIG changes)
function getChunkSz()    { return CONFIG.chunkSizeMB * 1024 * 1024; }
function getPoolSz()     { return Math.min(Math.max(1, CONFIG.workerCount), 8); }
function getPreviewMax() { return CONFIG.previewLimitMB * 1024 * 1024; }

const POOL = new WorkerPool(getPoolSz());

// ═══════════════════════════════════════════════════════════════════════
// LOW-LEVEL HELPERS
// ═══════════════════════════════════════════════════════════════════════
const readBlob = b => new Promise((res,rej) => {
  const fr = new FileReader();
  fr.onload  = () => res(new Uint8Array(fr.result));
  fr.onerror = () => rej(fr.error);
  fr.readAsArrayBuffer(b);
});

// Ensure a Uint8Array owns its ArrayBuffer before transferring to a worker
const ownBuf = u8 =>
  (u8.byteOffset!==0 || u8.byteLength!==u8.buffer.byteLength) ? u8.slice(0).buffer : u8.buffer;

// 32-bit LE, unsigned-safe
const ru32 = (a,o) => ((a[o])|(a[o+1]<<8)|(a[o+2]<<16)|(a[o+3]<<24))>>>0;
const wu32 = v => { const b=new Uint8Array(4); new DataView(b.buffer).setUint32(0,v>>>0,true); return b; };

// 64-bit LE via BigInt — handles up to 9 petabytes
function wu64(v) {
  const b=new Uint8Array(8); let n=BigInt(Math.floor(v));
  for(let i=0;i<8;i++){b[i]=Number(n&0xFFn);n>>=8n;} return b;
}
function ru64(a,o) {
  let n=0n; for(let i=7;i>=0;i--)n=(n<<8n)|BigInt(a[o+i]); return Number(n);
}

// MIME and icon tables
function getMime(n){const e=(n.split('.').pop()||'').toLowerCase();return{mp4:'video/mp4',mkv:'video/x-matroska',mov:'video/quicktime',avi:'video/x-msvideo',webm:'video/webm',m4v:'video/x-m4v',mp3:'audio/mpeg',wav:'audio/wav',flac:'audio/flac',aac:'audio/aac',ogg:'audio/ogg',m4a:'audio/x-m4a',jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',gif:'image/gif',webp:'image/webp',bmp:'image/bmp',svg:'image/svg+xml',heic:'image/heic',pdf:'application/pdf',txt:'text/plain',zip:'application/zip'}[e]||'application/octet-stream';}
function getIcon(n){const e=(n.split('.').pop()||'').toLowerCase();return{mp4:'🎬',mkv:'🎬',mov:'🎬',avi:'🎬',webm:'🎬',m4v:'🎬',mp3:'🎵',wav:'🎵',flac:'🎵',aac:'🎵',ogg:'🎵',m4a:'🎵',jpg:'🖼️',jpeg:'🖼️',png:'🖼️',gif:'🖼️',webp:'🖼️',bmp:'🖼️',svg:'🖼️',heic:'🖼️',pdf:'📄',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',txt:'📃',zip:'🗜️',rar:'🗜️'}[e]||'📁';}
const isVid = n=>/\.(mp4|mkv|mov|avi|webm|m4v)$/i.test(n);
const isAud = n=>/\.(mp3|wav|flac|aac|ogg|m4a)$/i.test(n);
const isImg = n=>/\.(jpg|jpeg|png|gif|webp|bmp|svg|heic)$/i.test(n);
const isPDF = n=>/\.pdf$/i.test(n);
const isTxt = n=>/\.txt$/i.test(n);

function fmtBytes(n){if(n<1024)return n+'B';if(n<1e6)return(n/1024).toFixed(1)+'KB';if(n<1e9)return(n/1e6).toFixed(1)+'MB';return(n/1e9).toFixed(2)+'GB';}
function fmtSpd(b){return b<1e6?(b/1024).toFixed(0)+' KB/s':(b/1e6).toFixed(1)+' MB/s';}
function fmtEta(r,b){if(b<=0||r<=0)return'';const s=r/b;return s<60?`~${Math.ceil(s)}s`:s<3600?`~${Math.ceil(s/60)}m`:`~${(s/3600).toFixed(1)}h`;}

// ═══════════════════════════════════════════════════════════════════════
// PROGRESS HELPER
// ═══════════════════════════════════════════════════════════════════════
function makeProgress(barEl, labelEl) {
  let t0 = Date.now();
  return {
    start(label) {
      t0 = Date.now();
      if (barEl)   { barEl.style.width = '0%'; barEl.classList.remove('pulsing'); }
      if (labelEl) labelEl.textContent = label;
    },
    update(done, total) {
      const spd = done / Math.max((Date.now()-t0)/1000, 0.001);
      // Cap at 98% — the last 2% is reserved for the "Finalizing" phase below
      const pct = total > 0 ? Math.min(Math.round(done/total*100), 98) : 0;
      if (barEl)   { barEl.style.width = pct + '%'; barEl.classList.remove('pulsing'); }
      if (labelEl) labelEl.textContent = `${fmtBytes(done)} / ${fmtBytes(total)} · ${fmtSpd(spd)} · ${fmtEta(total-done, spd)}`;
    },
    // Call this between finishing the chunk loop and calling writable.close()
    // writable.close() can block for several seconds on large files while the OS flushes
    finalizing() {
      if (barEl)   { barEl.style.width = '99%'; barEl.classList.add('pulsing'); }
      if (labelEl) labelEl.textContent = 'Finalizing — flushing to disk… (do not close)';
    },
    finish(msg = '✔ Done') {
      if (barEl)   { barEl.style.width = '100%'; barEl.classList.remove('pulsing'); }
      if (labelEl) labelEl.textContent = msg;
    }
  };
}

// ═══════════════════════════════════════════════════════════════════════
// VAULT I/O — V6 FORMAT
// ═══════════════════════════════════════════════════════════════════════

// ── ENCRYPT ──────────────────────────────────────────────────────────
// Header format: MAGIC(8) + SALT(16) + CHUNK_SIZE(4) + FILE_COUNT(4) + metadata
// CHUNK_SIZE is stored in the file so decryption always uses the right value,
// regardless of what the app setting is later.
async function vaultEncrypt(files, password, coverArrayBuf, outFH, onProgress) {
  // Snapshot live config at the moment of encryption
  const chunkSz = getChunkSz();
  const batchSz = getPoolSz();

  const salt    = crypto.getRandomValues(new Uint8Array(16));
  const saltArr = Array.from(salt);
  await POOL.init(password, saltArr);

  // 1. Encrypt all metadata (tiny — file names + sizes only)
  const metaEncs = [];
  for (const f of files) {
    const j  = JSON.stringify({name:f.name, mime:getMime(f.name), size:f.size});
    const u8 = new TextEncoder().encode(j);
    metaEncs.push(await POOL.enc(ownBuf(u8)));
  }
  await POOL.rst();

  // 2. Compute header size (needed for trailer before any writing)
  //    MAGIC(8) + SALT(16) + CHUNK_SIZE(4) + FILE_COUNT(4) + Σ[META_ENC_LEN(4) + META_ENC]
  let headerSize = MAGIC.length + 16 + 4 + 4; // extra 4 = stored CHUNK_SIZE field
  for (const me of metaEncs) headerSize += 4 + me.length;

  const coverU8   = new Uint8Array(coverArrayBuf);
  const coverSize = coverU8.length;

  // 3. Open writable and stream everything to disk
  await POOL.init(password, saltArr);
  const writable = await outFH.createWritable();

  // Write cover image
  await writable.write(coverU8);

  // Write payload header: MAGIC + SALT + CHUNK_SIZE (stored!) + FILE_COUNT + per-file metadata
  await writable.write(MAGIC);
  await writable.write(salt);
  await writable.write(wu32(chunkSz));   // ← stored chunk size — always read back by decryptor
  await writable.write(wu32(files.length));
  for (const me of metaEncs) {
    await writable.write(wu32(me.length));
    await writable.write(me);
  }

  // Write chunk data — batchSz chunks in parallel, sequential writes
  const totalBytes = files.reduce((s,f) => s+f.size, 0);
  let done=0, t0=Date.now();

  for (const f of files) {
    const nChunks = f.size > 0 ? Math.ceil(f.size / chunkSz) : 0;
    for (let base=0; base<nChunks; base+=batchSz) {
      const bEnd = Math.min(base+batchSz, nChunks);
      const readPs = [];
      for (let ci=base; ci<bEnd; ci++) {
        const s=ci*chunkSz, e=Math.min(s+chunkSz, f.size);
        readPs.push(readBlob(f.slice(s, e)));
      }
      const chunks = await Promise.all(readPs);
      const encPs  = chunks.map(c => POOL.enc(c.buffer));
      for (let i=0; i<encPs.length; i++) {
        const enc = await encPs[i];
        await writable.write(wu32(enc.length));
        await writable.write(enc);
        done += chunks[i].length;
        if (onProgress) onProgress(done, totalBytes);
      }
    }
  }

  // Signal "finalizing" to UI — writable.close() blocks while OS flushes to disk
  if (onProgress) onProgress(null, null);
  await writable.write(wu64(coverSize));   // ← trailer
  await writable.write(wu32(headerSize));  // ← trailer
  await writable.write(END_MARKER);        // ← trailer (unique 8 bytes)
  await writable.close();
  if (onProgress) onProgress(totalBytes, totalBytes); // signal 100%
  await POOL.rst();
}

// ── READ METADATA ────────────────────────────────────────────────────
// Reads the 20-byte trailer → finds the header (tiny) → decrypts metadata.
// Reads the stored CHUNK_SIZE from the header and uses it for position arithmetic.
// Never has to scan through chunk data — all positions computed from sizes.
async function vaultReadMeta(imageFile, password) {
  if (imageFile.size < TRAILER_SZ + MAGIC.length + 20) throw new Error('File too small to be a vault');

  // ── Step 1: read trailer (last 20 bytes), verify END_MARKER
  const trailer = await readBlob(imageFile.slice(imageFile.size - TRAILER_SZ, imageFile.size));
  for (let i=0; i<END_MARKER.length; i++) {
    if (trailer[12+i] !== END_MARKER[i]) throw new Error('Not a StealthVault v6 file');
  }
  const coverSize  = ru64(trailer, 0);
  const headerSize = ru32(trailer, 8);

  if (coverSize <= 0 || coverSize >= imageFile.size - TRAILER_SZ)
    throw new Error('Corrupted vault: invalid cover size');
  if (headerSize < MAGIC.length + 20)
    throw new Error('Corrupted vault: invalid header size');

  // ── Step 2: read entire payload header into memory (always tiny)
  const hdr = await readBlob(imageFile.slice(coverSize, coverSize + headerSize));

  // ── Step 3: verify MAGIC
  let off = 0;
  for (let i=0; i<MAGIC.length; i++) {
    if (hdr[off+i] !== MAGIC[i]) throw new Error('Invalid MAGIC — file created with a different version');
  }
  off += MAGIC.length;

  // ── Step 4: read salt → stored chunk size → derive key → decrypt metadata
  const salt    = hdr.slice(off, off+16); off += 16;
  const saltArr = Array.from(salt);

  // Read the chunk size stored at encryption time — NOT the current app setting.
  // This guarantees correct decryption even if the user later changes the setting.
  const storedChunkSz = ru32(hdr, off); off += 4;
  if (!CHUNK_SIZE_OPTIONS.includes(storedChunkSz) && storedChunkSz !== 64*1024*1024)
    throw new Error('Corrupted vault: unrecognised chunk size ' + storedChunkSz);

  await POOL.init(password, saltArr);

  const fileCount = ru32(hdr, off); off += 4;
  if (fileCount === 0 || fileCount > 10000) { await POOL.rst(); throw new Error('Wrong password or corrupted vault'); }

  const items = [];
  for (let fi=0; fi<fileCount; fi++) {
    const mLen = ru32(hdr, off); off += 4;
    const mEnc = hdr.slice(off, off+mLen).slice(0); off += mLen;

    let meta;
    try {
      const plain = await POOL.dec(mEnc.buffer);
      meta = JSON.parse(new TextDecoder().decode(plain));
    } catch {
      await POOL.rst();
      throw new Error('Wrong password');
    }
    // Store storedChunkSz on each item — decryptFull and prefetch use this
    items.push({ name:meta.name, mime:meta.mime||getMime(meta.name), size:meta.size, salt:saltArr, chunkSz:storedChunkSz, imageFile });
  }
  await POOL.rst();

  // ── Step 5: compute chunk positions arithmetically using the STORED chunk size
  const dataStart = coverSize + headerSize;
  let pos = dataStart;
  for (const item of items) {
    const nChunks = item.size > 0 ? Math.ceil(item.size / item.chunkSz) : 0;
    item.nChunks      = nChunks;
    item.chunkOffsets = [];
    for (let ci=0; ci<nChunks; ci++) {
      item.chunkOffsets.push(pos);
      const plainLen = Math.min(item.chunkSz, item.size - ci*item.chunkSz);
      pos += 4 + plainLen + ENC_OVERHEAD;
    }
  }

  return items;
}

// ── DECRYPT FULL ─────────────────────────────────────────────────────
// Decrypts all chunks into a single Uint8Array (for in-browser playback).
// Uses BATCH parallel decryptions. Peak RAM ≈ file.size + BATCH×128MB.
async function vaultDecryptFull(item, password, pool, onProgress) {
  await pool.init(password, item.salt);
  const result = new Uint8Array(item.size);
  let writeOff=0, done=0, t0=Date.now();

  for (let base=0; base<item.nChunks; base+=BATCH) {
    const bEnd = Math.min(base+BATCH, item.nChunks);
    // Read encrypted chunks in parallel
    const readPs = [];
    for (let ci=base; ci<bEnd; ci++) {
      const absOff = item.chunkOffsets[ci];
      readPs.push(
        readBlob(item.imageFile.slice(absOff, absOff+4)).then(lb => {
          const encLen = ru32(lb, 0);
          return readBlob(item.imageFile.slice(absOff+4, absOff+4+encLen));
        })
      );
    }
    const encChunks = await Promise.all(readPs);
    // Decrypt in parallel (round-robin)
    const decPs = encChunks.map(ec => pool.dec(ec.buffer));
    // Copy results into pre-allocated output buffer
    for (let i=0; i<decPs.length; i++) {
      const plain = await decPs[i];
      result.set(plain, writeOff);
      writeOff += plain.length;
      done     += plain.length;
      if (onProgress) onProgress(done, item.size);
    }
  }
  await pool.rst();
  return result;
}

// ── EXPORT TO FILE ───────────────────────────────────────────────────
// Streams decrypted chunks directly to disk. Never accumulates in RAM.
// Peak RAM ≈ BATCH × 128 MB, regardless of file size.
async function vaultExportItem(item, password) {
  let fh;
  try {
    const ext = item.name.split('.').pop() || 'bin';
    fh = await window.showSaveFilePicker({
      suggestedName: item.name,
      types: [{ description: 'File', accept: {[item.mime]: ['.' + ext]} }]
    });
  } catch(e) { if (e.name !== 'AbortError') throw e; return false; }

  const prog = makeProgress(
    document.getElementById('viewer-dec-bar'),
    document.getElementById('viewer-dec-label')
  );
  document.getElementById('viewer-loading').classList.remove('hidden');
  document.getElementById('vl-icon').textContent = '💾';
  document.getElementById('vl-name').textContent = 'Exporting ' + item.name;
  prog.start('Starting export…');

  await POOL.init(password, item.salt);
  const writable = await fh.createWritable();
  let done=0;

  for (let base=0; base<item.nChunks; base+=BATCH) {
    const bEnd = Math.min(base+BATCH, item.nChunks);
    const readPs = [];
    for (let ci=base; ci<bEnd; ci++) {
      const absOff = item.chunkOffsets[ci];
      readPs.push(
        readBlob(item.imageFile.slice(absOff, absOff+4)).then(lb => {
          const encLen = ru32(lb,0);
          return readBlob(item.imageFile.slice(absOff+4, absOff+4+encLen));
        })
      );
    }
    const encChunks = await Promise.all(readPs);
    const decPs = encChunks.map(ec => POOL.dec(ec.buffer));
    for (let i=0; i<decPs.length; i++) {
      const plain = await decPs[i];
      await writable.write(plain);   // write directly to disk
      done += plain.length;
      prog.update(done, item.size);
    }
  }

  await writable.close();
  await POOL.rst();
  document.getElementById('viewer-loading').classList.add('hidden');
  return true;
}

// ── CHANGE PASSWORD (streaming — RAM ≈ 2 × CHUNK_SZ) ────────────────
// Decrypts each chunk with old key → re-encrypts with new key → writes.
// No full file ever in RAM at once.
async function vaultChangePassword(imageFile, oldPw, newPw, outFH, onProgress) {
  const items = await vaultReadMeta(imageFile, oldPw);

  // New crypto material
  const newSalt    = crypto.getRandomValues(new Uint8Array(16));
  const newSaltArr = Array.from(newSalt);

  // Re-encrypt metadata with new password
  const encW = new CryptoWorker();
  await encW.init(newPw, newSaltArr);
  const metaEncs = [];
  for (const item of items) {
    const j  = JSON.stringify({name:item.name, mime:item.mime, size:item.size});
    const u8 = new TextEncoder().encode(j);
    metaEncs.push(await encW.enc(ownBuf(u8)));
  }

  // Compute new header size
  let headerSize = MAGIC.length + 16 + 4;
  for (const me of metaEncs) headerSize += 4 + me.length;

  // Read original cover image
  const trailer   = await readBlob(imageFile.slice(imageFile.size-TRAILER_SZ, imageFile.size));
  const coverSize = ru64(trailer, 0);
  const coverU8   = await readBlob(imageFile.slice(0, coverSize));

  // Write new vault file
  const writable = await outFH.createWritable();
  await writable.write(coverU8);
  await writable.write(MAGIC);
  await writable.write(newSalt);
  await writable.write(wu32(items.length));
  for (const me of metaEncs) { await writable.write(wu32(me.length)); await writable.write(me); }

  // Re-encrypt chunks: old-key decrypt → new-key encrypt
  const decW = new CryptoWorker();
  const totalBytes = items.reduce((s,it) => s+it.size, 0);
  let done=0;

  for (const item of items) {
    await decW.init(oldPw, item.salt);
    for (let ci=0; ci<item.nChunks; ci++) {
      const absOff = item.chunkOffsets[ci];
      const lb     = await readBlob(item.imageFile.slice(absOff, absOff+4));
      const encLen = ru32(lb, 0);
      const encDat = await readBlob(item.imageFile.slice(absOff+4, absOff+4+encLen));
      const plain  = await decW.dec(encDat.buffer);
      const newEnc = await encW.enc(ownBuf(new Uint8Array(plain)));
      await writable.write(wu32(newEnc.length));
      await writable.write(newEnc);
      done += plain.byteLength;
      if (onProgress) onProgress(done, totalBytes);
    }
  }

  await writable.write(wu64(coverSize));
  await writable.write(wu32(headerSize));
  await writable.write(END_MARKER);
  await writable.close();
  decW.kill(); encW.kill();
}

// ═══════════════════════════════════════════════════════════════════════
// PREFETCH MANAGER
// Each item gets its OWN CryptoWorker → no shared state, no races.
// Keeps window of [N-1, N, N+1, N+2] items pre-decrypted.
// ═══════════════════════════════════════════════════════════════════════
class PrefetchManager {
  constructor() { this._cache=new Map(); this._items=[]; this._pw=''; }

  setup(items, pw) { this.clearAll(); this._items=items; this._pw=pw; }

  triggerAround(center) {
    const N = this._items.length;
    const keep = new Set([center-1, center, center+1, center+2].filter(i=>i>=0&&i<N));

    // Evict items outside window
    for (const [item, st] of this._cache) {
      const idx = this._items.indexOf(item);
      if (!keep.has(idx)) {
        if (st.url) URL.revokeObjectURL(st.url);
        if (st.worker) { st.worker.kill(); }
        this._cache.delete(item);
      }
    }
    // Start new prefetches
    for (const idx of keep) {
      const item = this._items[idx];
      if (!item || this._cache.has(item) || item.size > getPreviewMax()) continue;
      this._startOne(item);
    }
    updatePrefetchStatus();
    setTimeout(renderGallery, 0); // refresh ⚡ indicators
  }

  _startOne(item) {
    const st = { url: null, worker: null, promise: null };
    st.promise = (async () => {
      const w = new CryptoWorker();
      st.worker = w;
      await w.init(this._pw, item.salt);
      const result = new Uint8Array(item.size);
      let off = 0;
      for (let ci=0; ci<item.nChunks; ci++) {
        const absOff = item.chunkOffsets[ci];
        const lb  = await readBlob(item.imageFile.slice(absOff, absOff+4));
        const eL  = ru32(lb, 0);
        const enc = await readBlob(item.imageFile.slice(absOff+4, absOff+4+eL));
        const pln = await w.dec(enc.buffer);
        result.set(new Uint8Array(pln), off); off += pln.byteLength;
      }
      await w.rst(); w.kill(); st.worker = null;
      st.url = URL.createObjectURL(new Blob([result], {type:item.mime}));
      // Refresh gallery card thumbnails now that this item is ready
      setTimeout(renderGallery, 0);
      return st.url;
    })().catch(() => null);
    this._cache.set(item, st);
  }

  isReady(idx) {
    if (idx<0||idx>=this._items.length) return false;
    const st = this._cache.get(this._items[idx]);
    return !!(st && st.url);
  }

  // Get URL — instant from cache, or wait for in-progress prefetch, or decrypt now
  async get(idx, onProgress) {
    const item = this._items[idx];
    if (!item) return null;
    if (item.size > getPreviewMax()) return null; // too large for in-browser preview

    const st = this._cache.get(item);
    if (st) {
      if (st.url) return st.url;       // ⚡ instant
      return st.promise;               // wait for ongoing prefetch
    }
    // Not cached — decrypt now with POOL (user is waiting)
    const data = await vaultDecryptFull(item, this._pw, POOL, onProgress);
    const url  = URL.createObjectURL(new Blob([data], {type:item.mime}));
    this._cache.set(item, {url, worker:null, promise:Promise.resolve(url)});
    return url;
  }

  clearAll() {
    for (const st of this._cache.values()) {
      if (st.url) URL.revokeObjectURL(st.url);
      if (st.worker) st.worker.kill();
    }
    this._cache.clear(); this._items=[]; this._pw='';
  }
}
const PM = new PrefetchManager();

// ═══════════════════════════════════════════════════════════════════════
// TOAST
// ═══════════════════════════════════════════════════════════════════════
let _tt;
function toast(msg, type='') {
  const el = document.getElementById('toast');
  el.textContent = msg; el.className = 'toast' + (type?' '+type:'');
  clearTimeout(_tt); _tt = setTimeout(() => el.classList.add('hidden'), 3500);
}

// ═══════════════════════════════════════════════════════════════════════
// UI INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════


// Tabs — with persistence across page reloads
const _TAB_KEY = 'sv-last-tab';
function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
  const btn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
  if (btn) btn.classList.add('active');
  const panel = document.getElementById('tab-' + tabName);
  if (panel) panel.classList.add('active');
  localStorage.setItem(_TAB_KEY, tabName);
}
document.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
// Restore last tab on load (DOMContentLoaded or immediately if already ready)
(function() {
  const last = localStorage.getItem(_TAB_KEY);
  if (last && document.querySelector(`.tab-btn[data-tab="${last}"]`)) switchTab(last);
})();

// Password toggles
[['hide-pw','toggle-hide-pw'],['open-pw','toggle-open-pw'],['cpw-old','toggle-cpw-old'],['cpw-new','toggle-cpw-new']].forEach(([id,btn])=>{
  const b = document.getElementById(btn);
  if (!b) return;
  b.addEventListener('click', () => {
    const el = document.getElementById(id);
    el.type = el.type==='password' ? 'text' : 'password';
    b.textContent = el.type==='password' ? '👁' : '🙈';
  });
});

// Mode cards (shared handler for both Hide and Change Password tabs)
document.querySelectorAll('.mode-card').forEach(card => {
  card.addEventListener('click', () => {
    const parent = card.closest('.mode-cards'); if (!parent) return;
    parent.querySelectorAll('.mode-card').forEach(c => c.classList.remove('active'));
    card.classList.add('active');
    card.querySelector('input[type=radio]').checked = true;
    // Hide mode
    if (document.getElementById('tab-hide').contains(card)) {
      hideMode = card.dataset.mode;
      renderOutputNames();
    }
    // Change password save mode
    if (document.getElementById('tab-changepw').contains(card)) {
      cpwSaveMode = card.dataset.mode;
      document.getElementById('cpw-output-folder-row').classList.toggle('hidden', cpwSaveMode === 'overwrite');
      document.getElementById('cpw-source-folder-row').classList.toggle('hidden', cpwSaveMode !== 'overwrite');
    }
  });
});

// Worker badge — updated by updateWorkerBadge() after CONFIG loads
document.addEventListener('DOMContentLoaded', () => {
  CONFIG = loadConfig();
  if (typeof updateWorkerBadge === 'function') updateWorkerBadge();
  if (typeof updateSkipLabels === 'function') updateSkipLabels();
  if (typeof syncSettingsUI === 'function') syncSettingsUI();
});


// ═══════════════════════════════════════════════════════════════════════
// ══ HIDE FILES ══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════
let secretFiles = [], dummyFile = null, outputDirHandle = null, hideMode = 'one-to-one';

// Pick files — REPLACE selection (fresh start)
document.getElementById('btn-pick-secret-files').addEventListener('click', () => document.getElementById('input-secret-files').click());
document.getElementById('input-secret-files').addEventListener('change', function() {
  secretFiles = []; // Replace mode: clear first
  addSecretFiles(Array.from(this.files)); this.value = '';
});

// Add More — APPEND to existing selection without clearing
document.getElementById('btn-add-more-files').addEventListener('click', () => document.getElementById('input-add-more-files').click());
document.getElementById('input-add-more-files').addEventListener('change', function() {
  const before = secretFiles.length;
  addSecretFiles(Array.from(this.files)); this.value = '';
  const added = secretFiles.length - before;
  if (added > 0) toast(`➕ Added ${added} file(s). Total: ${secretFiles.length}`, 'success');
  else toast('Those files are already in the list.', 'error');
});

// Pick folder (recursively) — always APPENDS
document.getElementById('btn-pick-secret-folder').addEventListener('click', async () => {
  try {
    const dir = await window.showDirectoryPicker({mode:'read'});
    toast('Scanning folder…');
    const files = await scanDir(dir);
    const before = secretFiles.length;
    addSecretFiles(files);
    const added = secretFiles.length - before;
    toast(`Added ${added} file(s) from "${dir.name}". Total: ${secretFiles.length}`, 'success');
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});

document.getElementById('btn-clear-secrets').addEventListener('click', () => {
  secretFiles = []; renderSecretsList(); renderOutputNames();
});

async function scanDir(dh, prefix='') {
  const out = [];
  for await (const [name, handle] of dh.entries()) {
    if (handle.kind === 'file') {
      const file = await handle.getFile();
      out.push(new File([file], name, {type:file.type, lastModified:file.lastModified}));
    } else {
      out.push(...await scanDir(handle, prefix ? prefix+'/'+name : name));
    }
  }
  return out;
}

function addSecretFiles(files) {
  files.forEach(f => { if (!secretFiles.some(x => x.name===f.name && x.size===f.size)) secretFiles.push(f); });
  renderSecretsList(); renderOutputNames();
}

function removeSecretFile(i) { secretFiles.splice(i, 1); renderSecretsList(); renderOutputNames(); }

function renderSecretsList() {
  const el = document.getElementById('secrets-list'); el.innerHTML = '';
  const sm = document.getElementById('secrets-summary');
  secretFiles.forEach((f, i) => {
    const row = document.createElement('div'); row.className = 'file-item';
    row.innerHTML = `<span class="file-icon">${getIcon(f.name)}</span><span class="file-name" title="${f.name}">${f.name}</span><span class="file-size">${fmtBytes(f.size)}</span><button class="file-remove">&#215;</button>`;
    row.querySelector('.file-remove').addEventListener('click', () => removeSecretFile(i));
    el.appendChild(row);
  });
  const total = secretFiles.reduce((s,f)=>s+f.size,0);
  sm.className = 'file-summary ok'; sm.classList.toggle('hidden', !secretFiles.length);
  sm.textContent = secretFiles.length ? `${secretFiles.length} file(s) selected · ${fmtBytes(total)} total` : '';
}

// Pick dummy cover image
document.getElementById('btn-pick-dummy').addEventListener('click', () => document.getElementById('input-dummy').click());
document.getElementById('input-dummy').addEventListener('change', function() {
  dummyFile = this.files[0] || null;
  const dn = document.getElementById('dummy-name');
  const dp = document.getElementById('dummy-preview');
  if (dummyFile) {
    dn.className = 'file-summary ok';
    dn.textContent = `✔ ${dummyFile.name}  (${fmtBytes(dummyFile.size)})`;
    dp.innerHTML = `<img src="${URL.createObjectURL(dummyFile)}" alt="cover" />`;
  } else {
    dn.className = 'file-summary hidden'; dn.textContent = '';
    dp.innerHTML = '';
  }
  renderOutputNames();
});

// Live password-match hint
document.getElementById('hide-pw-confirm').addEventListener('input', function() {
  const hint = document.getElementById('hide-pw-match');
  const pw1  = document.getElementById('hide-pw').value;
  if (!this.value) { hint.classList.add('hidden'); hint.className = 'step-inline-hint hidden'; return; }
  hint.classList.remove('hidden');
  if (this.value === pw1) {
    hint.className = 'step-inline-hint ok'; hint.textContent = '✔ Passphrases match';
  } else {
    hint.className = 'step-inline-hint err'; hint.textContent = '✖ Passphrases do not match';
  }
});


// Pick output folder
document.getElementById('btn-pick-output-folder').addEventListener('click', async () => {
  try {
    outputDirHandle = await window.showDirectoryPicker({mode:'readwrite'});
    const el = document.getElementById('output-folder-status');
    el.className = 'folder-status loaded';
    el.textContent = `✔ Output folder: "${outputDirHandle.name}"`;
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});

function renderOutputNames() {
  const section = document.getElementById('output-names-section');
  const list    = document.getElementById('output-names-list');
  if (!secretFiles.length) { section.classList.add('hidden'); return; }
  section.classList.remove('hidden'); list.innerHTML = '';
  const ext = dummyFile ? dummyFile.name.split('.').pop() : 'jpg';

  if (hideMode === 'all-in-one') {
    const row = document.createElement('div'); row.className = 'output-name-row';
    row.innerHTML = `<span class="orig-name">${secretFiles.length} files bundled together</span><span class="arrow">→</span><input class="out-name-input" data-idx="bundle" value="vault_bundle.${ext}" />`;
    list.appendChild(row); return;
  }
  secretFiles.forEach((f, i) => {
    const base = f.name.replace(/\.[^/.]+$/,'');
    const def  = hideMode==='same-dummy' ? `cover_${String(i+1).padStart(3,'0')}.${ext}` : `${base}.${ext}`;
    const row  = document.createElement('div'); row.className = 'output-name-row';
    row.innerHTML = `<span class="orig-name" title="${f.name}">${f.name}</span><span class="arrow">→</span><input class="out-name-input" data-idx="${i}" value="${def}" />`;
    list.appendChild(row);
  });
}

function getOutName(idx) {
  const el = document.querySelector(`.out-name-input[data-idx="${idx}"]`);
  return el ? (el.value.trim() || el.defaultValue) : `file_${idx}.jpg`;
}

// ── Stitch / Encrypt ─────────────────────────────────────────────────
document.getElementById('btn-stitch').addEventListener('click', async () => {
  const pw1 = document.getElementById('hide-pw').value.trim();
  const pw2 = document.getElementById('hide-pw-confirm').value.trim();
  if (!secretFiles.length)   return toast('Select at least one file to hide.', 'error');
  if (!dummyFile)             return toast('Select a dummy cover image.', 'error');
  if (!outputDirHandle)       return toast('Select an output folder.', 'error');
  if (!pw1)                   return toast('Enter a passphrase.', 'error');
  if (pw1 !== pw2)            return toast('Passphrases do not match.', 'error');
  if (pw1.length < 8)         return toast('Passphrase must be at least 8 characters.', 'error');

  const btn = document.getElementById('btn-stitch'); btn.disabled = true;
  const pArea = document.getElementById('stitch-progress'); pArea.classList.remove('hidden');
  document.getElementById('stitch-results').innerHTML = '';
  document.getElementById('encrypt-done-banner').classList.add('hidden'); // reset

  const prog    = makeProgress(document.getElementById('stitch-bar'), document.getElementById('stitch-label'));
  const dummyBuf = (await readBlob(dummyFile)).buffer;
  const batches  = hideMode==='all-in-one' ? [[...secretFiles]] : secretFiles.map(f=>[f]);
  const outNames = hideMode==='all-in-one' ? [getOutName('bundle')] : secretFiles.map((_,i)=>getOutName(i));
  let   okCount  = 0;

  for (let i=0; i<batches.length; i++) {
    const batch = batches[i], name = outNames[i];
    const total = batch.reduce((s,f)=>s+f.size,0);
    prog.start(`[${i+1}/${batches.length}] Encrypting ${name}…`);
    try {
      const outFH = await outputDirHandle.getFileHandle(name, {create:true});
      await vaultEncrypt(batch, pw1, dummyBuf, outFH, (done, tot) => {
        if (done === null) prog.finalizing();
        else               prog.update(done, tot);
      });
      addResultRow(true, `${name}  (${fmtBytes(total)})  ✔ saved to "${outputDirHandle.name}"`);
      okCount++;
    } catch(err) {
      addResultRow(false, `${name}: ${err.message}`);
    }
  }

  prog.finish(`✔ All ${batches.length} file(s) encrypted and saved!`);
  btn.disabled = false;

  // Show success banner
  if (okCount > 0) {
    const banner = document.getElementById('encrypt-done-banner');
    const text   = document.getElementById('encrypt-done-text');
    text.textContent = `✔ ${okCount} vault image${okCount!==1?'s':''} saved to "${outputDirHandle.name}". Open that folder to find your encrypted files.`;
    banner.classList.remove('hidden');
  }
  toast('Encryption complete!', 'success');
});


function addResultRow(ok, msg) {
  const d = document.createElement('div');
  d.className = 'stitch-result-item ' + (ok ? 'ok' : 'err');
  d.textContent = (ok ? '✔ ' : '✖ ') + msg;
  document.getElementById('stitch-results').appendChild(d);
}

// ═══════════════════════════════════════════════════════════════════════
// ══ OPEN VAULT ══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════
let vaultEntries=[], unlockedItems=[], filteredItems=[], vaultPw='';

// Pick single image(s)
document.getElementById('btn-open-file').addEventListener('click', async () => {
  try {
    const picks = await window.showOpenFilePicker({
      multiple: true,
      types: [{ description: 'Images', accept: {'image/*':['.jpg','.jpeg','.png']} }]
    });
    vaultEntries = picks.map(h => ({name:h.name, handle:h}));
    const vls = document.getElementById('vault-load-status');
    vls.className = 'folder-status loaded';
    if (picks.length === 1) {
      const f = await picks[0].getFile();
      vls.textContent = `✔ ${picks[0].name}  (${fmtBytes(f.size)})`;
    } else {
      vls.textContent = `✔ ${picks.length} vault images selected`;
    }
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});

// Pick entire folder
document.getElementById('btn-open-folder').addEventListener('click', async () => {
  try {
    const dir = await window.showDirectoryPicker({mode:'read'});
    vaultEntries = [];
    for await (const [name, handle] of dir.entries())
      if (handle.kind==='file' && /\.(jpg|jpeg|png)$/i.test(name))
        vaultEntries.push({name, handle});
    const vls = document.getElementById('vault-load-status');
    vls.className = 'folder-status loaded';
    vls.textContent = `✔ Vault folder: "${dir.name}" (${vaultEntries.length} image${vaultEntries.length!==1?'s':''})`;
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});

// Unlock
document.getElementById('btn-unlock').addEventListener('click', async () => {
  const pw    = document.getElementById('open-pw').value;
  const errEl = document.getElementById('unlock-error'); errEl.classList.add('hidden');
  if (!vaultEntries.length) return toast('Open a file or folder first.', 'error');
  if (!pw)                  return toast('Enter your passphrase.', 'error');

  const btn = document.getElementById('btn-unlock');
  btn.disabled = true; btn.textContent = '⏳ Reading vault…';

  const items   = [];
  let   skipped = 0;
  for (const entry of vaultEntries) {
    try {
      const file = entry.file || await entry.handle.getFile();
      const found = await vaultReadMeta(file, pw);
      items.push(...found);
    } catch {
      // Wrong password or not a vault file — silently skip this image
      skipped++;
    }
  }

  btn.disabled = false; btn.textContent = '🔓 Unlock Vault';

  if (!items.length) {
    errEl.classList.remove('hidden');
    errEl.textContent = skipped > 0
      ? `Incorrect password — none of the ${skipped} selected image(s) matched.`
      : 'No StealthVault v6 files found in the selection.';
    return;
  }

  // Some files opened, some may have been skipped (different passwords — that's fine)
  if (skipped > 0) {
    toast(`${items.length} file(s) unlocked · ${skipped} image(s) skipped (different password or not a vault).`, 'success');
  } else {
    toast(`🔓 ${items.length} file(s) unlocked.`, 'success');
  }

  vaultPw = pw; unlockedItems = items; filteredItems = [...items];
  PM.setup(unlockedItems, vaultPw);
  document.getElementById('unlock-panel').classList.add('hidden');
  document.getElementById('gallery-panel').classList.remove('hidden');
  renderGallery();
  PM.triggerAround(0);
});

// Lock vault
document.getElementById('btn-lock-vault').addEventListener('click', () => {
  PM.clearAll();
  unlockedItems=[]; filteredItems=[]; vaultEntries=[]; vaultPw='';
  closeViewer();
  // Also hide inline CPW panel and reset its state
  document.getElementById('inline-cpw-panel').classList.add('hidden');
  document.getElementById('btn-toggle-inline-cpw').classList.remove('active');
  document.getElementById('unlock-panel').classList.remove('hidden');
  document.getElementById('gallery-panel').classList.add('hidden');
  document.getElementById('file-grid').innerHTML='';
  document.getElementById('vault-load-status').textContent='';
  document.getElementById('vault-load-status').className='folder-status';
  document.getElementById('open-pw').value='';
  document.getElementById('unlock-error').classList.add('hidden');
  toast('Vault locked. Memory cleared.');
});

// ═══════════════════════════════════════════════════════════════════════
// INLINE CHANGE PASSWORD (inside Open Vault tab)
// ═══════════════════════════════════════════════════════════════════════
let inlineCpwDir = null;

document.getElementById('btn-toggle-inline-cpw').addEventListener('click', () => {
  const panel = document.getElementById('inline-cpw-panel');
  const btn   = document.getElementById('btn-toggle-inline-cpw');
  const isOpen = !panel.classList.contains('hidden');
  panel.classList.toggle('hidden', isOpen);
  btn.classList.toggle('active', !isOpen);
  if (!isOpen) {
    // Pre-fill the old-password field from current vault password
    const oldEl = document.getElementById('inline-cpw-old');
    if (oldEl && vaultPw) oldEl.value = vaultPw;
    // Show file count
    const vaultImageCount = [...new Set(unlockedItems.map(f => f.imageFile))].length;
    document.getElementById('inline-cpw-count').textContent = vaultImageCount;
  }
});

// Password show/hide toggles for inline CPW fields
[['inline-cpw-old','toggle-inline-cpw-old'],['inline-cpw-new','toggle-inline-cpw-new']].forEach(([id,btn]) => {
  const b = document.getElementById(btn); if (!b) return;
  b.addEventListener('click', () => {
    const el = document.getElementById(id);
    el.type = el.type==='password' ? 'text' : 'password';
    b.textContent = el.type==='password' ? '👁' : '🙈';
  });
});

document.getElementById('btn-inline-cpw-folder').addEventListener('click', async () => {
  try {
    inlineCpwDir = await window.showDirectoryPicker({mode:'readwrite'});
    const el = document.getElementById('inline-cpw-folder-status');
    el.className = 'folder-status loaded';
    el.textContent = `✔ "${inlineCpwDir.name}"`;
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});

document.getElementById('btn-inline-cpw-go').addEventListener('click', async () => {
  const oldPw  = document.getElementById('inline-cpw-old').value;
  const newPw  = document.getElementById('inline-cpw-new').value.trim();
  const newPw2 = document.getElementById('inline-cpw-confirm').value.trim();

  if (!oldPw)              return toast('Enter the current password.', 'error');
  if (!newPw)              return toast('Enter a new password.', 'error');
  if (newPw !== newPw2)    return toast('New passwords do not match.', 'error');
  if (newPw.length < 8)   return toast('New password must be at least 8 characters.', 'error');
  if (!inlineCpwDir)       return toast('Select an output folder first.', 'error');

  // Get the unique vault image files
  const seen    = new Set();
  const sources = [];
  for (const item of unlockedItems) {
    if (!seen.has(item.imageFile)) {
      seen.add(item.imageFile);
      sources.push({ name: item.imageFile.name, file: item.imageFile });
    }
  }

  const btn   = document.getElementById('btn-inline-cpw-go'); btn.disabled = true;
  const pArea = document.getElementById('inline-cpw-progress'); pArea.classList.remove('hidden');
  document.getElementById('inline-cpw-results').innerHTML = '';
  const prog  = makeProgress(document.getElementById('inline-cpw-bar'), document.getElementById('inline-cpw-label'));

  for (let i=0; i<sources.length; i++) {
    const src = sources[i];
    prog.start(`[${i+1}/${sources.length}] ${src.name}…`);
    try {
      const outFH = await inlineCpwDir.getFileHandle(src.name, {create:true});
      await vaultChangePassword(src.file, oldPw, newPw, outFH, (done, tot) => {
        if (done === null) prog.finalizing();
        else               prog.update(done, tot);
      });
      const row = document.createElement('div');
      row.className = 'stitch-result-item ok';
      row.textContent = `✔ ${src.name} — password changed`;
      document.getElementById('inline-cpw-results').appendChild(row);
    } catch(err) {
      const row = document.createElement('div');
      row.className = 'stitch-result-item err';
      row.textContent = `✖ ${src.name}: ${err.message}`;
      document.getElementById('inline-cpw-results').appendChild(row);
    }
  }

  prog.finish(`✔ Done — ${sources.length} vault image(s) updated. New copies saved to "${inlineCpwDir.name}".`);
  btn.disabled = false;
  toast('Password changed! Load the new copies to continue.', 'success');
  // Update vaultPw in memory so the currently-open vault still works
  vaultPw = newPw;
});


// ═══════════════════════════════════════════════════════════════════════
// GALLERY
// ═══════════════════════════════════════════════════════════════════════
let isListView = false;

document.getElementById('btn-grid-view').addEventListener('click', () => {
  isListView = false;
  document.getElementById('btn-grid-view').classList.add('active');
  document.getElementById('btn-list-view').classList.remove('active');
  document.getElementById('file-grid').classList.remove('list-view');
});
document.getElementById('btn-list-view').addEventListener('click', () => {
  isListView = true;
  document.getElementById('btn-list-view').classList.add('active');
  document.getElementById('btn-grid-view').classList.remove('active');
  document.getElementById('file-grid').classList.add('list-view');
});
document.getElementById('search-box').addEventListener('input', function() {
  filteredItems = unlockedItems.filter(f => f.name.toLowerCase().includes(this.value.toLowerCase()));
  renderGallery();
});

function renderGallery() {
  const grid = document.getElementById('file-grid'); grid.innerHTML = '';
  document.getElementById('gallery-count').textContent = `${filteredItems.length} file(s)`;
  filteredItems.forEach((f, idx) => {
    const card = document.createElement('div'); card.className = 'file-card';
    if (PM.isReady(filteredItems.indexOf(f))) card.classList.add('prefetched');
    card.addEventListener('click', () => openViewer(idx));

    const thumb = document.createElement('div'); thumb.className = 'file-card-thumb';
    // Show thumbnail for pre-decrypted images
    const st = PM._cache.get(f);
    if (isImg(f.name) && st && st.url) {
      const img = document.createElement('img'); img.src = st.url; img.alt = f.name;
      thumb.appendChild(img);
    } else {
      thumb.textContent = getIcon(f.name);
    }
    const badge = document.createElement('div'); badge.className = 'file-card-type-badge';
    badge.textContent = (f.name.split('.').pop()||'?').toUpperCase();
    const info = document.createElement('div'); info.className = 'file-card-info';
    const ready = PM.isReady(filteredItems.indexOf(f));
    info.innerHTML = `<div class="file-card-name" title="${f.name}">${f.name}</div>
      <div class="file-card-meta">${fmtBytes(f.size)}${ready?' · ⚡':''}</div>`;

    card.appendChild(thumb); card.appendChild(badge); card.appendChild(info);
    grid.appendChild(card);
  });
}

// ═══════════════════════════════════════════════════════════════════════
// VIEWER
// ═══════════════════════════════════════════════════════════════════════
let curIdx=0, activeMedia=null;

function openViewer(idx) {
  curIdx = idx;
  document.getElementById('viewer-modal').classList.remove('hidden');
  loadViewerContent();
  updateViewerNav();
  PM.triggerAround(idx);
}

function closeViewer() {
  document.getElementById('viewer-modal').classList.add('hidden');
  if (activeMedia && activeMedia.pause) activeMedia.pause();
  activeMedia = null;
  document.getElementById('viewer-content').innerHTML = '';
  document.getElementById('viewer-nav-dots').innerHTML = '';
  document.getElementById('viewer-loading').classList.add('hidden');
}

async function loadViewerContent() {
  const f = filteredItems[curIdx]; if (!f) return;
  const content = document.getElementById('viewer-content');
  const loading  = document.getElementById('viewer-loading');

  // Cancel any pending auto-next countdown
  cancelAutoNext();

  // Pause and clear previous media
  if (activeMedia && activeMedia.pause) activeMedia.pause();
  activeMedia = null; content.innerHTML = '';

  // Hide skip buttons until we know what type the file is
  setSkipBtnsActive(false);

  document.getElementById('viewer-filename').textContent = f.name;
  document.getElementById('viewer-pos').textContent = `${curIdx+1} / ${filteredItems.length}`;
  updatePrefetchStatus();

  const previewMax = getPreviewMax();

  // Show loading overlay if not already cached
  if (!PM.isReady(curIdx) && f.size <= previewMax) {
    document.getElementById('vl-icon').textContent = getIcon(f.name);
    document.getElementById('vl-name').textContent = f.name;
    const prog = makeProgress(document.getElementById('viewer-dec-bar'), document.getElementById('viewer-dec-label'));
    prog.start('Decrypting…');
    loading.classList.remove('hidden');
  }

  let url;
  try {
    url = await PM.get(curIdx, (done, total) => {
      makeProgress(document.getElementById('viewer-dec-bar'), document.getElementById('viewer-dec-label')).update(done, total);
    });
  } catch(err) {
    loading.classList.add('hidden');
    content.innerHTML = `<div class="unsupported-file"><div class="big-icon">⚠️</div><p>Decryption failed: ${err.message}</p></div>`;
    return;
  }

  loading.classList.add('hidden');

  if (!url) {
    content.innerHTML = `<div class="unsupported-file">
      <div class="big-icon">${getIcon(f.name)}</div>
      <p style="font-size:15px;font-weight:700;">${f.name}</p>
      <p style="color:var(--text2);">${fmtBytes(f.size)} — too large to preview in browser.</p>
      <p style="color:var(--text2);margin-top:8px;">Click <strong style="color:var(--accent)">Export</strong> to save the decrypted file to disk.</p>
    </div>`;
    return;
  }

  // ── Render based on file type ──
  if (isVid(f.name)) {
    // If currently fullscreen, swap the video source without exiting fullscreen
    const wasFullscreen = document.fullscreenElement;
    const v = document.createElement('video');
    v.src = url; v.controls = true;
    content.appendChild(v); activeMedia = v;
    attachVideoHandlers(v);   // auto-next when video ends
    setSkipBtnsActive(true);  // show skip buttons
    v.play().catch(() => {}); // autoplay (may be blocked, that's fine)
    // Re-enter fullscreen if we were in it (browser handles this gracefully)
    if (wasFullscreen) v.requestFullscreen().catch(() => {});

  } else if (isAud(f.name)) {
    const wrap = document.createElement('div');
    wrap.style.cssText = 'display:flex;flex-direction:column;align-items:center;width:100%;padding:20px 0;';
    const art = document.createElement('div'); art.className = 'audio-art'; art.textContent = '🎵';
    const name = document.createElement('div');
    name.style.cssText = 'font-size:15px;font-weight:700;margin-bottom:16px;';
    name.textContent = f.name;
    const a = document.createElement('audio');
    a.src = url; a.controls = true; a.style.width = 'min(500px,90%)';
    wrap.appendChild(art); wrap.appendChild(name); wrap.appendChild(a);
    content.appendChild(wrap); activeMedia = a;
    attachVideoHandlers(a);  // auto-next when audio ends
    setSkipBtnsActive(true); // audio also gets skip buttons
    a.play().catch(() => {});
    a.addEventListener('play',  () => art.classList.add('playing'));
    a.addEventListener('pause', () => art.classList.remove('playing'));

  } else if (isImg(f.name)) {
    const img = document.createElement('img'); img.src = url; img.alt = f.name;
    content.appendChild(img);
    setSkipBtnsActive(false); // no skip for images — arrows navigate instead
    setTimeout(renderGallery, 0);

  } else if (isPDF(f.name)) {
    const fr = document.createElement('iframe'); fr.src = url;
    fr.style.cssText = 'width:100%;height:calc(96vh - 240px);border:none;';
    content.appendChild(fr);

  } else if (isTxt(f.name)) {
    const text = await (await fetch(url)).text();
    const pre = document.createElement('pre'); pre.textContent = text;
    content.appendChild(pre);

  } else {
    content.innerHTML = `<div class="unsupported-file">
      <div class="big-icon">${getIcon(f.name)}</div>
      <p>${f.name}</p>
      <p style="color:var(--text2);">Cannot preview this file type. Use <strong style="color:var(--accent)">Export</strong>.</p>
    </div>`;
  }

  PM.triggerAround(curIdx);
  updatePrefetchStatus();
}


function updateViewerNav() {
  document.getElementById('btn-prev').disabled = (curIdx === 0);
  document.getElementById('btn-next').disabled = (curIdx === filteredItems.length - 1);
  const dotsEl = document.getElementById('viewer-nav-dots'); dotsEl.innerHTML = '';
  const N = filteredItems.length;
  if (N <= 24) {
    for (let i=0; i<N; i++) {
      const d = document.createElement('div');
      d.className = 'nav-dot' + (i===curIdx?' active':'') + (PM.isReady(i)?' prefetched':'');
      d.title = filteredItems[i].name + (PM.isReady(i)?' ⚡':'');
      d.addEventListener('click', () => navigateTo(i));
      dotsEl.appendChild(d);
    }
  } else {
    dotsEl.style.cssText = 'font-size:12px;color:var(--text2);font-family:var(--mono)';
    dotsEl.textContent = `${curIdx+1} of ${N}`;
  }
}

function updatePrefetchStatus() {
  const el = document.getElementById('prefetch-status'); if (!el) return;
  const parts = [];
  if (PM.isReady(curIdx+1)) parts.push('⚡ Next ready');
  else if (filteredItems[curIdx+1] && PM._cache.has(filteredItems[curIdx+1])) parts.push('⏳ Loading next…');
  if (PM.isReady(curIdx-1)) parts.push('⚡ Prev ready');
  el.textContent = parts.join(' · ');
  el.className = 'prefetch-status' + (parts.some(p=>p.startsWith('⚡'))?' ready':'');
}

function navigateTo(idx) { curIdx = idx; loadViewerContent(); updateViewerNav(); }

document.getElementById('btn-prev').addEventListener('click', () => { if (curIdx > 0) navigateTo(curIdx-1); });
document.getElementById('btn-next').addEventListener('click', () => { if (curIdx < filteredItems.length-1) navigateTo(curIdx+1); });
document.getElementById('btn-close-viewer').addEventListener('click', closeViewer);
document.getElementById('viewer-backdrop').addEventListener('click', closeViewer);

// Export (streams to disk, no RAM spike)
document.getElementById('btn-export').addEventListener('click', async () => {
  const f = filteredItems[curIdx]; if (!f) return;
  try {
    const ok = await vaultExportItem(f, vaultPw);
    if (ok) toast(`Exported: ${f.name}`, 'success');
  } catch(err) {
    document.getElementById('viewer-loading').classList.add('hidden');
    toast('Export failed: ' + err.message, 'error');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ══ CHANGE PASSWORD ══════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════
let cpwFiles=[], cpwOutputDir=null, cpwSourceDir=null, cpwSaveMode='newcopy';

document.getElementById('btn-cpw-pick-files').addEventListener('click', async () => {
  try {
    const picks = await window.showOpenFilePicker({multiple:true, types:[{description:'Images',accept:{'image/*':['.jpg','.jpeg','.png']}}]});
    cpwFiles = picks.map(h => ({name:h.name, handle:h}));
    renderCpwList();
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});
document.getElementById('btn-cpw-pick-folder').addEventListener('click', async () => {
  try {
    const dir = await window.showDirectoryPicker({mode:'read'});
    cpwFiles = [];
    for await (const [name,handle] of dir.entries())
      if (handle.kind==='file' && /\.(jpg|jpeg|png)$/i.test(name)) cpwFiles.push({name, handle});
    renderCpwList();
    toast(`Loaded ${cpwFiles.length} image(s).`, 'success');
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});
function renderCpwList() {
  const el = document.getElementById('cpw-files-list'); el.innerHTML = '';
  cpwFiles.forEach(f => {
    const row = document.createElement('div'); row.className = 'file-item';
    row.innerHTML = `<span class="file-icon">🖼️</span><span class="file-name">${f.name}</span>`;
    el.appendChild(row);
  });
}
document.getElementById('btn-cpw-output-folder').addEventListener('click', async () => {
  try {
    cpwOutputDir = await window.showDirectoryPicker({mode:'readwrite'});
    const el = document.getElementById('cpw-output-status');
    el.className='folder-status loaded'; el.textContent=`✔ "${cpwOutputDir.name}"`;
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});
document.getElementById('btn-cpw-source-folder').addEventListener('click', async () => {
  try {
    cpwSourceDir = await window.showDirectoryPicker({mode:'readwrite'});
    const el = document.getElementById('cpw-source-status');
    el.className='folder-status loaded'; el.textContent=`✔ "${cpwSourceDir.name}"`;
  } catch(e) { if (e.name!=='AbortError') toast('Error: '+e.message,'error'); }
});

document.getElementById('btn-cpw-process').addEventListener('click', async () => {
  const oldPw  = document.getElementById('cpw-old').value;
  const newPw  = document.getElementById('cpw-new').value.trim();
  const newPw2 = document.getElementById('cpw-new-confirm').value.trim();
  if (!cpwFiles.length)                         return toast('Select vault images.','error');
  if (!oldPw)                                   return toast('Enter current password.','error');
  if (!newPw)                                   return toast('Enter new password.','error');
  if (newPw !== newPw2)                         return toast('New passwords do not match.','error');
  if (newPw.length < 8)                         return toast('New password must be ≥ 8 characters.','error');
  if (cpwSaveMode==='newcopy' && !cpwOutputDir) return toast('Select an output folder.','error');
  if (cpwSaveMode==='overwrite' && !cpwSourceDir) return toast('Select the vault folder (with write access).','error');

  const btn  = document.getElementById('btn-cpw-process'); btn.disabled = true;
  const pArea= document.getElementById('cpw-progress'); pArea.classList.remove('hidden');
  document.getElementById('cpw-results').innerHTML = '';
  const prog = makeProgress(document.getElementById('cpw-bar'), document.getElementById('cpw-label'));

  for (let i=0; i<cpwFiles.length; i++) {
    const entry = cpwFiles[i];
    prog.start(`[${i+1}/${cpwFiles.length}] ${entry.name}…`);
    try {
      const imageFile = await entry.handle.getFile();
      const saveDir   = cpwSaveMode==='overwrite' ? cpwSourceDir : cpwOutputDir;
      const outFH     = await saveDir.getFileHandle(entry.name, {create:true});
      await vaultChangePassword(imageFile, oldPw, newPw, outFH, (done,tot) => prog.update(done, tot));
      addCpwResult(true, `${entry.name} — password changed ✔`);
    } catch(err) { addCpwResult(false, `${entry.name}: ${err.message}`); }
  }

  prog.finish('All done!');
  btn.disabled = false;
  toast('Password change complete!','success');
});

function addCpwResult(ok, msg) {
  const d = document.createElement('div');
  d.className = 'stitch-result-item ' + (ok?'ok':'err');
  d.textContent = (ok?'✔ ':'✖ ') + msg;
  document.getElementById('cpw-results').appendChild(d);
}


// ═══════════════════════════════════════════════════════════════════════
// SETTINGS PANEL
// ═══════════════════════════════════════════════════════════════════════

function openSettings() {
  document.getElementById('settings-overlay').classList.remove('hidden');
  document.getElementById('settings-panel').classList.add('open');
  syncSettingsUI();
}
function closeSettings() {
  document.getElementById('settings-overlay').classList.add('hidden');
  document.getElementById('settings-panel').classList.remove('open');
}

// Sync chip/toggle UI to current CONFIG values
function syncSettingsUI() {
  setActiveChip('chunk-size-chips',    String(CONFIG.chunkSizeMB));
  setActiveChip('worker-count-chips',  String(CONFIG.workerCount));
  setActiveChip('skip-seconds-chips',  String(CONFIG.skipSeconds));
  setActiveChip('autoplay-delay-chips',String(CONFIG.autoPlayDelay));
  setActiveChip('prefetch-chips',      String(CONFIG.prefetchAhead));
  setActiveChip('preview-limit-chips', String(CONFIG.previewLimitMB));
  const tog = document.getElementById('toggle-autoplay');
  if (tog) tog.checked = CONFIG.autoPlayNext;
  document.getElementById('autoplay-delay-row').style.opacity = CONFIG.autoPlayNext ? '1' : '0.4';
  updateWorkerBadge();
}

function setActiveChip(groupId, val) {
  const group = document.getElementById(groupId); if (!group) return;
  group.querySelectorAll('.chip').forEach(c => c.classList.toggle('active', c.dataset.val === val));
}

function updateWorkerBadge() {
  const b = document.getElementById('worker-badge');
  if (b) b.textContent = `${CONFIG.workerCount} workers · ${CONFIG.chunkSizeMB} MB chunks · skip ${CONFIG.skipSeconds}s`;
}

// Wire chip groups
function wireChips(groupId, configKey, transform) {
  const group = document.getElementById(groupId); if (!group) return;
  group.addEventListener('click', e => {
    const chip = e.target.closest('.chip'); if (!chip) return;
    const val = transform ? transform(chip.dataset.val) : chip.dataset.val;
    CONFIG[configKey] = val;
    saveConfig(CONFIG);
    syncSettingsUI();
    // Update skip button labels live
    updateSkipLabels();
  });
}

wireChips('chunk-size-chips',    'chunkSizeMB',   Number);
wireChips('worker-count-chips',  'workerCount',   Number);
wireChips('skip-seconds-chips',  'skipSeconds',   Number);
wireChips('autoplay-delay-chips','autoPlayDelay', Number);
wireChips('prefetch-chips',      'prefetchAhead', Number);
wireChips('preview-limit-chips', 'previewLimitMB',Number);

const togAutoplay = document.getElementById('toggle-autoplay');
if (togAutoplay) {
  togAutoplay.addEventListener('change', () => {
    CONFIG.autoPlayNext = togAutoplay.checked;
    saveConfig(CONFIG);
    syncSettingsUI();
  });
}

document.getElementById('btn-open-settings').addEventListener('click', openSettings);
document.getElementById('btn-close-settings').addEventListener('click', closeSettings);
document.getElementById('settings-overlay').addEventListener('click', closeSettings);
document.getElementById('btn-reset-settings').addEventListener('click', () => {
  CONFIG = { ...CONFIG_DEFAULTS };
  saveConfig(CONFIG);
  syncSettingsUI();
  toast('Settings reset to defaults.', 'success');
});


// ═══════════════════════════════════════════════════════════════════════
// VIDEO SKIP CONTROLS + AUTO-NEXT
// ═══════════════════════════════════════════════════════════════════════
let autoNextTimer = null;

function updateSkipLabels() {
  const s = CONFIG.skipSeconds + 's';
  const bl = document.getElementById('skip-back-label');
  const fl = document.getElementById('skip-fwd-label');
  if (bl) bl.textContent = s;
  if (fl) fl.textContent = s;
}

function setSkipBtnsActive(active) {
  ['btn-skip-back','btn-skip-fwd'].forEach(id => {
    document.getElementById(id)?.classList.toggle('inactive', !active);
  });
}

function skipMedia(dir) {
  if (!activeMedia) return;
  const t = activeMedia.currentTime + dir * CONFIG.skipSeconds;
  activeMedia.currentTime = Math.max(0, Math.min(activeMedia.duration || 0, t));
  showSkipFlash(dir);
}

// Brief flash animation when skipping
function showSkipFlash(dir) {
  const id = dir < 0 ? 'btn-skip-back' : 'btn-skip-fwd';
  const btn = document.getElementById(id); if (!btn) return;
  btn.style.color = 'var(--accent)';
  setTimeout(() => btn.style.color = '', 300);
}

// Volume HUD
let volHideTimer = null;
function showVolumeHUD(vol) {
  const bar  = document.getElementById('volume-bar');
  const fill = document.getElementById('volume-fill');
  const pct  = document.getElementById('volume-pct');
  const icon = document.getElementById('volume-icon');
  if (!bar) return;
  bar.classList.remove('hidden');
  fill.style.width = (vol * 100) + '%';
  pct.textContent  = Math.round(vol * 100) + '%';
  icon.textContent = vol === 0 ? '🔇' : vol < 0.5 ? '🔉' : '🔊';
  clearTimeout(volHideTimer);
  volHideTimer = setTimeout(() => bar.classList.add('hidden'), 1500);
}

// Auto-next countdown
function startAutoNext() {
  if (!CONFIG.autoPlayNext) return;
  const nextItem = filteredItems[curIdx + 1];
  if (!nextItem) return;

  const overlay  = document.getElementById('autonext-overlay');
  const nameEl   = document.getElementById('autonext-name');
  const countEl  = document.getElementById('autonext-countdown');
  nameEl.textContent = nextItem.name;

  let secs = CONFIG.autoPlayDelay;
  if (secs === 0) { overlay.classList.add('hidden'); navigateTo(curIdx + 1); return; }

  countEl.textContent = secs;
  overlay.classList.remove('hidden');
  clearInterval(autoNextTimer);
  autoNextTimer = setInterval(() => {
    secs--;
    countEl.textContent = secs;
    if (secs <= 0) {
      clearInterval(autoNextTimer); autoNextTimer = null;
      overlay.classList.add('hidden');
      navigateTo(curIdx + 1);
    }
  }, 1000);
}

function cancelAutoNext() {
  clearInterval(autoNextTimer); autoNextTimer = null;
  document.getElementById('autonext-overlay')?.classList.add('hidden');
}

document.getElementById('btn-autonext-cancel')?.addEventListener('click', cancelAutoNext);
document.getElementById('btn-skip-back')?.addEventListener('click', () => skipMedia(-1));
document.getElementById('btn-skip-fwd')?.addEventListener('click',  () => skipMedia(+1));

// Attach video ended handler whenever a new video is loaded
// (called from loadViewerContent after creating the <video> element)
function attachVideoHandlers(videoEl) {
  videoEl.addEventListener('ended', () => {
    cancelAutoNext();
    startAutoNext();
  });
}

// ═══════════════════════════════════════════════════════════════════════
// KEYBOARD SHORTCUTS — context-aware
// ═══════════════════════════════════════════════════════════════════════
document.addEventListener('keydown', e => {
  // Settings panel: Escape closes it
  if (!document.getElementById('settings-panel').classList.contains('open')) {
    if (e.key === 'Escape' && !document.getElementById('viewer-modal').classList.contains('hidden')) {
      closeViewer(); return;
    }
  } else {
    if (e.key === 'Escape') { closeSettings(); return; }
  }

  if (document.getElementById('viewer-modal').classList.contains('hidden')) return;
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

  const isMedia = activeMedia && (activeMedia.tagName === 'VIDEO' || activeMedia.tagName === 'AUDIO');

  switch (e.key) {
    // ── Navigation (always works regardless of media type) ──
    case 'n': case 'N':
      e.preventDefault(); cancelAutoNext(); if (curIdx < filteredItems.length-1) navigateTo(curIdx+1); break;
    case 'b': case 'B':
      e.preventDefault(); cancelAutoNext(); if (curIdx > 0) navigateTo(curIdx-1); break;

    // ── Context-aware arrows ──
    case 'ArrowLeft':
      e.preventDefault();
      if (isMedia) skipMedia(-1);                                       // skip video back
      else { cancelAutoNext(); if (curIdx>0) navigateTo(curIdx-1); }   // navigate
      break;
    case 'ArrowRight':
      e.preventDefault();
      if (isMedia) skipMedia(+1);                                              // skip video forward
      else { cancelAutoNext(); if (curIdx<filteredItems.length-1) navigateTo(curIdx+1); } // navigate
      break;

    // ── Volume (up/down arrows, only when media is active) ──
    case 'ArrowUp':
      if (isMedia) { e.preventDefault(); activeMedia.volume = Math.min(1, activeMedia.volume + 0.1); showVolumeHUD(activeMedia.volume); }
      break;
    case 'ArrowDown':
      if (isMedia) { e.preventDefault(); activeMedia.volume = Math.max(0, activeMedia.volume - 0.1); showVolumeHUD(activeMedia.volume); }
      break;

    // ── Playback ──
    case ' ': {
      if (isMedia) { e.preventDefault(); activeMedia.paused ? activeMedia.play() : activeMedia.pause(); }
      break;
    }
    case 'm': case 'M':
      if (activeMedia) { activeMedia.muted = !activeMedia.muted; showVolumeHUD(activeMedia.muted ? 0 : activeMedia.volume); }
      break;
    case 'f': case 'F': {
      if (activeMedia && activeMedia.tagName === 'VIDEO') {
        if (document.fullscreenElement) document.exitFullscreen();
        else activeMedia.requestFullscreen();
      }
      break;
    }
    case 'p': case 'P': {
      if (activeMedia && activeMedia.tagName === 'VIDEO')
        document.pictureInPictureElement
          ? document.exitPictureInPicture()
          : activeMedia.requestPictureInPicture().catch(() => toast('PiP not available.', 'error'));
      break;
    }
  }
});

// ── Fullscreen navigation fix ──
document.addEventListener('fullscreenchange', () => {
  window._svFullscreen = !!document.fullscreenElement;
});

// ═══════════════════════════════════════════════════════════════════════
// GALLERY TYPE FILTER
// ═══════════════════════════════════════════════════════════════════════
let activeTypeFilter = 'all';

function matchesTypeFilter(item, filterType) {
  switch (filterType) {
    case 'video': return isVid(item.name);
    case 'image': return isImg(item.name);
    case 'audio': return isAud(item.name);
    case 'doc':   return isPDF(item.name) || isTxt(item.name);
    default:      return true; // 'all'
  }
}

function applyFilters() {
  const searchVal = (document.getElementById('search-box')?.value || '').toLowerCase();
  filteredItems = unlockedItems.filter(f =>
    f.name.toLowerCase().includes(searchVal) && matchesTypeFilter(f, activeTypeFilter)
  );
  renderGallery();
}

// Wire type filter chips
document.getElementById('type-filter-chips')?.addEventListener('click', e => {
  const chip = e.target.closest('.type-chip'); if (!chip) return;
  document.querySelectorAll('.type-chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  activeTypeFilter = chip.dataset.type;
  applyFilters();
});

// Update search handler to use combined filter
document.getElementById('search-box').removeEventListener('input', null); // detach old handler
document.getElementById('search-box').addEventListener('input', applyFilters);

// Reset filter on vault lock
document.getElementById('btn-lock-vault').addEventListener('click', () => {
  activeTypeFilter = 'all';
  document.querySelectorAll('.type-chip').forEach((c, i) => c.classList.toggle('active', i === 0));
}, { capture: true }); // fires before the main lock handler

// ═══════════════════════════════════════════════════════════════════════
// MOBILE SWIPE GESTURES
// ═══════════════════════════════════════════════════════════════════════
(function initSwipe() {
  const container = document.getElementById('viewer-modal');
  if (!container) return;

  let touchStartX = 0, touchStartY = 0, touchStartTime = 0;
  const SWIPE_THRESHOLD  = 60;   // px to count as a swipe
  const SWIPE_MAX_TIME   = 500;  // ms — faster than this counts as a swipe
  const SWIPE_DOWN_MIN   = 80;   // px down to close viewer
  const SWIPE_RATIO      = 1.5;  // horizontal must dominate for left/right swipe

  container.addEventListener('touchstart', e => {
    if (e.touches.length !== 1) return;
    touchStartX    = e.touches[0].clientX;
    touchStartY    = e.touches[0].clientY;
    touchStartTime = Date.now();
  }, { passive: true });

  container.addEventListener('touchend', e => {
    if (e.changedTouches.length !== 1) return;
    const dx   = e.changedTouches[0].clientX - touchStartX;
    const dy   = e.changedTouches[0].clientY - touchStartY;
    const dt   = Date.now() - touchStartTime;
    const absDx = Math.abs(dx), absDy = Math.abs(dy);

    if (dt > SWIPE_MAX_TIME) return; // too slow

    // Swipe down → close viewer
    if (dy > SWIPE_DOWN_MIN && absDy > absDx) {
      closeViewer(); return;
    }

    // Horizontal swipe — only when NOT on a video (scrolling inside controls)
    const isOnVideo = e.target.closest('video') !== null;
    if (isOnVideo) return;

    if (absDx > SWIPE_THRESHOLD && absDx > absDy * SWIPE_RATIO) {
      cancelAutoNext();
      if (dx < 0) {
        // Swipe left → next
        if (curIdx < filteredItems.length - 1) navigateTo(curIdx + 1);
      } else {
        // Swipe right → prev
        if (curIdx > 0) navigateTo(curIdx - 1);
      }
    }
  }, { passive: true });
})();

// ═══════════════════════════════════════════════════════════════════════
// ENTER KEY SHORTCUTS
// ═══════════════════════════════════════════════════════════════════════
// Enter on password field triggers unlock
document.getElementById('open-pw')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('btn-unlock')?.click();
});
// Enter on hide-pw-confirm triggers encrypt
document.getElementById('hide-pw-confirm')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('btn-stitch')?.click();
});

// ═══════════════════════════════════════════════════════════════════════
// INITIALISE ON DOM READY
// ═══════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  CONFIG = loadConfig();
  syncSettingsUI();
  updateSkipLabels();
});
