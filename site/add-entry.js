"use strict";

/* Reads just enough of a vpk (a zip) to pull out sce_sys/param.sfo, without
   ever downloading the whole file: the zip's central directory sits at the
   end, so a couple of small ranged reads are enough to locate one member
   and fetch only its bytes. Works the same way whether the bytes come from
   a local File (drag-and-drop) or a remote URL (a GitHub release asset). */

class FileSource {
  constructor(file) { this.file = file; this.size = file.size; }
  async read(offset, length) {
    const end = Math.min(offset + length, this.size);
    const buf = await this.file.slice(offset, end).arrayBuffer();
    return new Uint8Array(buf);
  }
}

class UrlSource {
  constructor(url, size) { this.url = url; this.size = size; }
  static async open(url) {
    const res = await fetch(url, { method: "HEAD" });
    if (!res.ok) throw new Error(`could not reach the asset (HTTP ${res.status})`);
    const size = parseInt(res.headers.get("Content-Length") || "0", 10);
    if (!size) throw new Error("asset has no known size (missing Content-Length)");
    return new UrlSource(url, size);
  }
  async read(offset, length) {
    const end = Math.min(offset + length, this.size) - 1;
    const res = await fetch(this.url, { headers: { Range: `bytes=${offset}-${end}` } });
    if (!res.ok && res.status !== 206) throw new Error(`range request failed (HTTP ${res.status})`);
    return new Uint8Array(await res.arrayBuffer());
  }
}

const EOCD_SIG = 0x06054b50;
const CDFH_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;

async function findZipMember(source, memberNameLower) {
  const tailLen = Math.min(source.size, 65557);
  const tail = await source.read(source.size - tailLen, tailLen);
  const tailView = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);

  let eocdPos = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tailView.getUint32(i, true) === EOCD_SIG) { eocdPos = i; break; }
  }
  if (eocdPos < 0) throw new Error("not a valid zip file (no end-of-central-directory record)");

  const cdSize = tailView.getUint32(eocdPos + 12, true);
  const cdOffset = tailView.getUint32(eocdPos + 16, true);
  const tailStart = source.size - tailLen;

  let cd;
  if (cdOffset >= tailStart) {
    cd = tail.subarray(cdOffset - tailStart, cdOffset - tailStart + cdSize);
  } else {
    cd = await source.read(cdOffset, cdSize);
  }
  const cdView = new DataView(cd.buffer, cd.byteOffset, cd.byteLength);

  let pos = 0;
  while (pos + 46 <= cd.length) {
    if (cdView.getUint32(pos, true) !== CDFH_SIG) break;
    const compMethod = cdView.getUint16(pos + 10, true);
    const compSize = cdView.getUint32(pos + 20, true);
    const nameLen = cdView.getUint16(pos + 28, true);
    const extraLen = cdView.getUint16(pos + 30, true);
    const commentLen = cdView.getUint16(pos + 32, true);
    const localOffset = cdView.getUint32(pos + 42, true);
    const nameBytes = cd.subarray(pos + 46, pos + 46 + nameLen);
    const name = new TextDecoder().decode(nameBytes);

    if (name.toLowerCase().replace(/^\.\//, "") === memberNameLower) {
      const lfh = await source.read(localOffset, 30);
      const lfhView = new DataView(lfh.buffer, lfh.byteOffset, lfh.byteLength);
      if (lfhView.getUint32(0, true) !== LFH_SIG) throw new Error("corrupt zip local header");
      const lfhNameLen = lfhView.getUint16(26, true);
      const lfhExtraLen = lfhView.getUint16(28, true);
      const dataStart = localOffset + 30 + lfhNameLen + lfhExtraLen;
      const raw = await source.read(dataStart, compSize);

      if (compMethod === 0) return raw;
      if (compMethod === 8) {
        const ds = new DecompressionStream("deflate-raw");
        const decompressed = new Response(new Blob([raw]).stream().pipeThrough(ds));
        return new Uint8Array(await decompressed.arrayBuffer());
      }
      throw new Error(`unsupported zip compression method (${compMethod})`);
    }
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

/* PSF (param.sfo) format: 20-byte header, then one 16-byte index entry per
   key (name offset/type/size/data offset into two separate string/data
   tables that follow the index). Only string-typed values (type 0x02) are
   read here - titleid/title/version are all strings. */
function parseSfo(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const keys = {};
  if (bytes.length < 20 || view.getUint32(0, true) !== 0x46535000) return keys;
  const keyTableOff = view.getUint32(8, true);
  const dataTableOff = view.getUint32(12, true);
  const count = view.getUint32(16, true);
  const readCstr = (offset) => {
    let end = offset;
    while (end < bytes.length && bytes[end] !== 0) end++;
    return new TextDecoder().decode(bytes.subarray(offset, end));
  };
  for (let i = 0; i < count; i++) {
    const entryOff = 20 + i * 16;
    const nameOff = view.getUint16(entryOff, true);
    const dataType = view.getUint8(entryOff + 3);
    const dataLen = view.getUint32(entryOff + 4, true);
    const dataOff = view.getUint32(entryOff + 12, true);
    const key = readCstr(keyTableOff + nameOff);
    if (dataType === 2) {
      const start = dataTableOff + dataOff;
      keys[key] = readCstr(start > 0 ? start : 0).slice(0, dataLen);
    }
  }
  return keys;
}

async function readVpkSfo(source) {
  const wrapperSfo = await findZipMember(source, "sce_sys/param.sfo");
  if (wrapperSfo) return parseSfo(wrapperSfo);

  const names = await listZipNames(source);
  const nestedVpk = names.find((n) => n.toLowerCase().endsWith(".vpk"));
  if (!nestedVpk) throw new Error("no sce_sys/param.sfo found (not a vpk, or a wrapper zip with no nested vpk)");
  const nestedBytes = await findZipMember(source, nestedVpk.toLowerCase());
  const nestedSource = new (class {
    constructor(bytes) { this.bytes = bytes; this.size = bytes.length; }
    async read(offset, length) { return this.bytes.subarray(offset, Math.min(offset + length, this.size)); }
  })(nestedBytes);
  const innerSfo = await findZipMember(nestedSource, "sce_sys/param.sfo");
  if (!innerSfo) throw new Error("nested vpk has no sce_sys/param.sfo either");
  return parseSfo(innerSfo);
}

async function listZipNames(source) {
  const tailLen = Math.min(source.size, 65557);
  const tail = await source.read(source.size - tailLen, tailLen);
  const tailView = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);
  let eocdPos = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tailView.getUint32(i, true) === EOCD_SIG) { eocdPos = i; break; }
  }
  if (eocdPos < 0) return [];
  const cdSize = tailView.getUint32(eocdPos + 12, true);
  const cdOffset = tailView.getUint32(eocdPos + 16, true);
  const tailStart = source.size - tailLen;
  const cd = cdOffset >= tailStart
    ? tail.subarray(cdOffset - tailStart, cdOffset - tailStart + cdSize)
    : await source.read(cdOffset, cdSize);
  const cdView = new DataView(cd.buffer, cd.byteOffset, cd.byteLength);
  const names = [];
  let pos = 0;
  while (pos + 46 <= cd.length && cdView.getUint32(pos, true) === CDFH_SIG) {
    const nameLen = cdView.getUint16(pos + 28, true);
    const extraLen = cdView.getUint16(pos + 30, true);
    const commentLen = cdView.getUint16(pos + 32, true);
    names.push(new TextDecoder().decode(cd.subarray(pos + 46, pos + 46 + nameLen)));
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return names;
}

/* ---------------- GitHub glue ---------------- */

function parseRepoUrl(input) {
  const trimmed = input.trim().replace(/\.git$/, "").replace(/\/$/, "");
  const m = trimmed.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)/)
    || trimmed.match(/^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

async function fetchLatestVpkAssets(owner, repo) {
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/releases?per_page=20`);
  if (res.status === 403) throw new Error("GitHub API rate limit reached - try again in a bit");
  if (res.status === 404) throw new Error("repo not found (check spelling / it might be private)");
  if (!res.ok) throw new Error(`GitHub API error (HTTP ${res.status})`);
  const releases = await res.json();
  for (const release of releases) {
    if (release.draft || release.prerelease) continue;
    const assets = (release.assets || []).filter((a) => /\.(vpk|zip)$/i.test(a.name));
    if (assets.length) return { release, assets };
  }
  throw new Error("no release with a .vpk/.zip asset found");
}

/* ---------------- PR automation (fork + branch + commit + PR) ----------------
   Deliberately hardcoded to the test catalog, never the production one - this
   button is a shortcut for staging submissions, not for publishing for real.
   Runs entirely client-side: api.github.com sends CORS headers, so a user's
   own token (kept in memory only, never persisted) is enough to do the whole
   fork -> branch -> commit -> PR sequence straight from the browser. */

const PR_UPSTREAM_OWNER = "robin994";
const PR_UPSTREAM_REPO = "NeoVitaDB-Catalog-Test";

async function ghApi(token, method, path, body) {
  return fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function ghErrorMessage(res) {
  const body = await res.json().catch(() => ({}));
  return `HTTP ${res.status}${body.message ? ` - ${body.message}` : ""}`;
}

async function ensureFork(token, onProgress) {
  const meRes = await ghApi(token, "GET", "/user");
  if (!meRes.ok) throw new Error(`Invalid token (${await ghErrorMessage(meRes)}) - check it has "public_repo" scope (classic) or Contents + Pull requests write (fine-grained)`);
  const forkOwner = (await meRes.json()).login;

  let forkRes = await ghApi(token, "GET", `/repos/${forkOwner}/${PR_UPSTREAM_REPO}`);
  if (forkRes.status === 404) {
    onProgress(`Forking ${PR_UPSTREAM_OWNER}/${PR_UPSTREAM_REPO} to your account...`);
    const createRes = await ghApi(token, "POST", `/repos/${PR_UPSTREAM_OWNER}/${PR_UPSTREAM_REPO}/forks`, {});
    if (!createRes.ok) throw new Error(`Could not fork the repo (${await ghErrorMessage(createRes)})`);
    // Forking is async on GitHub's side - poll until the new repo actually resolves.
    for (let i = 0; i < 10 && !forkRes.ok; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      forkRes = await ghApi(token, "GET", `/repos/${forkOwner}/${PR_UPSTREAM_REPO}`);
    }
    if (!forkRes.ok) throw new Error("Fork was created but isn't ready yet - wait a few seconds and try again");
  } else if (!forkRes.ok) {
    throw new Error(`Could not check for an existing fork (${await ghErrorMessage(forkRes)})`);
  }
  return forkOwner;
}

async function createBranchFromUpstreamMain(token, forkOwner, branchName) {
  const refRes = await ghApi(token, "GET", `/repos/${PR_UPSTREAM_OWNER}/${PR_UPSTREAM_REPO}/git/refs/heads/main`);
  if (!refRes.ok) throw new Error(`Could not read upstream main (${await ghErrorMessage(refRes)})`);
  const { object } = await refRes.json();
  const createRes = await ghApi(token, "POST", `/repos/${forkOwner}/${PR_UPSTREAM_REPO}/git/refs`, {
    ref: `refs/heads/${branchName}`,
    sha: object.sha,
  });
  if (!createRes.ok) throw new Error(`Could not create a branch on your fork (${await ghErrorMessage(createRes)})`);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

async function putFileOnBranch(token, forkOwner, branchName, path, bytes, message) {
  const res = await ghApi(token, "PUT", `/repos/${forkOwner}/${PR_UPSTREAM_REPO}/contents/${path}`, {
    message,
    content: bytesToBase64(bytes),
    branch: branchName,
  });
  if (!res.ok) throw new Error(`Could not write ${path} (${await ghErrorMessage(res)})`);
}

async function openPullRequestForEntries(token, entries, onProgress) {
  if (!entries.length) throw new Error("No entries to submit");
  const forkOwner = await ensureFork(token, onProgress);
  const branchName = `add-entries-${Date.now()}`;
  onProgress(`Branching ${branchName} from upstream main...`);
  await createBranchFromUpstreamMain(token, forkOwner, branchName);

  const enc = new TextEncoder();
  let done = 0;
  const totalFiles = entries.reduce((n, e) => n + 1 + (e.iconBytes ? 1 : 0), 0);
  for (const entry of entries) {
    onProgress(`Committing ${entry.fileName} (${++done}/${totalFiles})...`);
    await putFileOnBranch(token, forkOwner, branchName, `apps/vita/${entry.fileName}`, enc.encode(entry.json), `Add ${entry.fileName}`);
    if (entry.iconBytes) {
      const iconFile = entry.fileName.replace(/\.json$/, ".png");
      onProgress(`Committing ${iconFile} (${++done}/${totalFiles})...`);
      await putFileOnBranch(token, forkOwner, branchName, `icons_vita/${iconFile}`, entry.iconBytes, `Add icon for ${entry.fileName}`);
    }
  }

  onProgress("Opening the pull request...");
  const names = entries.map((e) => JSON.parse(e.json).name);
  const prRes = await ghApi(token, "POST", `/repos/${PR_UPSTREAM_OWNER}/${PR_UPSTREAM_REPO}/pulls`, {
    title: `Add ${entries.length} homebrew ${entries.length === 1 ? "entry" : "entries"}: ${names.join(", ")}`,
    head: `${forkOwner}:${branchName}`,
    base: "main",
    body: `Opened automatically from the developer wizard.\n\nEntries:\n${names.map((n) => `- ${n}`).join("\n")}`,
  });
  if (!prRes.ok) throw new Error(`Could not open the pull request (${await ghErrorMessage(prRes)})`);
  return (await prRes.json()).html_url;
}

/* ---------------- id suggestion ---------------- */

let liveIds = new Set();
let liveCheckOk = null; // null until the first load settles
let liveIdsPromise = null;
function loadLiveIds() {
  if (!liveIdsPromise) {
    liveIdsPromise = fetch("vita.json")
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then((items) => {
        liveIds = new Set(items.map((item) => parseInt(item.id, 10)).filter((n) => !Number.isNaN(n)));
        liveCheckOk = true;
      })
      .catch(() => {
        liveIds = new Set();
        liveCheckOk = false;
      });
  }
  return liveIdsPromise;
}

function isIdTaken(id, takenElsewhere) {
  return liveIds.has(id) || Boolean(takenElsewhere && takenElsewhere.has(id));
}

async function suggestNextId(takenElsewhere) {
  await loadLiveIds();
  let candidate = 1;
  while (isIdTaken(candidate, takenElsewhere)) candidate++;
  return candidate;
}

/* ---------------- entry drafting ---------------- */

function slugify(name) {
  return (name || "my-homebrew").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "app";
}

function defaultDescription(sourceLabel) {
  return sourceLabel ? `Imported from ${sourceLabel}. Describe what it does here.` : "What it does, in a couple of sentences.";
}

function buildEntryObject({ id, sfo, repo, asset, directUrl, directAuthor, directVersion, sourceLabel, aiUsed, description }) {
  const name = sfo.TITLE || "My Homebrew";
  const titleid = sfo.TITLE_ID || "MYHB00001";
  const slug = slugify(name);
  const paddedId = String(id).padStart(4, "0");
  return {
    id,
    name,
    author: repo ? repo.owner : (directAuthor || "Your Name"),
    category: "game",
    platform: "vita",
    titleid,
    ...(repo
      ? { repo: `${repo.owner}/${repo.repo}`, asset: asset || "*.vpk" }
      : { direct_url: directUrl || "https://.../your-file.vpk", version: directVersion || sfo.APP_VER || "v.1.0" }),
    prerelease: false,
    icon: `${paddedId}-${slug}.png`,
    description: description || defaultDescription(sourceLabel),
    requirements: "",
    screenshots: [],
    trophies: false,
    ai: Boolean(aiUsed),
  };
}

function draftEntry(fields) {
  return JSON.stringify(buildEntryObject(fields), null, 2);
}

/* ---------------- zip writing (for the final downloadable package) ----------------
   Every file is stored uncompressed - these are a handful of small json/png
   files, not worth the code to deflate them - but a correct CRC32 is still
   required by the zip format for tools that verify it (macOS Archive
   Utility does). */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
  const time = ((date.getHours() & 0x1f) << 11) | ((date.getMinutes() & 0x3f) << 5) | (Math.floor(date.getSeconds() / 2) & 0x1f);
  const day = (((date.getFullYear() - 1980) & 0x7f) << 9) | (((date.getMonth() + 1) & 0xf) << 5) | (date.getDate() & 0x1f);
  return { time, day };
}

function buildZip(files) {
  const encoder = new TextEncoder();
  const { time, day } = dosDateTime(new Date());
  const parts = [];
  const central = [];
  let offset = 0;

  for (const file of files) {
    const nameBytes = encoder.encode(file.name);
    const crc = crc32(file.data);
    const size = file.data.length;

    const lfh = new DataView(new ArrayBuffer(30));
    lfh.setUint32(0, 0x04034b50, true);
    lfh.setUint16(4, 20, true);
    lfh.setUint16(6, 0, true);
    lfh.setUint16(8, 0, true);
    lfh.setUint16(10, time, true);
    lfh.setUint16(12, day, true);
    lfh.setUint32(14, crc, true);
    lfh.setUint32(18, size, true);
    lfh.setUint32(22, size, true);
    lfh.setUint16(26, nameBytes.length, true);
    lfh.setUint16(28, 0, true);
    parts.push(new Uint8Array(lfh.buffer), nameBytes, file.data);

    const cdh = new DataView(new ArrayBuffer(46));
    cdh.setUint32(0, 0x02014b50, true);
    cdh.setUint16(4, 20, true);
    cdh.setUint16(6, 20, true);
    cdh.setUint16(8, 0, true);
    cdh.setUint16(10, 0, true);
    cdh.setUint16(12, time, true);
    cdh.setUint16(14, day, true);
    cdh.setUint32(16, crc, true);
    cdh.setUint32(20, size, true);
    cdh.setUint32(24, size, true);
    cdh.setUint16(28, nameBytes.length, true);
    cdh.setUint16(30, 0, true);
    cdh.setUint16(32, 0, true);
    cdh.setUint16(34, 0, true);
    cdh.setUint16(36, 0, true);
    cdh.setUint32(38, 0, true);
    cdh.setUint32(42, offset, true);
    central.push(new Uint8Array(cdh.buffer), nameBytes);

    offset += 30 + nameBytes.length + size;
  }

  const centralStart = offset;
  const centralSize = central.reduce((sum, c) => sum + c.length, 0);

  const eocd = new DataView(new ArrayBuffer(22));
  eocd.setUint32(0, 0x06054b50, true);
  eocd.setUint16(8, files.length, true);
  eocd.setUint16(10, files.length, true);
  eocd.setUint32(12, centralSize, true);
  eocd.setUint32(16, centralStart, true);

  return new Blob([...parts, ...central, new Uint8Array(eocd.buffer)], { type: "application/zip" });
}

/* ---------------- icon validation ---------------- */

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

async function readIcon(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const isPng = PNG_SIGNATURE.every((b, i) => bytes[i] === b);
  if (!isPng) throw new Error("that's not a PNG file");
  let width = null, height = null;
  try {
    const bitmap = await createImageBitmap(new Blob([bytes]));
    width = bitmap.width;
    height = bitmap.height;
    bitmap.close?.();
  } catch (_) { /* dimension check is best-effort */ }
  return { bytes, width, height };
}

/* ---------------- wizard UI ---------------- */

(function () {
  if (typeof document === "undefined") return;
  const $ = (id) => document.getElementById(id);
  const panels = document.querySelectorAll(".wizard-panel");
  const tabs = document.querySelectorAll(".wizard-step-tab");
  if (!panels.length) return;

  const statusEl = $("generator-status");
  function setStatus(message, isError) {
    statusEl.hidden = !message;
    statusEl.textContent = message || "";
    statusEl.classList.toggle("generator-status-error", Boolean(isError));
  }

  function showPanel(name) {
    panels.forEach((panel) => { panel.hidden = panel.dataset.panel !== name; });
    tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.step === name));
    // Only worth offering once there's an existing list to cancel back to -
    // the very first entry has nowhere to return to.
    $("w-cancel").hidden = name === "continue" || session.entries.length === 0;
    setStatus("");
  }

  // Rebuilt fresh for every entry; carried across the repo -> vpk -> icon
  // steps, then pushed into `session.entries` once confirmed.
  let current = { repo: null, asset: null, sfo: {}, icon: null, directUrl: null, directAuthor: null, directVersion: null };
  const session = { entries: [], usedIds: new Set() };

  function resetCurrent() {
    current = { repo: null, asset: null, sfo: {}, icon: null, directUrl: null, directAuthor: null, directVersion: null };
    $("w-repo-url").value = "";
    $("w-repo-next").textContent = "Look up latest release";
    $("w-direct-fields").hidden = true;
    $("w-direct-author").value = "";
    $("w-direct-version").value = "";
    $("w-icon-preview").hidden = true;
    $("w-icon-preview").removeAttribute("src");
    $("w-icon-label").textContent = "Drop a .png here, or click to choose one";
  }

  /* ---- step 1: repo (GitHub) or direct external link ---- */
  // A URL pointing at one specific file (path ends in .vpk/.zip, e.g. a
  // /releases/download/TAG/NAME.vpk link) pins that exact asset - treat it as
  // a direct link even when the host is github.com. Resolving it as "look up
  // this repo's latest release" is wrong whenever the repo isn't the
  // homebrew's own repo (a multi-game mirror repo, a fork's release page,
  // etc): the latest release there can be a different, unrelated game.
  function isSpecificAssetUrl(raw) {
    return /\.(vpk|zip)(?:[?#].*)?$/i.test(raw);
  }

  async function handleRepoNext() {
    const raw = $("w-repo-url").value.trim();
    const parsed = !isSpecificAssetUrl(raw) && parseRepoUrl(raw);

    if (parsed) {
      $("w-direct-fields").hidden = true;
      setStatus(`Looking up ${parsed.owner}/${parsed.repo} releases...`);
      try {
        const { assets } = await fetchLatestVpkAssets(parsed.owner, parsed.repo);
        const vpkAssets = assets.filter((a) => /\.vpk$/i.test(a.name));
        const chosen = (vpkAssets.length ? vpkAssets : assets)[0];
        current.repo = parsed;
        current.asset = vpkAssets.length === 1 ? "*.vpk" : chosen.name;
        current.directUrl = null;
        current.directAuthor = null;
        current.directVersion = null;

        // Works from any origin only sometimes (GitHub doesn't send CORS
        // headers for release-asset bytes) - try, but the vpk step covers it
        // either way, so a failure here is silent and not an error state.
        try {
          const source = await UrlSource.open(chosen.browser_download_url);
          const sfo = await readVpkSfo(source);
          if (sfo.TITLE_ID) current.sfo = sfo;
        } catch (_) { /* expected most of the time - see the vpk step */ }

        setStatus(current.sfo.TITLE_ID
          ? `Got ${chosen.name} - title id read directly. Confirm with the vpk below, or skip ahead.`
          : `Found ${chosen.name}. Drop it (or any Vita vpk) in the next step to read its title id.`);
        $("w-vpk-hint-name").textContent = chosen.name;
        showPanel("vpk");
      } catch (error) {
        setStatus(error.message || "Could not analyze this repo", true);
      }
      return;
    }

    if (!/^https?:\/\//i.test(raw)) {
      setStatus("That doesn't look like a GitHub repo (owner/repo) or a direct .vpk link", true);
      return;
    }

    // A direct link to one specific file - either not on GitHub at all, or a
    // GitHub URL that already names an exact asset. Either way there's no
    // "look up the latest release" to lean on, so verify the link actually
    // points at a downloadable vpk, then ask for the owner/version through
    // the form below instead of assuming them.
    current.repo = null;
    current.asset = null;
    setStatus(`Verifying ${raw} is a downloadable vpk...`);
    try {
      const source = await UrlSource.open(raw);
      const sfo = await readVpkSfo(source);
      if (!sfo.TITLE_ID) throw new Error("param.sfo found, but it has no TITLE_ID");
      current.sfo = sfo;
      current.directUrl = raw;
      $("w-direct-version").value = sfo.APP_VER || "";
      $("w-direct-fields").hidden = false;
      $("w-direct-author").focus();
      setStatus(`Verified ${sfo.TITLE || "vpk"} (${sfo.TITLE_ID}). Fill in the author (and version, if not already right) below.`);
    } catch (error) {
      setStatus(`${error.message || "Could not verify this link"} - some hosts block direct downloads from a browser (CORS). Use "Skip" below and drop the .vpk file by hand instead.`, true);
    }
  }

  function handleDirectNext() {
    const author = $("w-direct-author").value.trim();
    if (!author) { setStatus("Enter an author name first", true); return; }
    current.directAuthor = author;
    // Leave unset rather than defaulting to "v.1.0" here: when verification
    // never ran (the Skip path), the real version usually isn't known yet -
    // it shows up once a vpk is dropped in the next step - so buildEntryObject's
    // own sfo.APP_VER fallback needs the chance to win instead of this
    // already having claimed a value.
    current.directVersion = $("w-direct-version").value.trim() || null;
    setStatus("");
    $("w-vpk-hint-name").textContent = (current.directUrl && current.directUrl.split("/").pop()) || ".vpk";
    showPanel("vpk");
  }

  /* ---- step 2: vpk ---- */
  async function handleVpkFile(file) {
    if (!file) return;
    setStatus(`Reading ${file.name}...`);
    try {
      const source = new FileSource(file);
      const sfo = await readVpkSfo(source);
      if (!sfo.TITLE_ID) throw new Error("param.sfo found, but it has no TITLE_ID");
      current.sfo = sfo;
      setStatus("");
      showPanel("icon");
    } catch (error) {
      setStatus(error.message || "Could not read this file", true);
    }
  }

  /* ---- step 3: icon ---- */
  async function handleIconFile(file) {
    if (!file) return;
    setStatus(`Checking ${file.name}...`);
    try {
      const icon = await readIcon(file);
      current.icon = icon;
      const preview = $("w-icon-preview");
      preview.src = URL.createObjectURL(new Blob([icon.bytes], { type: "image/png" }));
      preview.hidden = false;
      $("w-icon-label").textContent = file.name;
      setStatus(icon.width && icon.width !== 128 || icon.height && icon.height !== 128
        ? `${file.name} is ${icon.width}x${icon.height} - the convention is 128x128, but this will still work.`
        : "");
      goToReview();
    } catch (error) {
      setStatus(error.message || "Could not read this image", true);
    }
  }

  /* ---- step 4: review ---- */
  async function goToReview() {
    $("w-custom-id").checked = false;
    $("w-id").disabled = true;
    $("w-ai").checked = false;
    $("w-needs-data").checked = false;
    $("w-data-fields").hidden = true;
    $("w-data-desc").value = "";
    $("w-data-url").value = "";
    $("w-needs-plugin").checked = false;
    $("w-plugin-fields").hidden = true;
    $("w-plugin-list").value = "";

    const sourceLabel = current.repo
      ? `${current.repo.owner}/${current.repo.repo}`
      : (current.directAuthor || current.sfo.TITLE || "a local vpk");
    $("w-description").value = defaultDescription(sourceLabel);

    const suggested = await suggestNextId(session.usedIds);
    $("w-id").value = suggested;
    setStatus(liveCheckOk === false
      ? "Could not load the live catalog (vita.json) to check used ids - the id below is only checked against this session. Tick \"custom id\" if you want to enter one you've verified yourself."
      : "");
    refreshDraftText(sourceLabel);
    checkIdAvailability();
    showPanel("review");
  }

  function refreshDraftText(sourceLabel) {
    $("generator-json").value = draftEntry({
      id: parseInt($("w-id").value, 10) || $("w-id").value,
      sfo: current.sfo,
      repo: current.repo,
      asset: current.asset,
      directUrl: current.directUrl,
      directAuthor: current.directAuthor,
      directVersion: current.directVersion,
      sourceLabel,
      aiUsed: $("w-ai").checked,
      description: $("w-description").value,
    });
  }

  function checkIdAvailability() {
    const id = parseInt($("w-id").value, 10);
    const statusSpan = $("w-id-status");
    if (!id) { statusSpan.textContent = ""; return true; }
    const taken = isIdTaken(id, session.usedIds);
    statusSpan.textContent = taken ? "already taken" : "";
    statusSpan.classList.toggle("wizard-id-taken", taken);
    return !taken;
  }

  // Parses the textarea, lets the caller mutate just the fields it cares
  // about, and re-serializes - safe for multi-line/quoted text (unlike a
  // regex replace) and leaves every other manual edit in the textarea alone.
  function patchJson(mutate) {
    let obj;
    try {
      obj = JSON.parse($("generator-json").value);
    } catch (_) {
      return; // the user broke the JSON by hand - don't clobber their edit
    }
    mutate(obj);
    $("generator-json").value = JSON.stringify(obj, null, 2);
  }

  function handleIdInput() {
    const id = parseInt($("w-id").value, 10);
    if (id) {
      const padded = String(id).padStart(4, "0");
      patchJson((obj) => {
        const slug = (obj.icon || "").replace(/^\d{4}-/, "");
        obj.id = id;
        obj.icon = `${padded}-${slug}`;
      });
    }
    checkIdAvailability();
  }

  async function handleCustomIdToggle() {
    const enabled = $("w-custom-id").checked;
    $("w-id").disabled = !enabled;
    if (!enabled) {
      const suggested = await suggestNextId(session.usedIds);
      $("w-id").value = suggested;
      handleIdInput();
    }
  }

  function handleAiToggle() {
    patchJson((obj) => { obj.ai = $("w-ai").checked; });
  }

  function handleDescriptionInput() {
    patchJson((obj) => { obj.description = $("w-description").value; });
  }

  function buildRequirementsText() {
    const parts = [];
    if ($("w-needs-data").checked) {
      const desc = $("w-data-desc").value.trim();
      parts.push(desc ? `- Game data required: ${desc}` : "- Game data required");
    }
    if ($("w-needs-plugin").checked) {
      const plugins = $("w-plugin-list").value.trim();
      parts.push(plugins ? `- Plugin(s) required: ${plugins}` : "- Plugin(s) required");
    }
    return parts.join("\n");
  }

  function handleRequirementsChange() {
    patchJson((obj) => {
      obj.requirements = buildRequirementsText();
      const url = $("w-needs-data").checked ? $("w-data-url").value.trim() : "";
      if (url) obj.data = url; else delete obj.data;
    });
  }

  function addEntry() {
    let parsed;
    try {
      parsed = JSON.parse($("generator-json").value);
    } catch (_) {
      setStatus("The draft isn't valid JSON - fix it before adding this entry", true);
      return;
    }
    const id = parseInt(parsed.id, 10);
    if (!id) { setStatus("Set a valid numeric id first", true); return; }
    if (isIdTaken(id, session.usedIds)) { setStatus(`id ${id} is already taken (live catalog or this session)`, true); return; }

    session.usedIds.add(id);
    session.entries.push({
      id,
      json: JSON.stringify(parsed, null, 2),
      iconBytes: current.icon ? current.icon.bytes : null,
      iconName: parsed.icon,
      fileName: `${String(id).padStart(4, "0")}-${slugify(parsed.name)}.json`,
    });
    renderEntriesList();
    resetCurrent();
    showPanel("continue");
  }

  function removeEntry(index) {
    const [removed] = session.entries.splice(index, 1);
    session.usedIds.delete(removed.id);
    renderEntriesList();
  }

  function renderEntriesList() {
    const list = $("w-entries-list");
    $("w-count").textContent = session.entries.length;
    list.innerHTML = session.entries.map((e, i) => `<li>
      <span>${e.fileName}${e.iconBytes ? "" : " <span class=\"wizard-no-icon\">(no icon)</span>"}</span>
      <button type="button" class="wizard-remove-entry" data-index="${i}" aria-label="Remove ${e.fileName}">&times;</button>
    </li>`).join("");
    list.querySelectorAll(".wizard-remove-entry").forEach((btn) => {
      btn.addEventListener("click", () => removeEntry(parseInt(btn.dataset.index, 10)));
    });
    $("w-download").disabled = session.entries.length === 0;
  }

  function cancelToList() {
    resetCurrent();
    showPanel("continue");
  }

  function downloadPackage() {
    const files = [];
    for (const entry of session.entries) {
      files.push({ name: `apps/vita/${entry.fileName}`, data: new TextEncoder().encode(entry.json) });
      if (entry.iconBytes) {
        const iconFile = entry.fileName.replace(/\.json$/, ".png");
        files.push({ name: `icons_vita/${iconFile}`, data: entry.iconBytes });
      }
    }
    const blob = buildZip(files);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "neovitadb-entries.zip";
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleOpenPr() {
    const token = $("w-gh-token").value.trim();
    if (!token) { setStatus("Paste a GitHub token first", true); return; }
    const prStatus = $("w-pr-status");
    prStatus.hidden = false;
    prStatus.classList.remove("generator-status-error");
    $("w-open-pr").disabled = true;
    try {
      const url = await openPullRequestForEntries(token, session.entries, (msg) => { prStatus.textContent = msg; });
      prStatus.innerHTML = `Pull request opened: <a href="${url}" target="_blank" rel="noopener">${url}</a>`;
    } catch (error) {
      prStatus.textContent = error.message || "Could not open the pull request";
      prStatus.classList.add("generator-status-error");
    } finally {
      $("w-open-pr").disabled = false;
    }
  }

  /* ---- wiring ---- */
  $("w-repo-next").addEventListener("click", handleRepoNext);
  $("w-repo-url").addEventListener("keydown", (event) => { if (event.key === "Enter") handleRepoNext(); });
  $("w-repo-url").addEventListener("input", () => {
    const raw = $("w-repo-url").value.trim();
    const isRepoRef = raw && !isSpecificAssetUrl(raw) && parseRepoUrl(raw);
    $("w-repo-next").textContent = raw && !isRepoRef ? "Verify link" : "Look up latest release";
    $("w-direct-fields").hidden = true;
  });
  $("w-direct-next").addEventListener("click", handleDirectNext);
  $("w-direct-author").addEventListener("keydown", (event) => { if (event.key === "Enter") handleDirectNext(); });
  $("w-direct-version").addEventListener("keydown", (event) => { if (event.key === "Enter") handleDirectNext(); });
  $("w-repo-skip").addEventListener("click", () => {
    current.repo = null;
    current.asset = null;
    // Keep whatever was typed if it's already a URL (e.g. a GitHub release
    // asset link that failed verification because that host doesn't send
    // CORS headers) - no reason to make the user re-paste it into the JSON
    // by hand just because we couldn't fetch it ourselves.
    const raw = $("w-repo-url").value.trim();
    current.directUrl = /^https?:\/\//i.test(raw) ? raw : null;
    // Same form as a verified direct link, just without the vpk download to
    // back it up - author still has to come from somewhere other than a
    // "Your Name" placeholder nobody remembers to replace.
    $("w-direct-version").value = current.sfo.APP_VER || "";
    $("w-direct-fields").hidden = false;
    $("w-direct-author").focus();
    setStatus(current.directUrl
      ? "Couldn't verify that link automatically - fill in the author (and version, if not already right) below, then continue."
      : "Fill in the author (and version, if you know it) below, then continue - repo/asset can still be set by hand afterwards in the JSON.");
  });

  const vpkZone = $("w-dropzone-vpk"), vpkInput = $("w-vpk-file");
  vpkZone.addEventListener("click", () => vpkInput.click());
  vpkZone.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); vpkInput.click(); } });
  vpkInput.addEventListener("change", () => handleVpkFile(vpkInput.files[0]));
  ["dragenter", "dragover"].forEach((n) => vpkZone.addEventListener(n, (e) => { e.preventDefault(); vpkZone.classList.add("dropzone-active"); }));
  ["dragleave", "drop"].forEach((n) => vpkZone.addEventListener(n, (e) => { e.preventDefault(); vpkZone.classList.remove("dropzone-active"); }));
  vpkZone.addEventListener("drop", (event) => handleVpkFile(event.dataTransfer.files[0]));
  $("w-vpk-back").addEventListener("click", () => showPanel("repo"));

  const iconZone = $("w-dropzone-icon"), iconInput = $("w-icon-file");
  iconZone.addEventListener("click", () => iconInput.click());
  iconZone.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); iconInput.click(); } });
  iconInput.addEventListener("change", () => handleIconFile(iconInput.files[0]));
  ["dragenter", "dragover"].forEach((n) => iconZone.addEventListener(n, (e) => { e.preventDefault(); iconZone.classList.add("dropzone-active"); }));
  ["dragleave", "drop"].forEach((n) => iconZone.addEventListener(n, (e) => { e.preventDefault(); iconZone.classList.remove("dropzone-active"); }));
  iconZone.addEventListener("drop", (event) => handleIconFile(event.dataTransfer.files[0]));
  $("w-icon-back").addEventListener("click", () => showPanel("vpk"));
  $("w-icon-skip").addEventListener("click", () => { current.icon = null; goToReview(); });

  $("w-id").addEventListener("input", handleIdInput);
  $("w-custom-id").addEventListener("change", handleCustomIdToggle);
  $("w-ai").addEventListener("change", handleAiToggle);
  $("w-description").addEventListener("input", handleDescriptionInput);

  $("w-needs-data").addEventListener("change", () => {
    $("w-data-fields").hidden = !$("w-needs-data").checked;
    handleRequirementsChange();
  });
  $("w-data-desc").addEventListener("input", handleRequirementsChange);
  $("w-data-url").addEventListener("input", handleRequirementsChange);
  $("w-needs-plugin").addEventListener("change", () => {
    $("w-plugin-fields").hidden = !$("w-needs-plugin").checked;
    handleRequirementsChange();
  });
  $("w-plugin-list").addEventListener("input", handleRequirementsChange);

  $("w-add-entry").addEventListener("click", addEntry);
  $("generator-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("generator-json").value);
      const btn = $("generator-copy");
      const original = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = original; }, 1400);
    } catch (_) {
      $("generator-json").select();
    }
  });

  $("w-add-more").addEventListener("click", () => { resetCurrent(); showPanel("repo"); });
  $("w-download").addEventListener("click", downloadPackage);
  $("w-open-pr").addEventListener("click", handleOpenPr);
  $("w-cancel").addEventListener("click", cancelToList);

  loadLiveIds();
  showPanel("repo");
})();
