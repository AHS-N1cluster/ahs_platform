/* AHS platform encryption helpers, shared by the login page (loader), sw.js and the decrypted pages.
   Nothing here is secret: the keys only exist after a correct password, and are kept in IndexedDB. */
(function (g) {
  var enc = new TextEncoder(), dec = new TextDecoder();
  var MAGIC = [65, 72, 83, 69, 1]; // "AHSE" v1
  var TYPES = {jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', svg: 'image/svg+xml', pdf: 'application/pdf'};
  var ASSET_RE = /(^|\/)(images|reports)\//;

  function b64d(s) {
    var bin = atob(String(s).replace(/\s+/g, '')), u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
  function shaHex(s) { return crypto.subtle.digest('SHA-256', enc.encode(s)).then(hex); }

  function isSealed(u) { for (var i = 0; i < MAGIC.length; i++) if (u[i] !== MAGIC[i]) return false; return true; }
  function parts(u) {
    var n = u[MAGIC.length], p = MAGIC.length + 1;
    var name = dec.decode(u.subarray(p, p + n)); p += n;
    return {name: name, iv: u.subarray(p, p + 12), ct: u.subarray(p + 12)};
  }
  function keyNameOf(u) { return isSealed(u) ? parts(u).name : null; }
  function openSealed(u, key) {
    var x = parts(u);
    return crypto.subtle.decrypt({name: 'AES-GCM', iv: x.iv, additionalData: enc.encode(x.name)}, key, x.ct).then(function (b) { return new Uint8Array(b); });
  }

  /* password -> every key it opens: {hash, keys: {name: {key, slot}}} */
  async function unlockRing(ring, password) {
    var h = await shaHex(String(password).trim());
    var base = await crypto.subtle.importKey('raw', enc.encode(h), 'PBKDF2', false, ['deriveKey']);
    var kek = await crypto.subtle.deriveKey({name: 'PBKDF2', salt: b64d(ring.salt), iterations: ring.iter, hash: 'SHA-256'},
      base, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
    var out = {};
    for (var name in ring.keys) {
      var slots = ring.keys[name];
      for (var i = 0; i < slots.length; i++) {
        try {
          var raw = await crypto.subtle.decrypt({name: 'AES-GCM', iv: b64d(slots[i].iv), additionalData: enc.encode(name)}, kek, b64d(slots[i].ct));
          out[name] = {key: await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']), slot: slots[i].id};
          break;
        } catch (e) {}
      }
    }
    return {hash: h, keys: out};
  }

  /* IndexedDB: unlocked keys (non-extractable) so the service worker can use them */
  function db() {
    return new Promise(function (res, rej) {
      var r = indexedDB.open('ahs-sec', 1);
      r.onupgradeneeded = function () { r.result.createObjectStore('keys'); };
      r.onsuccess = function () { res(r.result); };
      r.onerror = function () { rej(r.error); };
    });
  }
  function tx(mode, fn) {
    return db().then(function (d) {
      return new Promise(function (res, rej) {
        var t = d.transaction('keys', mode), st = t.objectStore('keys'), out = fn(st);
        t.oncomplete = function () { d.close(); res(out && 'result' in out ? out.result : undefined); };
        t.onerror = t.onabort = function () { d.close(); rej(t.error); };
      });
    });
  }
  function getKey(name) { return tx('readonly', function (st) { return st.get(name); }).then(function (r) { return r || null; }); }
  function putKeys(map) { return tx('readwrite', function (st) { for (var n in map) st.put(map[n], n); }); }
  function delKey(name) { return tx('readwrite', function (st) { st.delete(name); }); }
  function clearKeys() { return tx('readwrite', function (st) { st.clear(); }); }

  function typeOf(path) { var m = /\.([a-z0-9]+)(?:[?#]|$)/i.exec(path); return (m && TYPES[m[1].toLowerCase()]) || 'application/octet-stream'; }

  /* Used only when no service worker controls the page: decrypt images and report links in place. */
  async function patchAssets() {
    var rec = await getKey('assets').catch(function () { return null; });
    if (!rec) return;
    var cache = new Map();
    var need = function (u) { return u && ASSET_RE.test(u) && !/^(blob|data):/.test(u); };
    function blobUrl(u) {
      if (!cache.has(u)) cache.set(u, fetch(u).then(function (r) { return r.arrayBuffer(); }).then(function (b) {
        var bytes = new Uint8Array(b);
        return isSealed(bytes) ? openSealed(bytes, rec.key) : bytes;
      }).then(function (plain) { return URL.createObjectURL(new Blob([plain], {type: typeOf(u)})); }));
      return cache.get(u);
    }
    function fix(img) {
      var s = img.getAttribute('src');
      if (need(s)) blobUrl(s).then(function (b) { if (img.getAttribute('src') === s) img.src = b; }).catch(function () {});
    }
    document.querySelectorAll('img').forEach(fix);
    new MutationObserver(function (ms) {
      ms.forEach(function (m) {
        if (m.type === 'attributes') { if (m.target.tagName === 'IMG') fix(m.target); return; }
        m.addedNodes.forEach(function (n) {
          if (n.nodeType !== 1) return;
          if (n.tagName === 'IMG') fix(n);
          if (n.querySelectorAll) n.querySelectorAll('img').forEach(fix);
        });
      });
    }).observe(document.documentElement, {subtree: true, childList: true, attributes: true, attributeFilter: ['src']});
    var openUrl = function (h) { var w = window.open('', '_blank'); blobUrl(h).then(function (b) { if (w) w.location = b; else location.href = b; }); };
    document.addEventListener('click', function (e) {
      var a = e.target.closest && e.target.closest('a[href]');
      if (!a || !need(a.getAttribute('href'))) return;
      e.preventDefault(); e.stopPropagation(); openUrl(a.getAttribute('href'));
    }, true);
    var wo = window.open;
    window.open = function (u) { if (typeof u === 'string' && need(u)) { var w = wo.call(window, '', '_blank'); blobUrl(u).then(function (b) { if (w) w.location = b; }); return w; } return wo.apply(window, arguments); };
  }

  /* Script placed at the top of every decrypted page */
  var HEAD_HOOK = '<script src="sec-core.js"></script><script>(function(){' +
    'try{sessionStorage.removeItem("ahs_sw_reload")}catch(e){}' +
    'var K={"n1cluster_gate_v3":1,"ahs_dept_key":1},o=Storage.prototype.removeItem;' +
    'Storage.prototype.removeItem=function(k){if(K[k]&&self.AHSSec)AHSSec.clearKeys().catch(function(){});return o.apply(this,arguments)};' +
    'window.ahsLockAll=function(){try{localStorage.removeItem("n1cluster_gate_v3");localStorage.removeItem("ahs_dept_key")}catch(e){}AHSSec.clearKeys().then(function(){location.reload()},function(){location.reload()})};' +
    'if(!(navigator.serviceWorker&&navigator.serviceWorker.controller))AHSSec.patchAssets();' +
    '})();</script>';
  function injectHead(html) {
    var m = /<head[^>]*>/i.exec(html);
    return m ? html.slice(0, m.index + m[0].length) + HEAD_HOOK + html.slice(m.index + m[0].length) : HEAD_HOOK + html;
  }

  g.AHSSec = {b64d: b64d, shaHex: shaHex, isSealed: isSealed, keyNameOf: keyNameOf, openSealed: openSealed, unlockRing: unlockRing,
    getKey: getKey, putKeys: putKeys, delKey: delKey, clearKeys: clearKeys, typeOf: typeOf, patchAssets: patchAssets,
    injectHead: injectHead, decode: function (u) { return dec.decode(u); }, ASSET_RE: ASSET_RE,
    PAYLOAD_RE: /<script id="ahs-payload" type="application\/octet-stream">([A-Za-z0-9+\/=\s]+)<\/script>/};
})(self);
