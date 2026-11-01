/* Decrypts the platform's pages, images and reports for a browser that has logged in.
   Without the keys (kept in IndexedDB after a correct password) it passes the encrypted files through. */
importScripts('sec-core.js');

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

var SCOPE = new URL(self.registration.scope);

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  var url = new URL(req.url);
  if (url.origin !== SCOPE.origin || url.pathname.indexOf(SCOPE.pathname) !== 0) return;
  var rel = url.pathname.slice(SCOPE.pathname.length);
  if (/^(images|reports)\//.test(rel)) e.respondWith(asset(req, rel));
  else if (req.mode === 'navigate' || /(^|\/)[^\/.]*\.html$|\/$|^$/.test(rel)) e.respondWith(page(req));
});

async function page(req) {
  var res = await fetch(req.url, {cache: 'no-cache', credentials: 'same-origin'});
  var ct = res.headers.get('content-type') || '';
  if (!res.ok || ct.indexOf('text/html') < 0) return res;
  var text = await res.text();
  var m = AHSSec.PAYLOAD_RE.exec(text);
  var headers = {'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store'};
  if (m) {
    var blob = AHSSec.b64d(m[1]), name = AHSSec.keyNameOf(blob);
    var rec = name && await AHSSec.getKey(name).catch(function () { return null; });
    if (rec) {
      try {
        var html = AHSSec.decode(await AHSSec.openSealed(blob, rec.key));
        return new Response(AHSSec.injectHead(html), {headers: headers});
      } catch (err) {
        await AHSSec.delKey(name).catch(function () {}); // key no longer matches: ask for the password again
      }
    }
  }
  return new Response(text, {status: res.status, headers: headers});
}

async function asset(req, rel) {
  var res = await fetch(req.url, {credentials: 'same-origin'});
  if (!res.ok) return res;
  var bytes = new Uint8Array(await res.arrayBuffer());
  if (!AHSSec.isSealed(bytes)) return new Response(bytes, {status: res.status, headers: res.headers});
  var rec = await AHSSec.getKey(AHSSec.keyNameOf(bytes)).catch(function () { return null; });
  if (!rec) return new Response('locked', {status: 403});
  try {
    var plain = await AHSSec.openSealed(bytes, rec.key);
    return new Response(plain, {headers: {'content-type': AHSSec.typeOf(rel), 'cache-control': 'private, max-age=3600'}});
  } catch (err) {
    return new Response('locked', {status: 403});
  }
}
