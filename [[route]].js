// Cloudflare Pages Function. Routes:
//   /api/lookup?q=          quick info: IP/prefix, ASN, AS name, country (+ city for the visitor's own IP)
//   /api/connectivity?asn=&prefix=   upstreams, peers and Tier 1 paths from RIPEstat RIS BGP data
//   /api/prefixes?asn=      every prefix announced by the ASN, sorted
//   /api/whois?q=           WHOIS record, IRR route objects, abuse contact
//   /api/rpki?asn=&prefix=  RPKI origin validation + covering ROAs
//   /api/abuse?ip=          AbuseIPDB check (needs env var ABUSEIPDB_KEY)
//   /api/rdns?ip=           reverse DNS (PTR) hostname for an IPv4
// Server-side only. Never copy this key into index.html or a public repo.
const ABUSE_KEY = '3c2012ec25d9d9de1277b2c753053818e07e2e158da8a05129bf4939fa53fd0a9679963e2814ad27';
const R = 'https://stat.ripe.net/data';
const TIER1 = [174, 6453, 6461, 6762, 1299, 2914, 3491, 12956, 7018, 6830, 5511, 3320, 3257, 3356];

const J = (o, s = 200) => new Response(JSON.stringify(o), {
  status: s,
  headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'cache-control': 'no-store' }
});
const get = (u, h = {}) => fetch(u, { headers: { accept: 'application/json', ...h } })
  .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))));
const clean = (s) => (s || '').replace(/^[A-Z0-9-]+\s*-\s*/, '').slice(0, 40);
const nameCache = new Map();
async function nameOf(a) {
  if (nameCache.has(a)) return nameCache.get(a);
  let n = 'AS' + a;
  try { n = clean((await get(`${R}/as-overview/data.json?resource=AS${a}`)).data.holder) || n; } catch (e) {}
  nameCache.set(a, n);
  return n;
}
const rec2obj = (r) => { const o = {}; r.forEach((x) => { o[x.key] = o[x.key] ? o[x.key] + ', ' + x.value : x.value; }); return o; };
const v4int = (p) => p.split('/')[0].split('.').reduce((a, b) => a * 256 + +b, 0);
const count = (arr) => { const m = new Map(); arr.forEach((a) => m.set(a, (m.get(a) || 0) + 1)); return [...m].sort((a, b) => b[1] - a[1]); };
const enc = encodeURIComponent;

export async function onRequest({ request, env, params }) {
  const url = new URL(request.url), P = url.searchParams, route = (params.route || [])[0];
  const cf = request.cf || {}, clientIp = request.headers.get('CF-Connecting-IP') || '';
  try {
    if (route === 'lookup') {
      const q = (P.get('q') || '').trim() || clientIp, out = { ip: clientIp, query: q };
      const isAsn = /^(as)?\d+$/i.test(q);
      if (!isAsn && q === clientIp && cf.asn) Object.assign(out, { asn: cf.asn, name: cf.asOrganization, cc: cf.country, city: cf.city, region: cf.region, tz: cf.timezone });
      if (isAsn) {
        out.asn = Number(q.replace(/^as/i, ''));
        out.name = clean((await get(`${R}/as-overview/data.json?resource=AS${out.asn}`)).data.holder);
      } else {
        const p = await get(`${R}/prefix-overview/data.json?resource=${enc(q)}`);
        const a = p.data.asns && p.data.asns[0];
        if (a) { out.asn = out.asn || a.asn; out.name = out.name || clean(a.holder); }
        out.cidr = p.data.resource;
      }
      return J(out);
    }

    if (route === 'connectivity') {
      const asn = Number(P.get('asn'));
      let prefix = P.get('prefix') || '';
      const nb = await get(`${R}/asn-neighbours/data.json?resource=AS${asn}`).catch(() => null);
      const neigh = (nb && nb.data.neighbours) || [];
      if (!prefix.includes('/')) {
        const ap = await get(`${R}/announced-prefixes/data.json?resource=AS${asn}`).catch(() => null);
        const all = ((ap && ap.data.prefixes) || []).map((x) => x.prefix);
        prefix = all.find((p) => !p.includes(':')) || all[0] || '';
      }
      const st = prefix ? await get(`${R}/bgp-state/data.json?resource=${enc(prefix)}`).catch(() => null) : null;
      const paths = ((st && st.data.bgp_state) || [])
        .map((x) => x.path.filter((a, i, r) => a !== r[i - 1]))
        .filter((p) => p.length >= 2 && p[p.length - 1] === asn);

      let ups = count(paths.map((p) => p[p.length - 2]));
      let chainAsns = [];
      if (ups.length) {
        chainAsns.push(ups[0][0]);
        const via = count(paths.filter((p) => p[p.length - 2] === ups[0][0] && p.length >= 3).map((p) => p[p.length - 3]))
          .find(([a]) => !TIER1.includes(a));
        if (via) chainAsns.push(via[0]);
      } else {
        const left = neigh.filter((x) => x.type === 'left').sort((a, b) => b.power - a.power);
        ups = left.slice(0, 10).map((x) => [x.asn, x.power]);
        if (ups.length) chainAsns.push(ups[0][0]);
      }
      const total = ups.reduce((s, x) => s + x[1], 0) || 1;
      const topUps = ups.slice(0, 10);
      const peerList = [...neigh].sort((a, b) => b.power - a.power).slice(0, 8);
      const ids = [...new Set([...topUps.map((x) => x[0]), ...chainAsns, ...peerList.map((x) => x.asn)])];
      await Promise.all(ids.map(nameOf));
      return J({
        asn, prefix, visible: paths.length > 0, paths: paths.length,
        up: chainAsns.map((a) => [a, nameCache.get(a), '']),
        upstreams: topUps.map(([a, c]) => ({ asn: a, name: nameCache.get(a), paths: c, share: c / total })),
        peers: peerList.map((x) => [x.asn, nameCache.get(x.asn), '']),
        t1: [...new Set(paths.flat().filter((a) => TIER1.includes(a)))]
      });
    }

    if (route === 'prefixes') {
      const asn = Number(P.get('asn'));
      const ap = await get(`${R}/announced-prefixes/data.json?resource=AS${asn}`);
      const rows = ap.data.prefixes.map((x) => [x.prefix, x.timelines && x.timelines[0] ? x.timelines[0].starttime : '']);
      const v4 = rows.filter((r) => !r[0].includes(':')).sort((a, b) => v4int(a[0]) - v4int(b[0]) || a[0].localeCompare(b[0]));
      const v6 = rows.filter((r) => r[0].includes(':')).sort((a, b) => a[0].localeCompare(b[0]));
      const MAX = 3000, total = rows.length, v4s = v4.slice(0, MAX), v6s = v6.slice(0, Math.max(0, MAX - v4s.length));
      return J({ asn, total, shown: v4s.length + v6s.length, v4: v4s, v6: v6s });
    }

    if (route === 'whois') {
      const q = (P.get('q') || '').trim();
      const w = await get(`${R}/whois/data.json?resource=${enc(q)}`);
      const recs = w.data.records || [];
      const main = recs[0] ? rec2obj(recs[0]) : {};
      if (!main.source && w.data.authorities && w.data.authorities[0]) main.source = String(w.data.authorities[0]).toUpperCase();
      const irr = (w.data.irr_records || []).map(rec2obj);
      const ab = await get(`${R}/abuse-contact-finder/data.json?resource=${enc(q)}`).catch(() => null);
      const abuse = ab && ab.data.anti_abuse_contacts && ab.data.anti_abuse_contacts.abuse_c && ab.data.anti_abuse_contacts.abuse_c[0]
        ? ab.data.anti_abuse_contacts.abuse_c[0].email : '';
      return J({ whois: main, irr, abuse });
    }

    if (route === 'rpki') {
      const asn = Number(P.get('asn')), prefix = P.get('prefix');
      const r = await get(`${R}/rpki-validation/data.json?resource=AS${asn}&prefix=${enc(prefix)}`);
      return J({ status: r.data.status, roas: r.data.validating_roas || [] });
    }

    if (route === 'abuse') {
      const key = env.ABUSEIPDB_KEY || ABUSE_KEY;
      if (!key) return J({ error: 'no_key' });
      const ip = (P.get('ip') || '').trim();
      const r = await get(`https://api.abuseipdb.com/api/v2/check?ipAddress=${enc(ip)}&maxAgeInDays=90`, { Key: key });
      return J(r.data);
    }

    if (route === 'rdns') {
      const ip = (P.get('ip') || '').trim();
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return J({ host: '' });
      const r = await get(`https://cloudflare-dns.com/dns-query?name=${ip.split('.').reverse().join('.')}.in-addr.arpa&type=PTR`, { accept: 'application/dns-json' });
      const a = (r.Answer || []).find((x) => x.type === 12);
      return J({ host: a ? a.data.replace(/\.$/, '') : '' });
    }

    return J({ error: 'unknown route' }, 404);
  } catch (e) {
    return J({ error: String(e.message || e) }, 502);
  }
}
