// Zugang nur per persönlichem Link: https://<seite>/?k=<Schlüssel>
//
// Die erlaubten Schlüssel stehen im Cloudflare-Secret ZUGAENGE, getrennt durch Komma
// oder Zeilenumbruch. Jeder Eintrag: name=schlüssel oder name=schlüssel:JJJJ-MM-TT
//   Beispiel: lennard=8f3a91..., bcg=91bc4e...:2026-12-31
// Mit Datum gilt der Link bis einschließlich zu diesem Tag (UTC), ohne Datum unbegrenzt.
// Eintrag löschen sperrt genau diesen Link, auch für Leute, die schon drin waren:
// Das Cookie wird bei jedem Aufruf gegen die aktuelle Liste geprüft.
// Gibt es ZUGAENGE nicht, gilt der einzelne Schlüssel aus ZUGANGS_SCHLUESSEL.

function erlaubteSchluessel(env) {
  const roh = env.ZUGAENGE || (env.ZUGANGS_SCHLUESSEL ? `standard=${env.ZUGANGS_SCHLUESSEL}` : '');
  const heute = new Date().toISOString().slice(0, 10);
  const gueltig = new Set();
  for (const eintrag of roh.split(/[\n,;]+/)) {
    const m = eintrag.trim().match(/^[^=\s]+\s*=\s*([A-Za-z0-9_-]{16,})(?:\s*:\s*(\d{4}-\d{2}-\d{2}))?$/);
    if (!m) continue; // kaputte Einträge zählen nicht
    const [, schluessel, ablauf] = m;
    if (ablauf && ablauf < heute) continue; // abgelaufen
    gueltig.add(schluessel);
  }
  return gueltig;
}

const KEIN_ZUGRIFF = () =>
  new Response('Kein Zugriff. Dieser Link ist ungültig oder abgelaufen.', {
    status: 403,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });

export async function onRequest({ request, env, next }) {
  const gueltig = erlaubteSchluessel(env);
  if (gueltig.size === 0) return KEIN_ZUGRIFF();

  const url = new URL(request.url);
  const ausLink = url.searchParams.get('k');
  if (ausLink !== null) {
    if (!gueltig.has(ausLink)) return KEIN_ZUGRIFF();
    url.searchParams.delete('k');
    return new Response(null, {
      status: 302,
      headers: {
        Location: url.pathname + url.search,
        'Set-Cookie': `zugang=${ausLink}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
        'Cache-Control': 'no-store',
      },
    });
  }

  const cookie = (request.headers.get('Cookie') || '')
    .split(/;\s*/)
    .find((c) => c.startsWith('zugang='));
  if (cookie && gueltig.has(cookie.slice('zugang='.length))) {
    const res = await next();
    const out = new Response(res.body, res);
    out.headers.set('X-Robots-Tag', 'noindex');
    return out;
  }
  return KEIN_ZUGRIFF();
}
