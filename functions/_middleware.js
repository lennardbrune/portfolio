// Lässt nur Besucher durch, die den Link mit ?k=<Schlüssel> haben.
// Danach merkt sich der Browser den Zugang 30 Tage lang per Cookie.
export async function onRequest({ request, env, next }) {
  const key = env.ZUGANGS_SCHLUESSEL;
  if (!key) return new Response('Kein Zugriff.', { status: 403 });

  const url = new URL(request.url);
  if (url.searchParams.get('k') === key) {
    url.searchParams.delete('k');
    return new Response(null, {
      status: 302,
      headers: {
        Location: url.pathname + url.search,
        'Set-Cookie': `zugang=${key}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
      },
    });
  }

  const cookies = (request.headers.get('Cookie') || '').split(/;\s*/);
  if (cookies.includes(`zugang=${key}`)) {
    const res = await next();
    const out = new Response(res.body, res);
    out.headers.set('X-Robots-Tag', 'noindex');
    return out;
  }
  return new Response('Kein Zugriff.', { status: 403 });
}
