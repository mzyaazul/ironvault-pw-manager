import { createClient } from '@supabase/supabase-js';

const MAX_BYTES = 1_000_000;
const json = (body, status = 200) => Response.json(body, { status });

export default async (req) => {
  const token = (req.headers.get('authorization') || '').replace('Bearer ', '');
  if (!token) return json({ error: 'Missing token' }, 401);

  // Forward the user's token so Row Level Security still applies.
  // Never use the service_role key here.
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY,
    { global: { headers: { Authorization: `Bearer ${token}` } } }
  );

  const { data: auth, error: authErr } = await supabase.auth.getUser(token);
  if (authErr || !auth.user) return json({ error: 'Invalid token' }, 401);
  const uid = auth.user.id;

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('vaults').select('salt, iv, data, version')
      .eq('user_id', uid).maybeSingle();
    if (error) return json({ error: 'Database error' }, 500);
    return json({ vault: data });
  }

  if (req.method === 'PUT') {
    const body = await req.json().catch(() => ({}));
    const { salt, iv, data, expectedVersion } = body;
    if (![salt, iv, data].every(v => typeof v === 'string') ||
        typeof expectedVersion !== 'number') {
      return json({ error: 'Bad payload' }, 400);
    }
    if (data.length > MAX_BYTES) return json({ error: 'Vault too large' }, 413);

    if (expectedVersion === 0) {
      const { error } = await supabase.from('vaults')
        .insert({ user_id: uid, salt, iv, data, version: 1 });
      if (error) return json({ error: 'Vault already exists' }, 409);
      return json({ version: 1 });
    }

    const { data: rows, error } = await supabase.from('vaults')
      .update({ salt, iv, data, version: expectedVersion + 1, updated_at: new Date().toISOString() })
      .eq('user_id', uid).eq('version', expectedVersion)
      .select('version');
    if (error) return json({ error: 'Database error' }, 500);
    if (!rows.length) return json({ error: 'Vault changed elsewhere' }, 409);
    return json({ version: rows[0].version });
  }

  if (req.method === 'DELETE') {
    await supabase.from('vaults').delete().eq('user_id', uid);
    return json({ ok: true });
  }

  return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, PUT, DELETE' } });
};

// This makes the endpoint /api/vault, so the frontend code is unchanged.
export const config = { path: '/api/vault' };