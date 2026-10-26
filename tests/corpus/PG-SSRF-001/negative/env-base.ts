// corpus: expect=none
export async function getUser(id: string) {
  const res = await fetch(`${process.env.API_BASE}/users/${encodeURIComponent(id)}`);
  return res.json();
}
