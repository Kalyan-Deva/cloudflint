/**
 * Thin proxy to the control plane.
 *
 * The browser never talks to the backends directly: it keeps their addresses off
 * the client, and it means neither of them needs CORS headers just so a dashboard
 * on another port can read them.
 */
const CP = process.env.CLOUDVEIL_CP ?? "http://127.0.0.1:9000";

async function forward(req: Request, path: string[]) {
  const url = new URL(req.url);
  const target = `${CP}/${path.join("/")}${url.search}`;

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: { "content-type": req.headers.get("content-type") ?? "application/json" },
      body: req.method === "GET" || req.method === "HEAD" ? undefined : await req.text(),
      cache: "no-store",
    });

    return new Response(await upstream.text(), {
      status: upstream.status,
      headers: { "content-type": "application/json" },
    });
  } catch (e) {
    /* say which hop failed - "failed to fetch" on its own sends people hunting */
    return Response.json(
      { error: `control plane at ${CP} is not answering: ${(e as Error).message}` },
      { status: 502 },
    );
  }
}

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function PUT(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function POST(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
