/**
 * Thin proxy to an edge's admin API. Streams `/admin/stream` through untouched so
 * the live log stays live rather than arriving in one lump at the end.
 */
const EDGE = process.env.CLOUDVEIL_EDGE ?? "http://127.0.0.1:9001";

async function forward(req: Request, path: string[]) {
  const url = new URL(req.url);
  const target = `${EDGE}/admin/${path.join("/")}${url.search}`;
  const streaming = path[0] === "stream";

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: { "content-type": "application/json" },
      body: req.method === "GET" || req.method === "HEAD" ? undefined : await req.text(),
      cache: "no-store",
      // @ts-expect-error node fetch needs this to stream a response body
      duplex: "half",
    });

    if (streaming && upstream.body) {
      return new Response(upstream.body, {
        status: upstream.status,
        headers: {
          "content-type": "text/event-stream",
          "cache-control": "no-cache, no-transform",
          connection: "keep-alive",
        },
      });
    }

    return new Response(await upstream.text(), {
      status: upstream.status,
      headers: { "content-type": "application/json" },
    });
  } catch (e) {
    return Response.json(
      { error: `edge admin at ${EDGE} is not answering: ${(e as Error).message}` },
      { status: 502 },
    );
  }
}

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function POST(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
