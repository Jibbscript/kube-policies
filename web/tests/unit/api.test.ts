import { describe, expect, it, vi } from "vitest";
import {
  testPolicy,
  listPolicies,
  getRecentDecisions,
  ApiError,
} from "../../src/lib/api";

function mockFetchOnce(status: number, body: unknown): void {
  const headers = new Headers({ "content-type": "application/json" });
  const fetchMock = vi
    .fn()
    .mockResolvedValue(
      new Response(JSON.stringify(body), { status, statusText: "OK", headers }),
    );
  vi.stubGlobal("fetch", fetchMock);
}

describe("api.testPolicy", () => {
  it("POSTs to /api/v1/policies/:id/test with JSON body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          allowed: false,
          decision: "DENY",
          violations: [],
          patches: [],
          metadata: {},
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const body = { kind: "Pod" };
    const result = await testPolicy("security-baseline", body);
    expect(result.decision).toBe("DENY");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/policies/security-baseline/test");
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify(body));
    const hdrs = new Headers(init.headers);
    expect(hdrs.get("content-type")).toBe("application/json");
  });

  it("URL-encodes policy id", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await testPolicy("weird/id with space", {});
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toBe("/api/v1/policies/weird%2Fid%20with%20space/test");
  });

  it("throws ApiError on non-2xx", async () => {
    mockFetchOnce(403, { error: "forbidden" });
    await expect(testPolicy("p", {})).rejects.toBeInstanceOf(ApiError);
  });
});

describe("api.listPolicies and getRecentDecisions", () => {
  it("listPolicies hits /api/v1/policies", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ policies: [], total: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const res = await listPolicies();
    expect(res).toEqual([]);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/policies");
  });

  it("getRecentDecisions passes limit query", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ events: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await getRecentDecisions(25);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/decisions/recent?limit=25");
  });
});
