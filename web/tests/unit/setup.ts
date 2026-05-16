// Vitest setup — extend globals if needed.
import { vi, afterEach } from "vitest";

afterEach(() => {
  vi.restoreAllMocks();
});
