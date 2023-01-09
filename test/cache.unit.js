// Import Node.js Dependencies
import { rmSync, writeFileSync } from "fs";
import path from "path";

// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import * as cache from "../src/cache.js";
import { TMP_CACHE, CACHE_DELAY } from "../src/constants.js";

test("cache constants", (tape) => {
  tape.true(typeof TMP_CACHE === "string");
  tape.true(path.isAbsolute(TMP_CACHE));

  tape.true(typeof CACHE_DELAY === "number");
  tape.true(CACHE_DELAY > 0);

  tape.end();
});

test("node-secure load cache", (tape) => {
  rmSync(TMP_CACHE, { force: true });

  {
    const payload = cache.load();
    tape.strictEqual("lastUpdated" in payload, true, "cache must contain a 'lastUpdated' property");

    const delay = (Date.now() - CACHE_DELAY) - payload.lastUpdated;
    tape.true(delay >= 0 && delay <= 1);
  }

  const fakePayload = { foo: "bar" };
  writeFileSync(TMP_CACHE, JSON.stringify(fakePayload));
  {
    const payload = cache.load();
    tape.deepEqual(payload, fakePayload);
  }

  tape.end();
});

test("node-secure refresh cache", (tape) => {
  rmSync(TMP_CACHE, { force: true });

  writeFileSync(TMP_CACHE, JSON.stringify({ foo: "bar" }));
  cache.refresh();

  {
    const payload = cache.load();
    tape.strictEqual("lastUpdated" in payload, true, "cache must contain a 'lastUpdated' property");

    const delay = Date.now() - payload.lastUpdated;
    tape.true(delay >= 0 && delay <= 1);
  }

  tape.end();
});

