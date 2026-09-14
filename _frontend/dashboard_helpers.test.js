import assert from "node:assert/strict";
import test from "node:test";

import { asList } from "./dashboard_helpers.js";

test("asList preserves arrays", () => {
  const value = [1, 2];
  assert.equal(asList(value), value);
});

test("asList converts absent or non-array values to empty arrays", () => {
  assert.deepEqual(asList(undefined), []);
  assert.deepEqual(asList(null), []);
  assert.deepEqual(asList({ length: 2 }), []);
});

