// Import Node.js Dependencies
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import {
  standardizeNpmSeverity,
  fromMaybeStringToArray,
  parseNpmSpec,
  chunkArray
} from "../src/utils.js";

test("parseNpmSpec", () => {
  assert.deepEqual(
    parseNpmSpec("foobar"),
    { name: "foobar", version: undefined }
  );
  assert.deepEqual(
    parseNpmSpec("foobar@1.0.0"),
    { name: "foobar", version: "1.0.0" }
  );

  assert.deepEqual(
    parseNpmSpec("@nodesecure/js-x-ray"),
    { name: "@nodesecure/js-x-ray", version: undefined }
  );
  assert.deepEqual(
    parseNpmSpec("@nodesecure/js-x-ray@1.0.0"),
    { name: "@nodesecure/js-x-ray", version: "1.0.0" }
  );
});

test("standardizeNpmSeverity", () => {
  assert.strictEqual(
    standardizeNpmSeverity("moderate"),
    "medium",
    "should transform moderate to medium"
  );

  assert.strictEqual(
    standardizeNpmSeverity("low"),
    "low",
    "should not transform function input and return the same primitive value"
  );
});

test("fromMaybeStringToArray", () => {
  assert.deepEqual(
    fromMaybeStringToArray("foobar"),
    ["foobar"],
    "should add the given primitive string to an Array and return it"
  );

  assert.deepEqual(
    fromMaybeStringToArray(null),
    [],
    "should return empty array if the provided input is falsy (undefined, null, ...)"
  );

  const inputArr = ["foobar"];
  assert.deepEqual(
    fromMaybeStringToArray(inputArr),
    inputArr,
    "should return the same Array (ref) if provided as input"
  );
});

test("chunkArray", () => {
  const groupedArr = [1, 2, 3, 4, 5, 6];
  const chunkedArr = [...chunkArray(groupedArr, 2)];

  assert.strictEqual(chunkedArr.length, 3);
  assert.deepEqual(chunkedArr, [
    [1, 2],
    [3, 4],
    [5, 6]
  ]);
});
