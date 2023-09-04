// Import Node.js Dependencies
import path from "path";
import { fileURLToPath } from "url";

// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import {
  readJsonFile,
  standardizeNpmSeverity,
  fromMaybeStringToArray,
  chunkArray
} from "../src/utils.js";

// CONSTANTS
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const kFixturesDir = path.join(__dirname, "fixtures");

test("readJsonFile (file that exists)", async(tape) => {
  const data = await readJsonFile(path.join(kFixturesDir, "jsondata.json"));
  tape.deepEqual(data, { foo: "bar" });

  tape.end();
});

test("readJsonFile (file that does not exist)", async(tape) => {
  const data = await readJsonFile(path.join(kFixturesDir, "blezkdcklerje.txt"));
  tape.strictEqual(data, null, "asking to read a file not on the local system should return null");

  tape.end();
});

test("standardizeNpmSeverity", (tape) => {
  tape.strictEqual(
    standardizeNpmSeverity("moderate"),
    "medium",
    "should transform moderate to medium"
  );

  tape.strictEqual(
    standardizeNpmSeverity("low"),
    "low",
    "should not transform function input and return the same primitive value"
  );

  tape.end();
});

test("fromMaybeStringToArray", (tape) => {
  tape.deepEqual(
    fromMaybeStringToArray("foobar"),
    ["foobar"],
    "should add the given primitive string to an Array and return it"
  );

  tape.deepEqual(
    fromMaybeStringToArray(null),
    [],
    "should return empty array if the provided input is falsy (undefined, null, ...)"
  );

  const inputArr = ["foobar"];
  tape.deepEqual(
    fromMaybeStringToArray(inputArr),
    inputArr,
    "should return the same Array (ref) if provided as input"
  );

  tape.end();
});

test("chunkArray", (tape) => {
  const groupedArr = [1, 2, 3, 4, 5, 6];
  const chunkedArr = [...chunkArray(groupedArr, 2)];

  tape.strictEqual(chunkedArr.length, 3);
  tape.deepEqual(chunkedArr, [
    [1, 2],
    [3, 4],
    [5, 6]
  ]);

  tape.end();
});
