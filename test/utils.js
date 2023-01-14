// Import Node.js Dependencies
import path from "path";
import { fileURLToPath } from "url";

// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { readJsonFile } from "../src/utils.js";

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
