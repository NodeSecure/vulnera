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

test("readJsonFile", async(tape) => {
  const data1 = await readJsonFile(path.join(kFixturesDir, "jsondata.json"));
  tape.deepEqual(data1, { foo: "bar" });

  const data2 = await readJsonFile(path.join(kFixturesDir, "blezkdcklerje.txt"));
  tape.deepEqual(data2, null);

  tape.end();
});
