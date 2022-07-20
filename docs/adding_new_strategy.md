# Adding a new strategy
If you are a contributor and want to add a new strategy to this package then this guide is for you.

The first thing to understand is that this package was built to meet the needs of the [NodeSecure Scanner](https://github.com/NodeSecure/scanner) and NodeSecure CLI. What are these needs you will ask?

- Download database on the local disk for some strategies (like Node.js Security WG with **hydrateDatabase**).
- Know if the data is up to date (what cover **src/cache.js**).
- Being able to delete it at any time (**deleteDatabase** method).
- Search and attach vulnerabilities for a given list of dependencies.

Not all strategies are the same and do not work in the same way. It is therefore also important to be able to adapt while maintaining abstract interfaces.

![](./images/scanner.png)

Dependencies is a `Map` object described in the scanner.

```js
const vulneraStrategy = await vulnera.getStrategy();
vulneraStrategy.hydratePayloadDependencies(payload.dependencies);

payload.vulnerabilityStrategy = vulneraStrategy.strategy;
```

<details><summary>see the complete definition of dependencies</summary>

dependencies is described by the type `Record<string, VersionDescriptor>`. And VersionDescriptor by the following interface:

```ts
interface VersionDescriptor {
    metadata: {
        dependencyCount: number;
        publishedCount: number;
        lastUpdateAt: number;
        lastVersion: number;
        hasChangedAuthor: boolean;
        hasManyPublishers: boolean;
        hasReceivedUpdateInOneYear: boolean;
        author: string | null;
        homepage: string | null;
        maintainers: Maintainer[];
        publishers: Publisher[];
    };
    versions: string[];
    vulnerabilities: Vulnerability[];
    [version: string]: {
        id: number;
        usedBy: Record<string, string>;
        size: number;
        description: string;
        author: string | Author;
        warnings: Warning[];
        composition: {
            extensions: string[];
            files: string[];
            minified: string[];
            required_files: string[];
            required_thirdparty: string[];
            required_nodejs: string[];
            unused: string[];
            missing: string[];
        };
        license: string | License[];
        flags: Flags;
        gitUrl: null | string;
    };
}
```

</details>

## Files to update

The files that must be modified to add a new strategy are:

<details><summary>src/constants.js</summary>

You must add a new constant in variable `VULN_MODE`
```js
export const VULN_MODE = Object.freeze({
  SECURITY_WG: "node",
  NPM_AUDIT: "npm",
  NONE: "none",
  MY_NEW_STRATEGY: "foobar" // <-- here
});
```

Also think to update the type definition of **VULN_MODE** in `types/api.d.ts`.

</details>

<details><summary>types/strategy.d.ts</summary>

It is necessary to add the name of your strategy in the exported type definitions.
```ts
declare namespace Strategy {
  export type Kind = "npm" | "node" | "none" | "foobar"; // <-- add the name here
```

</details>

<details><summary>src/strategies/index.js</summary>

This is the file we use to export and manage the initialization of a strategy.

The first line to update is the one who export all strategies at once.
```js
export { NPMAuditStrategy, SecurityWGStrategy, FooBarStrategy }; // <-- add yours here
```

And then it will be necessary to modify the function initStrategy to add a new case for your strategy.

```js
export async function initStrategy(strategy, options) {
  switch (strategy) {
    case VULN_MODE.SECURITY_WG:
      return Object.seal(await SecurityWGStrategy(options));

    case VULN_MODE.NPM_AUDIT:
      return Object.seal(NPMAuditStrategy());
    
    /** Add it at the end **/
    case VULN_MODE.MY_NEW_STRATEGY:
      return Object.seal(FooBarStrategy()); // <-- add options if required!
  }

  return Object.seal(NoneStrategy());
}
```

</details>

<details><summary>README.md</summary>

It is obviously necessary to add your strategy in the README. Also make sure that the codes and definitions are up to date.

</details>

---

You will obviously need to add your own `.js` file in the **src/strategies** folder. The content at the start will probably look like this:

```js
// Import Internal Dependencies
import { VULN_MODE } from "../constants.js";

export function FooBarStrategy() {
  return {
    strategy: VULN_MODE.MY_NEW_STRATEGY,
    hydratePayloadDependencies
  };
}

export async function hydratePayloadDependencies(dependencies, options = {}) {
  // Do your code here!
}
```

`hydrateDatabase` and `deleteDatabase` can also be added if required (take a look at security-wg.js for inspiration).

--- 

If your strategy returns information that does not match the other strategies or the standard format you will need to add definitions for this new format in `./types` (like `node-strategy.d.ts` and `npm-strategy.d.ts`).

```ts
export = FooBarStrategy;

declare namespace FooBarStrategy {
  export interface Vulnerability {
    // Your work here!
  }
}
```

Think to import/export those definitions in the root file `index.d.ts`.

---

> ⚠️ **Notes**: Documentation and testing are not specified here because it is difficult to predict what is needed. However, you are also responsible for adding them.

Take an interest in the previous works in `docs/` and `tests/strategies`. 
