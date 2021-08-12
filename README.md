# Vulnerabilities strategies
![version](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/NodeSecure/vuln/master/package.json&query=$.version&label=Version)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/NodeSecure/vuln/commit-activity)
[![Security Responsible Disclosure](https://img.shields.io/badge/Security-Responsible%20Disclosure-yellow.svg)](https://github.com/nodejs/security-wg/blob/master/processes/responsible_disclosure_template.md
)
[![mit](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/NodeSecure/vuln/blob/master/LICENSE)
![dep](https://img.shields.io/david/NodeSecure/vuln)

NodeSecure vulnerabilities strategies built for NodeSecure scanner.

## Requirements
- [Node.js](https://nodejs.org/en/) v14 or higher

## Getting Started

This package is available in the Node Package Repository and can be easily installed with [npm](https://docs.npmjs.com/getting-started/what-is-npm) or [yarn](https://yarnpkg.com).

```bash
$ npm i @nodesecure/vuln
# or
$ yarn add @nodesecure/vuln
```

## Usage example

```js
import * as vuln from "@nodesecure/vuln";

// Default strategy is currently "none".
await vuln.setStrategy(vuln.strategies.NPM_AUDIT);

const definition = await vuln.getStrategy();
console.log(definition.strategy);

await definition.hydratePayloadDependencies(new Map());
```

## Available strategy

- **None** (No strategy at all.. which is the `default` value).
- [NPM Audit](./docs/npm_audit.md)
- [Node.js Security WG - Database](./docs/node_security_wg.md)
- [**COMING SOON**] Snyk.

Those strategies are described as "string" **type** with the following TypeScript definition:
```ts
type Kind = "npm" | "node" | "none";
```

## API

See `types/api.d.ts` for a complete TypeScript definition.

```ts
function setStrategy(name?: Strategy.Kind, options?: Strategy.Options): Promise<Strategy.Definition>;
function getStrategy(): Promise<Strategy.Definition>;
const strategies: {
  SECURITY_WG: "node";
  NPM_AUDIT: "npm";
};
```

Strategy `Kind`, `HydratePayloadDependenciesOptions`, `Options` are described by the following interfaces:

```ts
export interface Options {
  /** Force hydratation of the strategy local database (if the strategy has one obviously) **/
  hydrateDatabase?: boolean;
}

export interface HydratePayloadDependenciesOptions {
  path?: string;
}

export interface Definition {
  /** Name of the strategy **/
  strategy: Kind;
  /** Method to hydrate (insert/push) vulnerabilities in the dependencies retrieved by the Scanner **/
  hydratePayloadDependencies: (dependencies: Dependencies, options?: HydratePayloadDependenciesOptions) => Promise<void>;
  /** Hydrate local database (if the strategy need one obviously) **/
  hydrateDatabase?: () => Promise<void>;
  /** Method to delete the local vulnerabilities database (if available) **/
  deleteDatabase?: () => Promise<void>;
}
```

Where `dependencies` is the dependencies **Map()** object of the scanner.

> Note: the option **hydrateDatabase** is only useful for some of the strategy (like Node.js Security WG).

## License
MIT
