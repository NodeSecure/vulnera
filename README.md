# Vulnerabilities strategies
![version](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/NodeSecure/vuln/master/package.json&query=$.version&label=Version)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/NodeSecure/vuln/commit-activity)
[![Security Responsible Disclosure](https://img.shields.io/badge/Security-Responsible%20Disclosure-yellow.svg)](https://github.com/nodejs/security-wg/blob/master/processes/responsible_disclosure_template.md
)
[![mit](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/NodeSecure/vuln/blob/master/LICENSE)
![build](https://img.shields.io/github/workflow/status/NodeSecure/vuln/Node.js%20CI)

NodeSecure vulnerabilities strategies built for NodeSecure scanner.

## Requirements
- [Node.js](https://nodejs.org/en/) v16 or higher

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

The default strategy is **NONE** which mean no strategy at all (we execute nothing).

[NPM Audit](./docs/npm_audit.md) | [Node.js Security WG - Database](./docs/node_security_wg.md) | [**COMING SOON**] Snyk 
:-------------------------:|:-------------------------:|:-------------------------:
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/db/Npm-logo.svg/1200px-Npm-logo.svg.png" width="300"> | <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d9/Node.js_logo.svg/1280px-Node.js_logo.svg.png" width="300"> | <img src="https://res.cloudinary.com/snyk/image/upload/v1537345894/press-kit/brand/logo-black.png" width="400"> 

Those strategies are described as "string" **type** with the following TypeScript definition:
```ts
type Kind = "npm" | "node" | "snyk" | "none";
```

To add a strategy or better understand how the code works, please consult [the following guide](./docs/adding_new_strategy.md).

## API

See `types/api.d.ts` for a complete TypeScript definition.

```ts
function setStrategy(name?: Strategy.Kind, options?: Strategy.Options): Promise<Strategy.Definition>;
function getStrategy(): Promise<Strategy.Definition>;

const strategies: {
  SECURITY_WG: "node";
  NPM_AUDIT: "npm";
  SNYK: "snyk";
  NONE: "none";
};

/** Equal to strategies.NONE by default **/
const defaultStrategyName: string;
```

Strategy `Kind`, `HydratePayloadDependenciesOptions`, `Options` are described by the following interfaces:

```ts
export interface Options {
  /** Force hydratation of the strategy local database (if the strategy has one obviously) **/
  hydrateDatabase?: boolean;
}

export interface HydratePayloadDependenciesOptions {
  /**
   * Absolute path to the location to analyze (with a package.json and/or package-lock.json)
   * Useful to NPM Audit strategy
   **/
  path?: string;
}

export interface Definition {
  /** Name of the strategy **/
  strategy: Kind;
  /** Method to hydrate (insert/push) vulnerabilities in the dependencies retrieved by the Scanner **/
  hydratePayloadDependencies: (
    dependencies: Dependencies,
    options?: HydratePayloadDependenciesOptions
  ) => Promise<void>;
  /** Hydrate local database (if the strategy need one obviously) **/
  hydrateDatabase?: () => Promise<void>;
  /** Method to delete the local vulnerabilities database (if available) **/
  deleteDatabase?: () => Promise<void>;
}
```

Where `dependencies` is the dependencies **Map()** object of the scanner.

> Note: the option **hydrateDatabase** is only useful for some of the strategy (like Node.js Security WG).

## Contributors ✨

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-4-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://www.linkedin.com/in/thomas-gentilhomme/"><img src="https://avatars.githubusercontent.com/u/4438263?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Gentilhomme</b></sub></a><br /><a href="https://github.com/NodeSecure/vuln/commits?author=fraxken" title="Code">💻</a> <a href="https://github.com/NodeSecure/vuln/commits?author=fraxken" title="Documentation">📖</a> <a href="https://github.com/NodeSecure/vuln/pulls?q=is%3Apr+reviewed-by%3Afraxken" title="Reviewed Pull Requests">👀</a> <a href="#security-fraxken" title="Security">🛡️</a> <a href="https://github.com/NodeSecure/vuln/issues?q=author%3Afraxken" title="Bug reports">🐛</a></td>
    <td align="center"><a href="http://tonygo.dev"><img src="https://avatars.githubusercontent.com/u/22824417?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Tony Gorez</b></sub></a><br /><a href="https://github.com/NodeSecure/vuln/commits?author=tony-go" title="Code">💻</a> <a href="https://github.com/NodeSecure/vuln/pulls?q=is%3Apr+reviewed-by%3Atony-go" title="Reviewed Pull Requests">👀</a> <a href="https://github.com/NodeSecure/vuln/issues?q=author%3Atony-go" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://antoinecoulon.me/"><img src="https://avatars.githubusercontent.com/u/43391199?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Antoine</b></sub></a><br /><a href="https://github.com/NodeSecure/vuln/commits?author=antoine-coulon" title="Code">💻</a> <a href="https://github.com/NodeSecure/vuln/issues?q=author%3Aantoine-coulon" title="Bug reports">🐛</a> <a href="https://github.com/NodeSecure/vuln/commits?author=antoine-coulon" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/OlehSych"><img src="https://avatars.githubusercontent.com/u/34604102?v=4?s=100" width="100px;" alt=""/><br /><sub><b>OlehSych</b></sub></a><br /><a href="https://github.com/NodeSecure/vuln/commits?author=OlehSych" title="Code">💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## License
MIT
