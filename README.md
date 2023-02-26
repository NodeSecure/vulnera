<p align="center">
  <img alt="vulnera" src="https://user-images.githubusercontent.com/43391199/180091156-9cf883b3-05bc-4c69-9943-3d1168818fab.png" width="650">
</p>

<p align="center">
    <a href="https://github.com/NodeSecure/vulnera">
      <img src="https://img.shields.io/github/package-json/v/NodeSecure/vulnera?style=for-the-badge" alt="npm version">
    </a>
    <a href="https://github.com/NodeSecure/vulnera">
      <img src="https://img.shields.io/github/license/NodeSecure/vulnera?style=for-the-badge" alt="license">
    </a>
    <a href="https://api.securityscorecards.dev/projects/github.com/NodeSecure/vulnera">
      <img src="https://api.securityscorecards.dev/projects/github.com/NodeSecure/vulnera/badge?style=for-the-badge" alt="ossf scorecard">
    </a>
    <a href="https://github.com/NodeSecure/vulnera/actions?query=workflow%3A%22Node.js+CI%22">
      <img src="https://img.shields.io/github/actions/workflow/status/NodeSecure/vulnera/main.yml?style=for-the-badge" alt="github ci workflow">
    </a>
</p>

The **vuln-*era*** has begun! Programmatically fetch security vulnerabilities with one or many strategies. Originally designed to run and analyze [Scanner](https://github.com/NodeSecure/scanner) dependencies it now also runs independently from an npm Manifest.

## Requirements
- [Node.js](https://nodejs.org/en/) v16 or higher

## Getting Started

This package is available in the Node Package Repository and can be easily installed with [npm](https://docs.npmjs.com/getting-started/what-is-npm) or [yarn](https://yarnpkg.com).

```bash
$ npm i @nodesecure/vulnera
# or
$ yarn add @nodesecure/vulnera
```

## Usage example

```js
import * as vulnera from "@nodesecure/vulnera";

// Default strategy is currently "none".
await vulnera.setStrategy(vulnera.strategies.NPM_AUDIT);

const definition = await vulnera.getStrategy();
console.log(definition.strategy);

const vulnerabilities = await definition.getVulnerabilities(process.cwd(), {
  useStandardFormat: true
});
console.log(vulnerabilities);
```

## Available strategy

The default strategy is **NONE** which mean no strategy at all (we execute nothing).

[NPM Audit](./docs/npm_audit.md) | [Sonatype - OSS Index](./docs/sonatype.md) | [**COMING SOON**] Snyk | [**DEPRECATED**] [Node.js Security WG - Database](./docs/node_security_wg.md)
:-------------------------:|:-------------------------:|:-------------------------:|:-------------------------:
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/db/Npm-logo.svg/1200px-Npm-logo.svg.png" width="300"> | <img src="https://ossindex.sonatype.org/assets/images/sonatype-image.png" width="400"> | <img src="https://res.cloudinary.com/snyk/image/upload/v1537345894/press-kit/brand/logo-black.png" width="400"> | <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d9/Node.js_logo.svg/1280px-Node.js_logo.svg.png" width="300">

Those strategies are described as "string" **type** with the following TypeScript definition:
```ts
type Kind = "npm" | "node" | "sonatype" | "snyk" | "none";
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
  SONATYPE: "sonatype";
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
  useStandardFormat?: boolean;
}

export interface GetVulnerabilitiesOptions {
  useStandardFormat?: boolean;
}

export interface Definition<T> {
  /** Name of the strategy **/
  strategy: Kind;
  /** Method to hydrate (insert/push) vulnerabilities in the dependencies retrieved by the Scanner **/
  hydratePayloadDependencies: (
    dependencies: Dependencies,
    options?: HydratePayloadDependenciesOptions
  ) => Promise<void>;
  /** Method to get vulnerabilities using the current strategy **/
  getVulnerabilities: (
    path: string,
    options?: GetVulnerabilitiesOptions
  ) => Promise<T | StandardVulnerability>;
  /** Hydrate local database (if the strategy need one obviously) **/
  hydrateDatabase?: () => Promise<void>;
  /** Method to delete the local vulnerabilities database (if available) **/
  deleteDatabase?: () => Promise<void>;
}
```

Where `dependencies` is the dependencies **Map()** object of the scanner.

> Note: the option **hydrateDatabase** is only useful for some of the strategy (like Node.js Security WG).

### Standard vulnerability format
We provide an high level format that work for all available strategy. It can be activated with the option `useStandardFormat`.

```ts
export interface StandardVulnerability {
  /** Unique identifier for the vulnerability **/
  id?: string;
  /** Vulnerability origin, either Snyk, NPM or NodeSWG **/
  origin: Origin;
  /** Package associated with the vulnerability **/
  package: string;
  /** Vulnerability title **/
  title: string;
  /** Vulnerability description **/
  description?: string;
  /** Vulnerability link references on origin's website **/
  url?: string;
  /** Vulnerability severity levels given the strategy **/
  severity?: Severity;
  /** Common Vulnerabilities and Exposures dictionary */
  cves?: string[];
  /** Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability, and produce a numerical score reflecting its severity, as well as a textual representation of that score. **/
  cvssVector?: string;
  /** CVSS Score **/
  cvssScore?: number;
  /** The range of vulnerable versions provided when too many versions are vulnerables */
  vulnerableRanges: string[];
  /** The set of versions that are vulnerable **/
  vulnerableVersions: string[];
  /** The set of versions that are patched **/
  patchedVersions?: string;
  /** Overview of available patches to get rid of listed vulnerabilities **/
  patches?: Patch[];
}
```

## Contributors ✨

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-7-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://www.linkedin.com/in/thomas-gentilhomme/"><img src="https://avatars.githubusercontent.com/u/4438263?v=4?s=100" width="100px;" alt="Gentilhomme"/><br /><sub><b>Gentilhomme</b></sub></a><br /><a href="https://github.com/NodeSecure/vulnera/commits?author=fraxken" title="Code">💻</a> <a href="https://github.com/NodeSecure/vulnera/commits?author=fraxken" title="Documentation">📖</a> <a href="https://github.com/NodeSecure/vulnera/pulls?q=is%3Apr+reviewed-by%3Afraxken" title="Reviewed Pull Requests">👀</a> <a href="#security-fraxken" title="Security">🛡️</a> <a href="https://github.com/NodeSecure/vulnera/issues?q=author%3Afraxken" title="Bug reports">🐛</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://tonygo.dev"><img src="https://avatars.githubusercontent.com/u/22824417?v=4?s=100" width="100px;" alt="Tony Gorez"/><br /><sub><b>Tony Gorez</b></sub></a><br /><a href="https://github.com/NodeSecure/vulnera/commits?author=tony-go" title="Code">💻</a> <a href="https://github.com/NodeSecure/vulnera/pulls?q=is%3Apr+reviewed-by%3Atony-go" title="Reviewed Pull Requests">👀</a> <a href="https://github.com/NodeSecure/vulnera/issues?q=author%3Atony-go" title="Bug reports">🐛</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://antoinecoulon.me/"><img src="https://avatars.githubusercontent.com/u/43391199?v=4?s=100" width="100px;" alt="Antoine"/><br /><sub><b>Antoine</b></sub></a><br /><a href="https://github.com/NodeSecure/vulnera/commits?author=antoine-coulon" title="Code">💻</a> <a href="https://github.com/NodeSecure/vulnera/issues?q=author%3Aantoine-coulon" title="Bug reports">🐛</a> <a href="https://github.com/NodeSecure/vulnera/commits?author=antoine-coulon" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/OlehSych"><img src="https://avatars.githubusercontent.com/u/34604102?v=4?s=100" width="100px;" alt="OlehSych"/><br /><sub><b>OlehSych</b></sub></a><br /><a href="https://github.com/NodeSecure/vulnera/commits?author=OlehSych" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Mathieuka"><img src="https://avatars.githubusercontent.com/u/34446722?v=4?s=100" width="100px;" alt="Mathieu"/><br /><sub><b>Mathieu</b></sub></a><br /><a href="https://github.com/NodeSecure/vulnera/commits?author=Mathieuka" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/PierreDemailly"><img src="https://avatars.githubusercontent.com/u/39910767?v=4?s=100" width="100px;" alt="PierreD"/><br /><sub><b>PierreD</b></sub></a><br /><a href="https://github.com/NodeSecure/vulnera/commits?author=PierreDemailly" title="Code">💻</a> <a href="https://github.com/NodeSecure/vulnera/commits?author=PierreDemailly" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/fabnguess"><img src="https://avatars.githubusercontent.com/u/72697416?v=4?s=100" width="100px;" alt="Kouadio Fabrice Nguessan"/><br /><sub><b>Kouadio Fabrice Nguessan</b></sub></a><br /><a href="https://github.com/NodeSecure/vulnera/commits?author=fabnguess" title="Code">💻</a> <a href="#maintenance-fabnguess" title="Maintenance">🚧</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## License
MIT
