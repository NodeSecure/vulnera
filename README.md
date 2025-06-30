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
- [Node.js](https://nodejs.org/en/) v20 or higher

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

await vulnera.setStrategy(
  vulnera.strategies.GITHUB_ADVISORY
);

const definition = await vulnera.getStrategy();
console.log(definition.strategy);

const vulnerabilities = await definition.getVulnerabilities(process.cwd(), {
  useFormat: "Standard"
});
console.log(vulnerabilities);
```

## Available strategy

The default strategy is **NONE** which mean no strategy at all (we execute nothing).

[GitHub Advisory](./docs/github_advisory.md) | [Sonatype - OSS Index](./docs/sonatype.md) | Snyk
:-------------------------:|:-------------------------:|:-------------------------:
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/db/Npm-logo.svg/1200px-Npm-logo.svg.png" width="300"> | <img src="https://ossindex.sonatype.org/assets/images/sonatype-image.png" width="400"> | <img src="https://res.cloudinary.com/snyk/image/upload/v1537345894/press-kit/brand/logo-black.png" width="400">

Those strategies are described as "string" **type** with the following TypeScript definition:
```ts
type Kind = "github-advisory" | "snyk" | "sonatype" | "none";
```

To add a strategy or better understand how the code works, please consult [the following guide](./docs/adding_new_strategy.md).

## API

```ts
function setStrategy<T extends Kind>(name: T): AllStrategy[T];
function getStrategy(): AnyStrategy;

const strategies: Object.freeze({
  GITHUB_ADVISORY: "github-advisory",
  SNYK: "snyk",
  SONATYPE: "sonatype",
  NONE: "none"
});

/** Equal to strategies.NONE by default **/
const defaultStrategyName: "none";
```

Strategy extend from the following set of interfaces;

```ts
export interface BaseStrategy<T extends Kind> {
  /** Name of the strategy **/
  strategy: T;
  /** Method to hydrate dependency vulnerabilities fetched by the Scanner **/
  hydratePayloadDependencies: (
    dependencies: Dependencies,
    options?: HydratePayloadDepsOptions
  ) => Promise<void>;
}

export interface ExtendedStrategy<
  T extends Kind, VulnFormat
> extends BaseStrategy<T> {
  /** Method to get vulnerabilities using the current strategy **/
  getVulnerabilities: (
    path: string,
    options?: BaseStrategyOptions
  ) => Promise<(VulnFormat | StandardVulnerability)[]>;
}

export type BaseStrategyFormat = "Standard";

export interface BaseStrategyOptions {
  useFormat?: BaseStrategyFormat;
}

export interface HydratePayloadDepsOptions extends BaseStrategyOptions {
  /**
   * Absolute path to the location to analyze
   * (with a package.json and/or package-lock.json for NPM Audit for example)
   **/
  path?: string;
}
```

Where `dependencies` is the dependencies **Map()** object of the NodeSecure Scanner.

> [!NOTE] 
> the option **hydrateDatabase** is only useful for some of the strategy (like Node.js Security WG).

### Formats
- [Standard](./docs/formats/standard.md)

### Databases
- [OSV](./docs/database/osv.md)
- [NVD](./docs/database/nvd.md)
- [Snyk](./docs/database/snyk.md)
- [Sonatype](./docs/database/sonatype.md)

## Contributors ✨

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-8-orange.svg?style=flat-square)](#contributors-)
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
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/AntonioliBenjamin"><img src="https://avatars.githubusercontent.com/u/111560667?v=4?s=100" width="100px;" alt="benjamin antonioli"/><br /><sub><b>benjamin antonioli</b></sub></a><br /><a href="https://github.com/NodeSecure/vulnera/commits?author=AntonioliBenjamin" title="Code">💻</a> <a href="https://github.com/NodeSecure/vulnera/commits?author=AntonioliBenjamin" title="Tests">⚠️</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## License
MIT
