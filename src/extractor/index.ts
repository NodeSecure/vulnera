// Import Node.js Dependencies
import fs from "node:fs/promises";
import nodePath from "node:path";

// Import Third-party Dependencies
import Arborist from "@npmcli/arborist";

// Import Internal Dependencies
import { NPM_TOKEN } from "../constants.ts";

export type PackageSpec = {
  name: string;
  version: string;
};

/**
 * Extracts npm package dependencies from a local project using Arborist.
 * Tries to load from `node_modules` first (`loadActual`), then falls back
 * to the lockfile (`loadVirtual`) when `node_modules` is absent.
 */
export class NodeDependencyExtractor {
  async extract(
    projectPath: string
  ): Promise<PackageSpec[]> {
    const arborist = new Arborist({ ...NPM_TOKEN, path: projectPath });

    let root: Arborist.Node;
    try {
      await fs.access(nodePath.join(projectPath, "node_modules"));
      root = await arborist.loadActual();
    }
    catch {
      root = await arborist.loadVirtual();
    }

    return Array.from(
      collectFromTree(root)
    );
  }
}

function* collectFromTree(
  root: Arborist.Node
): IterableIterator<PackageSpec> {
  const seen = new Set<Arborist.Node | Arborist.Link>();
  const queue: Arborist.Node[] = [root];

  while (queue.length > 0) {
    const node = queue.shift()!;
    for (const [, child] of node.children) {
      if (seen.has(child)) {
        continue;
      }
      seen.add(child);
      if (!child.isRoot && !child.isWorkspace && child.version) {
        yield { name: child.name, version: child.version };
      }
      queue.push(child);
    }
  }
}
