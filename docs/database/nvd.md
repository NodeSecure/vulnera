# NVD

NVD stand for <kbd>National Vulnerability Database</kbd>, which is the U.S. government repository of standards-based vulnerability management data. This database is maintained by NIST (National Institute of Standards and Technology).

## Implementation Notes

The NVD integration uses the REST API (v2.0) available at [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0). 

### Search Parameters

While the NVD API supports CPE matching via the `cpeMatchString` parameter, we've chosen to use only keyword search for NPM packages. This decision was made because:

1. The CPE format for npm packages is not standardized in NVD
2. Attempted CPE patterns (like `cpe:2.3:a:*:package-name:*:*:*:*:*:node.js:*:*`) resulted in 404 errors
3. Keyword search provides more flexible results for JavaScript/NPM packages

The implementation might be enhanced in the future if NVD provides clearer guidelines for CPE matching of npm packages.

## Format

The NVD API returns detailed vulnerability information. The raw response is structured as follows:

```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-XXXX-XXXXX",
        "sourceIdentifier": "source",
        "published": "YYYY-MM-DDThh:mm:ss.sss",
        "lastModified": "YYYY-MM-DDThh:mm:ss.sss",
        "vulnStatus": "status",
        "descriptions": [
          {
            "lang": "en",
            "value": "Description of the vulnerability"
          }
        ],
        "metrics": {
          "cvssMetricV2": [ /* CVSS v2 metrics */ ],
          "cvssMetricV3": [ /* CVSS v3 metrics */ ]
        }
      }
    }
  ]
}
```

## API

### findOne(parameters: NVDApiParameter): Promise< any[] >
Find the vulnerabilities of a given package using available NVD API parameters.

```ts
export type NVDApiParameter = {
  keywordSearch?: string;
  cweId?: string;
  cvssV3Severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  packageName?: string;
  ecosystem?: string;
};
```

### findOneBySpec(spec: string): Promise< any[] >
Find the vulnerabilities of a given package using the NPM spec format like `packageName@version`.

```ts
import * as vulnera from "@nodesecure/vulnera";

const vulns = await vulnera.Database.nvd.findOneBySpec(
  "express@4.0.0"
);
console.log(vulns);
```

### findMany< T extends string >(specs: T[]): Promise< Record< T, any[] > >
Find the vulnerabilities of many packages using the spec format.

Returns a Record where keys are equals to the provided specs. 