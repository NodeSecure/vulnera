export const NPM_VULNERABILITY = {
    "source": 1622,
    "name": "slashify",
    "dependency": "slashify",
    "title": "Open Redirect",
    "url": "https://npmjs.com/advisories/1622",
    "severity": "moderate",
    "range": ">=0.0.0",
    "vulnerableVersions": "*"
}

export const SNYK_VULNERABILITY = {
    "id": "npm:ms:20151024",
    "url": "https://snyk.io/vuln/npm:ms:20151024",
    "title": "Regular Expression Denial of Service (ReDoS)",
    "type": "vuln",
    "description": "## Overview\n\n[ms](https://www.npmjs.com/package/ms) is a tiny millisecond conversion utility.\n\n\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS)\nattack when converting a time period string (i.e. `\"2 days\"`, `\"1h\"`) into a milliseconds integer. A malicious user could pass extremely long strings to `ms()`, causing the server to take a long time to process, subsequently blocking the event loop for that extended period.\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\r\n\r\nThe Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.\r\n\r\nLet’s take the following regular expression as an example:\r\n```js\r\nregex = /A(B|C+)+D/\r\n```\r\n\r\nThis regular expression accomplishes the following:\r\n- `A` The string must start with the letter 'A'\r\n- `(B|C+)+` The string must then follow the letter A with either the letter 'B' or some number of occurrences of the letter 'C' (the `+` matches one or more times). The `+` at the end of this section states that we can look for one or more matches of this section.\r\n- `D` Finally, we ensure this section of the string ends with a 'D'\r\n\r\nThe expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD` and `ACCCCCD`\r\n\r\nIt most cases, it doesn't take very long for a regex engine to find a match:\r\n\r\n```bash\r\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD\")'\r\n0.04s user 0.01s system 95% cpu 0.052 total\r\n\r\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX\")'\r\n1.79s user 0.02s system 99% cpu 1.812 total\r\n```\r\n\r\nThe entire process of testing it against a 30 characters long string takes around ~52ms. But when given an invalid string, it takes nearly two seconds to complete the test, over ten times as long as it took to test a valid string. The dramatic difference is due to the way regular expressions get evaluated.\r\n\r\nMost Regex engines will work very similarly (with minor differences). The engine will match the first possible way to accept the current character and proceed to the next one. If it then fails to match the next one, it will backtrack and see if there was another way to digest the previous character. If it goes too far down the rabbit hole only to find out the string doesn’t match in the end, and if many characters have multiple valid regex paths, the number of backtracking steps can become very large, resulting in what is known as _catastrophic backtracking_.\r\n\r\nLet's look at how our expression runs into this problem, using a shorter string: \"ACCCX\". While it seems fairly straightforward, there are still four different ways that the engine could match those three C's:\r\n1. CCC\r\n2. CC+C\r\n3. C+CC\r\n4. C+C+C.\r\n\r\nThe engine has to try each of those combinations to see if any of them potentially match against the expression. When you combine that with the other steps the engine must take, we can use [RegEx 101 debugger](https://regex101.com/debugger) to see the engine has to take a total of 38 steps before it can determine the string doesn't match.\r\n\r\nFrom there, the number of steps the engine must use to validate a string just continues to grow.\r\n\r\n| String | Number of C's | Number of steps |\r\n| -------|-------------:| -----:|\r\n| ACCCX | 3 | 38\r\n| ACCCCX | 4 | 71\r\n| ACCCCCX | 5 | 136\r\n| ACCCCCCCCCCCCCCX | 14 | 65,553\r\n\r\n\r\nBy the time the string includes 14 C's, the engine has to take over 65,000 steps just to see if the string is valid. These extreme situations can cause them to work very slowly (exponentially related to input size, as shown above), allowing an attacker to exploit this and can cause the service to excessively consume CPU, resulting in a Denial of Service.\n\n## Remediation\n\nUpgrade `ms` to version 0.7.1 or higher.\n\n\n## References\n\n- [OSS Security advisory](https://www.openwall.com/lists/oss-security/2016/04/20/11)\n\n- [OWASP - ReDoS](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS)\n\n- [Security Focus](https://www.securityfocus.com/bid/96389)\n",
    "functions": [
        {
            "functionId": {
                "filePath": "ms.js",
                "functionName": "parse"
            },
            "version": [">0.1.0 <=0.3.0"]
        },
        {
            "functionId": {
                "filePath": "index.js",
                "functionName": "parse"
            },
            "version": [">0.3.0 <0.7.1"]
        }
    ],
    "from": ["ms@0.7.0"],
    "package": "ms",
    "version": "0.7.0",
    "severity": "medium",
    "exploitMaturity": "no-known-exploit",
    "language": "js",
    "packageManager": "npm",
    "semver": {
        "vulnerable": ["<0.5.0, >=0.4.0", "<0.3.8, >=0.3.6"]
    },
    "publicationTime": "2015-11-06T02:09:36Z",
    "disclosureTime": "2015-10-24T20:39:59Z",
    "isUpgradable": true,
    "isPatchable": true,
    "isPinnable": false,
    "identifiers": {
        "ALTERNATIVE": ["SNYK-JS-MS-10064"],
        "CVE": ["CVE-2015-8315"],
        "CWE": ["CWE-400"],
        "NSP": [46]
    },
    "credit": ["Adam Baldwin"],
    "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "cvssScore": 5.3,
    "patches": [
        {
            "comments": [],
            "id": "patch:npm:ms:20151024:5",
            "modificationTime": "2019-12-03T11:40:45.777474Z",
            "urls": [
                "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_5_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk5.patch"
            ],
            "version": "=0.1.0"
        },
        {
            "comments": [],
            "id": "patch:npm:ms:20151024:4",
            "modificationTime": "2019-12-03T11:40:45.776329Z",
            "urls": [
                "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_4_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk4.patch"
            ],
            "version": "=0.2.0"
        },
        {
            "comments": [],
            "id": "patch:npm:ms:20151024:3",
            "modificationTime": "2019-12-03T11:40:45.775292Z",
            "urls": [
                "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_3_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk3.patch"
            ],
            "version": "=0.3.0"
        },
        {
            "comments": [],
            "id": "patch:npm:ms:20151024:2",
            "modificationTime": "2019-12-03T11:40:45.774221Z",
            "urls": [
                "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_2_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk2.patch"
            ],
            "version": "<0.6.0 >0.3.0"
        },
        {
            "comments": [],
            "id": "patch:npm:ms:20151024:1",
            "modificationTime": "2019-12-03T11:40:45.773094Z",
            "urls": [
                "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_1_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk.patch"
            ],
            "version": "<0.7.0 >=0.6.0"
        },
        {
            "comments": [],
            "id": "patch:npm:ms:20151024:0",
            "modificationTime": "2019-12-03T11:40:45.772009Z",
            "urls": [
                "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_0_0_48701f029417faf65e6f5e0b61a3cebe5436b07b.patch"
            ],
            "version": "=0.7.0"
        }
    ],
    "upgradePath": ["ms@0.7.1"]
}

export const SECURITYWG_VULNERABILITY = {
    "id": 472,
    "title": "NoSQL injection on express-cart",
    "overview": "[express-cart] Customer and admin email enumeration through MongoDB injection",
    "created_at": "2018-08-20",
    "updated_at": "2018-09-10",
    "publish_date": "1970-01-01",
    "author": {
        "name": "Benoit Côté-Jodoin",
        "website": "http://bcj.io",
        "username": "becojo"
    },
    "module_name": "express-cart",
    "cves": [],
    "vulnerable_versions": "<1.1.8",
    "patched_versions": ">=1.1.8",
    "recommendation": "Update express-cart module to version >=1.1.8",
    "references": ["https://hackerone.com/reports/397445"],
    "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N",
    "cvss_score": 8.2,
    "coordinating_vendor": null
}
