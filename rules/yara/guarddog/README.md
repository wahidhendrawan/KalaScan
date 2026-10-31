# GuardDog rules (bundled)

Copied unchanged from [DataDog/guarddog](https://github.com/DataDog/guarddog/tree/a46949ddd7e164defe1a2ad78f7c8f6586c6667a/guarddog/analyzer/sourcecode)
at commit `a46949ddd7e164defe1a2ad78f7c8f6586c6667a`, under the Apache License 2.0 (see `LICENSE`).

Only rules that add coverage KalaScan's own rules lack, measured on the eval
corpus (`eval/`): no hits on the 227 clean samples.

| File | Detects |
|---|---|
| `threat-runtime-obfuscation-chr.yar` | Python `exec("".join(map(chr, [...])))` and `[chr(n) for n in [...]]` |
| `threat-runtime-self-propagation.yar` | Code that rewrites its own `package.json` and runs `npm publish` (worms) |

GuardDog's other rules were measured too: they either duplicate a KalaScan
rule or fire on dozens of clean packages (`dependency_confusion` 74/227).
To use all of them anyway: `kalascan scan … --yara-dir <guarddog>/guarddog/analyzer/sourcecode`.
