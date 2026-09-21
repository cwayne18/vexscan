---
sidebar_position: 13
title: "LLM layer (optional)"
---


The LLM is an overlay and never a source of truth. It runs only on findings the
deterministic tests could not clear, and it cannot change a status.

- **`--llm`** — for CVEs whose vulnerable code is genuinely linked or reachable,
  a chat model gives an advisory `likely` / `unlikely` / `unknown` exploitability
  verdict, recorded under `llm` on the finding. You choose which model — see
  [Choosing a provider](#choosing-a-provider). Because the verdict lives in the
  per-finding evidence block, `--llm` turns on `--details` for `--format text`
  so it is actually printed; pass `--format json`/`sarif` to get it structured
  instead.
- **`--mine-advisories`** — lets the model read an advisory's prose and extract
  symbols, sonames, filenames and **module paths** worth checking. Distro OSV
  records give a fixed version and nothing about what inside the package is
  vulnerable, so for OS packages this is often the only route to a
  below-package-level answer. For Python and npm the mined value is a dotted
  module path or a package subpath — `yaml.constructor`, `lodash/template` — and
  it is the only route to a `not_present` for a distribution that is installed
  and does ship code, since neither language eliminates dead code at build time.
  For Java the mined value is a **class name**, and this is the ecosystem that
  needs mining most while getting the least help with it: OSV's Maven records
  carry no `ecosystem_specific` function data at all, unlike RustSec, so a class
  name can only come from prose. When one arrives it is checkable against
  something exact — a class is an entry in a zip.

**Mined hints are contained, not trusted.** A hint may only support a
`not_affected`-flavored status *after validation*: it must appear literally in
the advisory text, and it must be found in something the package actually
installs — the **defined** `.dynsym` of one of its libraries for an OS package,
its own installed file list for a Python or npm module path, an entry in the
archive for a Java class. An unvalidatable mined hint is indistinguishable from
a hallucination and is recorded as inconclusive, so a hallucinated hint is inert
rather than dangerous.

The Python and npm validations additionally defer to any blocking taint, and to
a file list that had to be reconstructed rather than read. Both are cases where
"the module is not here" could equally mean "we did not look in the right
place".

The OS validation adds a **shape** gate, for the same reason the Java one below
does. A namespace is shared by far more than its functions, so passing the
namespace check is not evidence that the name is something a symbol table would
ever have held. Two kinds get refused:

- **Names that are not functions.** `OSSL_CMP_CTX` is a struct tag,
  `OPENSSL_NO_COMP_ALG` is a build macro, `SSL_OP_NO_RX_CERTIFICATE_COMPRESSION`
  is an option constant. All three sit in a namespace libcrypto really exports
  and none of them is in any build's symbol table, so their absence is
  guaranteed rather than observed. C spells these in upper case, so a name with
  no lower-case letter is refused. The cost is that a genuinely all-caps export
  like `MD5` can no longer be ruled out — a lost conclusion, not a wrong one.
- **Names the package exports under a different decoration.** PCRE2 ships one
  library per code-unit width and suffixes every export, so an advisory written
  about `pcre2_compile` is absent from `libpcre2-8-0` — which exports
  `pcre2_compile_8` — in every version ever built. Normalising the width suffix
  off both sides catches it.

Both were found by running a real miner against Rancher's RKE2 v1.36.0 images
and auditing every rule-out it produced. Without this gate, eleven package rows
across four of them were cleared on the strength of a struct tag, a build macro,
an option constant, a type name or a code-unit suffix. Three CVEs left their
reports entirely — the clearing hit every row they appeared on — and two more
survived only because a sibling package row happened to stay open.

The Java validation adds two gates of its own. A mined name must be **shaped
like a class** — a dotted name whose last segment is capitalised — because there
is no `doLookup.class` and concluding absence from a method name's absence would
be a plain lie. And the artifact's **coordinates must have been read** rather
than reconstructed (tiers 1–2 above), on the same principle: an absence claim
about an artifact whose identity is a guess is two guesses stacked.

The class is then looked for under **every** package spelling in the archive,
not only the one the advisory wrote. That is what makes a bare `JndiLookup`
usable at all — GHSA-jfh8-c2jp-5v3q never writes the package — and it is
simultaneously the shading guard described above.

`elf-import-absent`, `py-import-absent` and `npm-import-absent` — reachable, but
nothing imports the vulnerable symbol or module — stay evidence-only unless you
pass `--trust-import-absence`. Absence of a *direct* import does not prove
unreachability, because the vulnerable code is usually called from inside the
same library or package.

### Choosing a provider

There is **no default**. `vexscan` used to call [GitHub
Models](https://github.com/marketplace/models), which was free with a token most
users already had; it has been retired. `--llm` with nothing configured fails
and prints the three ways to configure it, rather than quietly not asking —
missing verdicts look exactly like findings nothing had an opinion about.

**An OpenAI-compatible endpoint.** Almost everything speaks this format:

```sh
export VEXSCAN_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions
export VEXSCAN_LLM_TOKEN=sk-...          # or just set OPENAI_API_KEY
vexscan --image myorg/app:latest --all --llm --llm-model gpt-4o
```

Anthropic serves the same shape at
`https://api.anthropic.com/v1/chat/completions` (with `ANTHROPIC_API_KEY`), as
do Azure AI Foundry, OpenRouter, Together, Groq and Fireworks. Set
`--llm-model` to whatever that provider calls the model; routers want the
`vendor/model` spelling.

**A model on your own machine.** Ollama, vLLM and `llama.cpp` all expose the
same endpoint, and none of them wants a token:

```sh
ollama pull llama3.1                     # with `ollama serve` running
vexscan --image myorg/app:latest --all --llm \
  --llm-endpoint http://localhost:11434/v1/chat/completions --llm-model llama3.1
```

This is the closest replacement for what GitHub Models provided — free, and
nothing about the image you are triaging leaves the machine. The work suits a
small model better than it looks: the prompts are short, the answer is one small
JSON object, and `--mine-advisories` is extraction from text that is supplied in
the prompt rather than recall. Expect thinner rationales; expect nothing else to
change.

**A CLI you already have logged in.** The prompt goes to its standard input and
the reply is read from its standard output:

```sh
vexscan --image myorg/app:latest --all --llm --llm-command 'claude -p'
```

Anything that takes a prompt on stdin and prints a reply works, including a
wrapper script around something in-house. This is the weakest transport and the
trade is worth knowing: there is no structured-output mode to ask for, so the
reply is whatever the CLI printed; there are no rate-limit headers, so a
provider that wants you to slow down can only say so by failing; and an
unauthenticated CLI fails once per finding rather than once at startup. Note
also that `--llm-model` does nothing here — put the model in the command itself.

| | Flag | Environment |
|---|---|---|
| Endpoint | `--llm-endpoint` | `VEXSCAN_LLM_ENDPOINT` |
| Model | `--llm-model` | `VEXSCAN_LLM_MODEL` (default `gpt-4o`) |
| Credential | *(none, deliberately)* | `VEXSCAN_LLM_TOKEN`, else `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` |
| Local CLI | `--llm-command` | `VEXSCAN_LLM_COMMAND` |

The credential has no flag on purpose: everything on a command line is readable
in the process table by every other user on the machine. The prompt is sent to a
command's stdin for the same reason, and because advisory prose is long enough
to approach the argument-length limit.

**Which provider you pick cannot change a conclusion.** A verdict is only ever
attached to a finding that already has a status, and a mined symbol has to be
found in the artifact before it supports one. A weaker model produces vaguer
rationales and finds fewer checkable symbols. It cannot manufacture a
`not_present`. That is why this is a configuration option and not an
architectural decision.

### Rate limits and failures

`vexscan` caches verdicts per CVE, so the same CVE linked into twenty binaries
costs one call. Requests are not spaced out by default — set
`VEXSCAN_LLM_MIN_INTERVAL` (a Go duration) for a provider that needs it.
`429`/`5xx` and connection failures are retried with backoff, honoring
`Retry-After` up to two minutes; a failing `--llm-command` is **not** retried,
because a CLI's transient failures were already retried inside its own client
and its other failures do not improve on the sixth attempt. A failed assessment
is non-fatal either way: the finding is still reported, just without a verdict.

