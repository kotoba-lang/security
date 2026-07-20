# Shared security adoption verifier

Each consumer stores `security-adoption.edn` at its repository root and runs:

```sh
clojure -M -m kotoba.security.adoption
```

The version 2 command denies floating or mismatched dependency pins, missing
central control namespaces, undeclared security-sensitive entrypoints, and
exceptions without an owner, reason, and unexpired ISO date. Entrypoints are a
map from namespace to the exact controls it must require. The verifier loads
them and inspects the runtime namespace dependency graph, so merely putting a
control on the classpath cannot satisfy the contract.

The verifier also parses every Clojure-family source file under `src/`. Every
namespace importing `kotoba.security.*` must appear in the entrypoint map, and
its exact imported control set must match the declaration. Hidden importers,
stale declarations, and incomplete or inflated edge declarations fail closed.
