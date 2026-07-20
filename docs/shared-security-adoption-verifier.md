# Shared security adoption verifier

Each consumer stores `security-adoption.edn` at its repository root and runs:

```sh
clojure -M -m kotoba.security.adoption
```

The command denies floating or mismatched dependency pins, missing central
control namespaces, undeclared security-sensitive entrypoints, and exceptions
without an owner, reason, and unexpired ISO date. It then loads every declared
namespace, proving that the controls are present on the actual consumer
classpath rather than merely mentioned in policy documentation.
