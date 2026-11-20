# Runtime package rollback

Each runtime package is published once per release tag. A published version can never be deleted from the registries that accept it, so a bad release is retired in place and replaced by the next version. The table names who runs each step.

| Registry | Reversible action | Irreversible limit | Who runs it |
| --- | --- | --- | --- |
| npm | `npm deprecate <pkg>@<version> "<reason>"` marks the version as deprecated; the tarball stays downloadable | A published version cannot be unpublished after 72 hours, and unpublishing is blocked entirely when other packages depend on it | Release owner runs `npm deprecate`, then publishes the fixed version |
| PyPI | `yank` removes the version from the default resolver view while the file stays reachable by exact pin | A filename cannot be reused once uploaded, even after yank | Release owner yanks on the PyPI project page, then publishes the fixed version |
| pub.dev | `retract` hides the version from resolution; the archive stays stored | A retracted version cannot be republished with the same version string | Release owner runs `dart pub publish` for the fixed version, then retracts the bad one |
| Maven Central | Nothing can be deleted or retracted after the release is closed | A bad artifact stays resolvable forever, so the only fix is to publish a higher version and stop documenting the old one | Release owner publishes the fixed version; the bad version stays in the repository |
| GitHub mirror tag (Go, Rust, Swift) | Delete the tag and re-tag the corrected commit, then let the mirror sync run | A module proxy caches a resolved version, so a moved tag is not observed by clients that already resolved it | Release owner deletes the tag; the mirror sync workflow republishes from the corrected commit |

## Order

1. Retire the bad version in its registry with the action above. Do not try to delete it.
2. Publish the fixed version from a new release tag. The publish workflow only runs on `v*` tags that match the package version.
3. Update the release receipt in the CLI repository to the fixed version, so the language gate reopens on a version that the registry actually serves.
4. Post the reason and the registry link in the tracking issue.

## Why deletion is not part of the plan

Deleting a published artifact breaks every project that already resolved it and is blocked by the registries themselves. A yank or a deprecation keeps the artifact reachable for existing pins while new resolutions move to the fixed version. Maven Central has no equivalent at all, which is why its row only offers a higher version.

