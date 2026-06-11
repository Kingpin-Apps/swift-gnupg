build:
    swift build

# --no-parallel is required: GnuPG's output collector dispatches blocking pipe
# readers to GCD's global queue and parks a coordinator thread in
# DispatchGroup.wait() (see collectOutput in GnuPG.swift). Under the parallel
# runner, many concurrent gpg calls — including the synchronous GnuPG.init path —
# each demand reader threads plus a parked coordinator, exhausting the pools and
# deadlocking (every stuck thread sits in collectOutput -> _dispatch_group_wait).
# Lifting this needs a non-blocking I/O rewrite (readabilityHandler/async-bytes),
# not just async wrappers. Suites are also marked .serialized for in-suite
# isolation when running filtered subsets.
test:
    swift test --no-parallel

release:
    swift build -c release

# Update changelog
changelog:
    cz ch

# Bump version according to changelog (tests must pass first)
bump: test changelog
    cz bump
