build:
    swift build

# Swift Testing's parallel runner deadlocks when all suites spawn gpg-agent
# concurrently, so we force --no-parallel. Suites are also marked .serialized
# in source for in-suite isolation when running filtered subsets.
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
