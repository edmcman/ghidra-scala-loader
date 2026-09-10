---
name: update-ghidra
description: Update the project for a new Ghidra version
---

# Update Ghidra to $ARGUMENTS

Update this project to support Ghidra version $ARGUMENTS.

## Step 1: Look up the Ghidra release

Use `gh api` to find the release details for Ghidra $ARGUMENTS:

```
gh api repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_$ARGUMENTS_build
```

Extract from the response:
- The exact ZIP filename (matches `ghidra_*_PUBLIC_*.zip`)
- The download URL (or construct it: `https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_$ARGUMENTS_build/<filename>`)
- The release date (needed for the devcontainer)

If the tag lookup fails, try a web search for "Ghidra $ARGUMENTS release" on github.com/NationalSecurityAgency/ghidra/releases.

## Step 2: Update `azure-pipelines.yml`

1. Change the `latest_ghidra` variable from the current version to `$ARGUMENTS`
2. Add a new matrix entry after the last existing ghidra entry. Follow this pattern (use the correct version, URL, and filename from step 1):

```yaml
      ghidra<key>:
        ghidraUrl: "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_<version>_build/<filename>.zip"
        ghidraVersion: "<version>"
        useJava21: true
```

The key is the version with dots removed (e.g., `12.1` → `ghidra121`).

## Step 3: Update `.github/workflows/test.yml`

Change the `GHIDRA_VERSION` env var to `"$ARGUMENTS"`.

## Step 4: Update `.devcontainer/devcontainer.json`

1. If the Ghidra version requires Java 21 (all 11.2+), update the image to `mcr.microsoft.com/devcontainers/java:1-21`. Otherwise use `java:0-17`.
2. Update the `postCreateCommand` with the new download URL and ZIP filename
3. Update `GHIDRA_INSTALL_DIR` to use the new Ghidra directory name (e.g., `ghidra_12.1_PUBLIC`)

The Ghidra directory name comes from the ZIP: `ghidra_12.1_PUBLIC_20260513.zip` extracts to `ghidra_12.1_PUBLIC/`.

## Step 5: Build and test

1. Check if the new Ghidra version is already installed locally:
   ```
   ls ~/Ghidra/ | grep $ARGUMENTS
   ```
2. If not installed, download it:
   ```
   cd ~/Ghidra && wget <url> && unzip <filename>
   ```
3. Build the extension against the new Ghidra:
   ```
   GHIDRA_INSTALL_DIR=~/Ghidra/ghidra_<version>_PUBLIC ./gradlew clean build
   ```
4. Install and test with analyzeHeadless:
   ```
   GHIDRA_INSTALL_DIR=~/Ghidra/ghidra_<version>_PUBLIC ./gradlew install
   mkdir -p /tmp/ghidra_test && ~/Ghidra/ghidra_<version>_PUBLIC/support/analyzeHeadless /tmp/ghidra_test TestProject -import /bin/ls -noanalysis -postScript HelloWorldScript.scala -deleteProject 2>&1 | tee /tmp/ghidra_test/output.log
   grep -q "Hello world, I'm written in Scala 3!" /tmp/ghidra_test/output.log
   ```

## Step 6: Commit and create PR

Commit all changes on a branch named `ghidra-$ARGUMENTS`, push to `origin`, and open a PR to `edmcman/ghidra-scala-loader`. `dangerouslyDisableSandbox: true` is needed for the push (per this project's git-push credential constraint).

## Step 7: Monitor PR checks

Watch the CI checks on the PR (both the GitHub Actions workflow and the Azure Pipelines build show up as PR status checks) and report back when they complete. Use `gh pr checks <PR_NUMBER>` to check status. If a check fails, pull the logs (`gh run view <RUN_ID> --log-failed` for the Actions job, or the Azure Pipelines UI for that build) to diagnose.

## Step 8: Report

Summarize what was changed and whether the build/test passed. If there are source code compatibility issues with the new Ghidra version, report them.