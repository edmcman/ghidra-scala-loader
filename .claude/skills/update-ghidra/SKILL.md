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

## Step 2: Update `.github/ghidra-versions.json`

1. Set `latest` to `$ARGUMENTS`.
2. Append an entry to `include` with string fields `ghidra`, `java`, and `gradle`.
3. Preserve existing entries, including upstream `master`. Use the JDK required
   by the new Ghidra version and a compatible Gradle version. Ghidra 12.2 uses
   Java 25 and Gradle 9.1.0; earlier Java 17/21 targets use Gradle 8.7.

Both CI and tag releases use this matrix through `.github/workflows/build.yml`.
README version badges read the same JSON file. There is no separate test-workflow
version to update.

## Step 3: Update `.devcontainer/devcontainer.json`

1. Select the image for the required JDK: Ghidra 12.2 uses `mcr.microsoft.com/devcontainers/java:1-25`, 11.2–12.1.x use `java:1-21`, and older targets use Java 17.
2. Update the `postCreateCommand` with the new download URL and ZIP filename
3. Update `GHIDRA_INSTALL_DIR` to use the new Ghidra directory name (e.g., `ghidra_12.1_PUBLIC`)

The Ghidra directory name comes from the ZIP: `ghidra_12.1_PUBLIC_20260513.zip` extracts to `ghidra_12.1_PUBLIC/`.

## Step 4: Build and test

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

## Step 5: Commit and create PR

Commit all changes on a branch named `ghidra-$ARGUMENTS`, push to `origin`, and open a PR to `edmcman/ghidra-scala-loader`. `dangerouslyDisableSandbox: true` is needed for the push (per this project's git-push credential constraint).

## Step 6: Monitor PR checks

Watch the GitHub Actions CI checks on the PR and report back when they complete. Use `gh pr checks <PR_NUMBER>` to check status and `gh run view <RUN_ID> --log-failed` to diagnose failures. CI builds and tests the entire matrix, including upstream master. Releases run only when a project tag is pushed; do not push a release tag as part of a compatibility update.

## Step 7: Report

Summarize what was changed and whether the build/test passed. If there are source code compatibility issues with the new Ghidra version, report them.