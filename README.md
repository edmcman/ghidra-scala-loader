[![CI](https://github.com/edmcman/ghidra-scala-loader/actions/workflows/test.yml/badge.svg)](https://github.com/edmcman/ghidra-scala-loader/actions/workflows/test.yml)
![Latest Ghidra version](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fedmcman%2Fghidra-scala-loader%2Fmaster%2F.github%2Fghidra-versions.json&query=%24.latest&label=Latest%20Ghidra%20version)

# Introduction #

Love ghidra but hate Java?  If so, then this extension is for you!
Just load this extension, and Ghidra will see and be able to load any
scripts written in Scala.  Just make sure their filename ends in
`.scala` and drop them into any `ghidra_scripts` directory.

# Compilation #

If you want to build the extension yourself, make sure you have
the JDK required by your Ghidra version installed, and then run
`GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew buildExtension`.  If
all goes well, you should get a message like:

```
> Task :buildExtension

Created ghidra_9.2_PUBLIC_20201117_ghidra-scala-loader.zip in /home/ed/Documents/ghidra-scala-loader/dist

BUILD SUCCESSFUL in 11s
4 actionable tasks: 1 executed, 3 up-to-date
```

In this case, the file
`dist/ghidra_9.2_PUBLIC_20201117_ghidra-scala-loader.zip` is your
newly built extension.

# Installation #

Download the extension ZIP matching your Ghidra version from the
[GitHub releases](https://github.com/edmcman/ghidra-scala-loader/releases),
or build it using the instructions above.

Start Ghidra, and in the initial window (i.e., _not_ the Code
Browser), open the `File` menu, and select `Install Extensions`.
Click the small plus icon in the top right of the window, and select
the extension zip file that you built above.  This should add an
extension into the list, `ScalaScriptProvider`.  Make sure the
checkbox is ticked, and click OK to close the window.  Ghidra will
tell you that you need to restart to load the extension.  Do so.

To make sure the extension loaded correctly, open the Code Browser,
and under the `Window` menu, select `Script Manager`.  If all is well,
you should see a `HelloWorld.scala` script.  Right click it, and
select `Run`.  You should see the hello world message print out to the
Console.

# Requirements #

Ghidra 12.2 requires JDK 25 and Gradle 9.1 or newer (provided by `./gradlew`).
For older supported Ghidra releases, use JDK 17 or 21 and the Gradle version
specified in their `Ghidra/application.properties` instead of the wrapper.
The prebuilt GitHub extensions
will only work with the JDK version required by the Ghidra version they are
built for.  If you want to use a different JDK version, you will need to build
the extension yourself.

# Supported Versions #

![Supported Ghidra versions](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fedmcman%2Fghidra-scala-loader%2Fmaster%2F.github%2Fghidra-versions.json&query=%24.include%5B*%5D.ghidra&label=Supported%20Ghidra%20versions)

The build matrix is maintained in [.github/ghidra-versions.json](.github/ghidra-versions.json).
CI builds and runs `HelloWorldScript.scala` in headless Ghidra for every listed
version, including upstream `master`, on branch pushes, pull requests to
`master`, and Sundays at 00:00 UTC. CI can also be run manually. Each run
provides extension ZIPs and diagnostic logs as workflow artifacts.

# Releases #

Push a project version tag in `vMAJOR.MINOR.PATCH` format (for example, `v1.0.0`) to build and test the tagged
commit across the complete matrix. Once all targets pass, GitHub Actions
publishes one release named after the tag containing all extension ZIPs.
The release notes identify the upstream Ghidra commit used for the `master`
build. The workflow filters for version-shaped tags and validates the exact
format before building. Version components must be nonnegative integers without
leading zeros; suffixes are not accepted. Other tags and branch builds do not publish.
Published ZIP filenames identify their Ghidra target and stay the same across
reruns, which replace matching assets without deleting the tag.
Uploads are staged in a draft release and published only after every upload
succeeds. Updating an existing release temporarily unpublishes it. If uploading
fails, the release stays in draft until a successful rerun; partial bundles are
not published.
Existing `ghidra-<version>` releases remain available but are no longer refreshed.

Publishing uses the built-in `GITHUB_TOKEN`; no deploy key or extra secret is
required. Only the publishing job has permission to write repository contents.

When switching over, disable the old pipeline in Azure DevOps and replace any
required Azure build status in GitHub branch protection with the new Actions
checks after the first successful CI run. Removing the Azure YAML alone does
not disable its service integration.
