[![Build Status](https://dev.azure.com/edmcman/ghidra-scala-loader/_apis/build/status/edmcman.ghidra-scala-loader?branchName=master)](https://dev.azure.com/edmcman/ghidra-scala-loader/_build/latest?definitionId=4&branchName=master)

# Introduction #

Love ghidra but hate Java?  If so, then this extension is for you!
Just load this extension, and Ghidra will see and be able to load any
scripts written in Scala.  Just make sure their filename ends in
`.scala` and drop them into any `ghidra_scripts` directory.

# Compilation #

If you want to build the extension yourself, make sure you have
`gradle` installed, and then run
`GHIDRA_INSTALL_DIR=/path/to/ghidra_9.2 gradle buildExtension`.  If
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
