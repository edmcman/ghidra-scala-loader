// Because the scala compiler is written in Scala, it's a bit annoying to
// convert all the Java types to Scala types.  So we'll just make a simple
// driver function here in Scala.

package scalascriptprovider

import dotty.tools.dotc.Driver
import dotty.tools.dotc.reporting.{Diagnostic, ConsoleReporter}
import java.util.function.Consumer

class ScalaHelper:
    def compile(errorFn: Consumer[java.lang.String], outputDirectory: String, sourcePath: String, classPath: String, sourceFileName: String): Boolean =
        val args = Array(
            "-d", outputDirectory,
            "-sourcepath", sourcePath,
            "-classpath", classPath,
            sourceFileName
        )

        val driver = new Driver
        val reporter = new ConsoleReporter
        val run = driver.process(args, reporter)

        def diagnosticToString(diag: Diagnostic): String =
            s"${diag.level}: ${diag.message} at ${diag.pos.toString}\n"

        if reporter.hasErrors then
            errorFn.accept("Error(s) while compiling scala script:")
            reporter.allErrors.foreach(d => errorFn.accept(diagnosticToString(d)))

        !reporter.hasErrors
