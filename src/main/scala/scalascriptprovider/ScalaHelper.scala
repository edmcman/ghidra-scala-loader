// Because the scala compiler is written in Scala, it's a bit annoying to
// convert all the Java types to Scala types.  So we'll just make a simple
// driver function here in Scala.

package scalascriptprovider

import scala.tools.nsc.{MainClass, CompilerCommand, Settings}
import scala.tools.nsc.reporters.StoreReporter
import java.util.function.Consumer

class ScalaHelper {
    def compile(errorFn: Consumer[java.lang.String], outputDirectory: String, sourcePath: String, classPath: String, sourceFileName: String): Boolean = {
        val settings = new Settings()

        val args = List("-g:source",
            "-d", outputDirectory,
            "-sourcepath", sourcePath,
            "-classpath", classPath,
            sourceFileName)

        val command = new CompilerCommand(args.toList, settings)
        val reporter = new scala.tools.nsc.reporters.StoreReporter
        val compiler = new scala.tools.nsc.Global(settings, reporter)
        val run = new compiler.Run()
        run.compile(command.files)

        def infoToString(info: reporter.Info): String = {
            s"${info.severity}: " + scala.reflect.internal.util.Position.formatMessage(info.pos, info.msg + "\n", true) + "\n"
        }

        if (reporter.hasErrors) {
            errorFn.accept("Error(s) while compiling scala script:")
            reporter.infos.foreach(i => errorFn.accept (infoToString (i)))
        }
        !reporter.hasErrors
    }
}