//Writes "Hello World" to console.
//@category    Examples
//@menupath    Help.Examples.Hello World (Scala)
//@toolbar    world.png

import ghidra.app.script.GhidraScript

class HelloWorldScript extends GhidraScript {

  override def run() = println("Hello world, I'm written in Scala!")
}
