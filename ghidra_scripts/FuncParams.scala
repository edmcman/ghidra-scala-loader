//Decompile the function at the cursor, then print out the parameters it expects
//@category    Decompiler

// Use with https://github.com/edmcman/ghidra-scala-loader

import ghidra.app.decompiler._
import ghidra.app.script.GhidraScript

import ghidra.program.model.pcode._

class FuncParams extends GhidraScript {

  override def run() = {
    println("Hello world, I'm written in Scala...!")

    val ifc = new DecompInterface
    if (!ifc.openProgram(currentProgram)) {
      throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage)
    }

    val res = ifc.decompileFunction(currentProgram.getFunctionManager.getFunctionContaining(currentAddress), 60, null)
    val hf = res.getHighFunction

    val proto = hf.getFunctionPrototype
    val storage = (0 until (proto.getNumParams))
      .map(proto.getParam (_))
      .map(_.getStorage.toString).mkString(", ")

    println(s"Function ${hf.getFunction.getName}: ${storage}")
  }
}
