//Prints high p-code.
//@category    Examples
//@menupath    Help.Examples.Print High P-code (Scala)

import ghidra.app.script.GhidraScript
import ghidra.app.decompiler._
import scala.collection.JavaConverters._

class PrintHighPCode extends GhidraScript {

  override def run() = {
    val ifc = new DecompInterface
    if (!ifc.openProgram(currentProgram)) {
      throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage)
    }

    ifc.setSimplificationStyle("decompiler")

    val res = ifc.decompileFunction(currentProgram.getFunctionManager.getFunctionContaining(currentAddress), 60, null)
    val hf = res.getHighFunction

    val hfblocks = hf.getBasicBlocks.asScala

    hfblocks.foreach (block => {
      println(s"Beginning of ${block.toString}")
      block.getIterator.asScala.foreach (inst => {
        println(inst.toString)
      })
    })

  }
}

