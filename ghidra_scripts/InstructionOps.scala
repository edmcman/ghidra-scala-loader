// This script dumps various instruction operand information to help understand them.
// @author Ed Schwartz <eschwartz@cert.org>
// @category Functions

import ghidra.app.script.GhidraScript
import ghidra.program.model.listing.Function
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.symbol.Reference

import scala.jdk.CollectionConverters.*

class InstructionOps extends GhidraScript:

  override def run() =

    println("Starting InstructionOps script")
    
    val funcs = getCurrentProgram.getFunctionManager
      .getFunctions(true)
      .asInstanceOf[java.lang.Iterable[Function]]
      .asScala

    val l = getCurrentProgram.getListing

    funcs.foreach(f =>
      println(s"Function ${f.getName}")
      l.getInstructions(f.getBody, true).forEach(i =>
        val numops = i.getNumOperands
        println(s" Insn: ${i} has ${numops} operands")
        (0 to numops-1).foreach(opnum =>
          println(s"  Operand ${opnum} ${i.getDefaultOperandRepresentation(opnum)}")
          //println(s"  Operand ${opnum} is ${i.getOpObjects(opnum)}")
          val reftype = i.getOperandRefType(opnum)
          println(s"  Operand ${opnum} ref type ${reftype}")
          val optype = i.getOperandType(opnum)
          val optypestr = ghidra.program.model.lang.OperandType.toString(optype)
          println(s"  Operand ${opnum} op type ${optypestr}")
        )
      )
    )
