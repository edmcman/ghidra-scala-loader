// Identify the most referenced functions in a program
// @author Jeff Gennari <jsg@cert.org> / converted to Scala by Ed Schwartz <eschwartz@cert.org>
// @category Functions

import ghidra.app.script.GhidraScript
import ghidra.program.model.listing.Function
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.symbol.Reference

import scala.jdk.CollectionConverters.*

class PopularFunctions extends GhidraScript:

  override def run() =
    val p = getCurrentProgram
    val refmgr = p.getReferenceManager
    getCurrentProgram.getFunctionManager
      .getFunctions(true)
      .asInstanceOf[java.lang.Iterable[Function]]
      .asScala
      .map(f =>
        (f -> refmgr
          .getReferencesTo(f.getEntryPoint)
          .asInstanceOf[java.lang.Iterable[Reference]]
          .asScala
          // .filter(_.getReferenceType.isCall)
          .size)
      )
      .toSeq
      .sortWith(_._2 > _._2)
      .take(20)
      .foreach{case (f,cnt) => println(s"Function ${f.getName} (${f.getEntryPoint}) is referenced $cnt times")}
