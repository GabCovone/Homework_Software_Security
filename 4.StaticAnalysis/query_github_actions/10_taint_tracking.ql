/**
 * @name U-Boot RCE: Dati di rete non validati su memcpy
 * @description I dati interi controllati dalla rete vengono passati all'argomento della lunghezza di memcpy senza validazione, portando a potenziali vulnerabilità di Remote Code Execution.
 * @kind path-problem
 * @problem.severity critical
 * @id cpp/uboot/unvalidated-network-memcpy
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists(MacroInvocation mi |
      mi.getMacroName() in ["ntohs", "ntohl", "ntohll"] 
      and
      this = mi.getExpr()
    )
  }
}

module MyConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().hasName("memcpy")
      and
      sink.asExpr() = call.getArgument(2)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    none()
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink) 
select sink, source, sink, "Vulnerabilità RCE: input di rete non validato raggiunge memcpy"
