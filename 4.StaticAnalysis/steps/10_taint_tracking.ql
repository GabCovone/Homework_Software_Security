/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
// Required to use GuardCondition and analyze 'if' statements
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
    exists(GuardCondition guard, RelationalOperation relOp, Variable v |
      // 1. Trattiamo la guardia esplicitamente come un'operazione relazionale (es. <, >, <=, >=)
      relOp = guard
      and
      // 2. Il nodo "tainted" che stiamo tracciando è un accesso a una specifica variabile 'v'
      node.asExpr() = v.getAnAccess()
      and
      // 3. Assicuriamoci che l'operazione relazionale stia effettivamente controllando quella stessa variabile 'v'
      // (controllando se appare nell'operando di sinistra o di destra)
      (relOp.getLeftOperand() = v.getAnAccess() or relOp.getRightOperand() = v.getAnAccess())
      and
      // 4. La guardia controlla il basic block in cui si trova il nodo (nel ramo 'true')
      guard.controls(node.asExpr().getBasicBlock(), true)
    )
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink) 
select sink, source, sink, "Network byte swap flows to memcpy without validation"