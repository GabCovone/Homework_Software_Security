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
 /*
  predicate isBarrier(DataFlow::Node node) {
    exists(GuardCondition guard, Variable access |
      // 1. The guard is a relational comparison (e.g., length <= max)
      guard instanceof RelationalOperation
      and
      // 2. The variable being checked is our tainted node
      access.getAnAccess() = node.asExpr()
      and
      // 3. The guard successfully controls the basic block where the node lives
      guard.controls(node.asExpr().getBasicBlock(), _)
    )
  }
}

*/
module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink) 
select sink, source, sink, "Network byte swap flows to memcpy without validation"