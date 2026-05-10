import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    // TODO: replace <class> and <var>
    exists(MacroInvocation mi |
      // TODO: <condition>
      mi.getMacro().getName() in ["ntohs", "ntohl", "ntohll"]
      and
      this = mi.getExpr()
    )
  }
}

from NetworkByteSwap n
select n, "Network byte swap"