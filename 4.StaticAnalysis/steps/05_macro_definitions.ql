import cpp

from Macro v
where v.getName() in ["ntohl", "ntohll", "ntohs"]
select v, "a macro for network variables"