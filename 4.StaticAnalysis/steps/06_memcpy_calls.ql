import cpp


from FunctionCall call
where
    call.getTarget().hasName("memcpy")
select call