define g
stepi
x/i $pc
end
define h
x/2i $pc
tbreak *$_
continue
x/i $pc
end
