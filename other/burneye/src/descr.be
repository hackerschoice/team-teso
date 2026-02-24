# burneye protection description file
#
# comments must have "^#.*" match, i.e. no end of line comments


##################
# stub description

stubfile = "..."

# first encryption layer (glfsr)
stubcrypt0_at = 0x........
stubcrypt0_len = 0x........


#################
# hostify options
# XXX: allow multiple fingerprints here

fingerprint = { file "foofile" | block "..." }
fingerprint_tolerance = 2


##########################
# wrapped file description

infile = "input"
wrapfile = "output"

function_file = "..."
function_default { "default", encryption-mode }

# individual function definitions
function { "name", 0xvaddr, 0xlen, encryption-mode }


