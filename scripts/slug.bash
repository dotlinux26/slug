# Bash completion for slug CLI
_slug_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local commands="add connect pull push status diff list stop rule audit env bench version help"

    case "${prev}" in
        slug)
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
        -s|--suite)
            COMPREPLY=( $(compgen -W "1 2 3 classical modern pqc" -- ${cur}) )
            return 0
            ;;
        rule)
            COMPREPLY=( $(compgen -W "list block allow rm" -- ${cur}) )
            return 0
            ;;
        audit)
            COMPREPLY=( $(compgen -W "list recheck allow" -- ${cur}) )
            return 0
            ;;
        env)
            COMPREPLY=( $(compgen -W "init run" -- ${cur}) )
            return 0
            ;;
        bench)
            COMPREPLY=( $(compgen -W "--quick -q --json" -- ${cur}) )
            return 0
            ;;
        *)
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        local flags="-p -s --suite --ttl -ai --ai --daemon -d -i --ip -o --totp --user -u --dry-run --quick -q --json"
        COMPREPLY=( $(compgen -W "${flags}" -- ${cur}) )
        return 0
    fi
}

complete -F _slug_completion slug
