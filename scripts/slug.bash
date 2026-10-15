# Bash completion for slug CLI
_slug_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local commands="add serve server connect pull push status diff list set web stop totp user rule audit env bench uninstall version help"

    case "${prev}" in
        slug)
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
        serve|server)
            COMPREPLY=( $(compgen -W "list stop -p --port -w --web" -- ${cur}) )
            return 0
            ;;
        connect)
            COMPREPLY=( $(compgen -W "list prune -i --host -p --port -o --otp -u --user --pass -w --web" -- ${cur}) )
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
        user)
            COMPREPLY=( $(compgen -W "add rm list" -- ${cur}) )
            return 0
            ;;
        uninstall)
            COMPREPLY=( $(compgen -W "-y --yes -n --no --keep-data" -- ${cur}) )
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
        local flags="-p --port -s --suite -t --ttl -ai --ai -d --daemon -i --host -o --otp -u --user --pass -r --role -w --web --dry-run --quick -q --json -y --yes -n --no --keep-data"
        COMPREPLY=( $(compgen -W "${flags}" -- ${cur}) )
        return 0
    fi
}

complete -F _slug_completion slug
