{
    /bin/bash -c "$*" || powershell -c "$*"
} || {
    echo 'error initializing bash'
}