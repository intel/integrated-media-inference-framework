#!/bin/bash

run_command() {
    user=$1
    command=$2

    if [ $EUID != 0 ] && [ $user != `whoami` ]
    then
        echo "Can't run command since I'm not root and it's not me. user=$user command=$command"
        return
    fi

    if [ "$user" = `whoami` ]
    then
        eval $command
    else
        eval su $user -c \"$command\"
    fi
}

parse_config() {
    conf_file=$1

    local get_user=1
    content=`cat $conf_file 2> /dev/null` 

    IFS=$'\n'       # make newlines the only separator
    set -f          # disable globbing
    for line in $content
    do
        [[ $line =~ ^[[:space:]]*\#.* ]] && continue
        
        config_name=$( [[ $line =~ ^\[ ]] && grep -Po '\[\K[^]]*' <<< $line )
        [ ! -z $config_name ] && echo "Executing $config_name" && continue

        arg=${line%=*}
        value=${line#*=}

        if [ $get_user = 1 ]
        then
            [ $arg != "USER" ] && echo "Bad config file - expected USER, but it's empty ($arg)" && exit 0
            [ -z $value ] && echo "Bad config file - expected USER, but it's empty" && exit 0
            [[ $value =~ ^[[:space:]]*\#.* ]] && echo "Bad config file - expected USER, but it's commented" && exit 0

            echo "Run as user $value"

            user_commands+=( "$value")
            get_user=0
        else
            [ $arg != "COMMAND" ] && echo "Bad config file - expected command, but it's empty" && exit 0;
            [ -z $value ] && echo "Bad config file - expected command, but it's empty" && exit 0;
            [[ $value =~ ^[[:space:]]*\#.* ]] && echo "Bad config file - expected command, but it's commented" && exit 0;

            echo "Command $value"
            echo

            user_commands+=( "$value")
            get_user=1
        fi
    done

    [ $get_user = 0 ] && echo "Bad config file - expected COMMAND, but didn't find it" && exit 0;
    echo
}

run_services() {
    declare -a user_commands
    parse_config $1

    i=0
    while [ $i -lt ${#user_commands[@]} ] 
    do
        uname=${user_commands[i]}
        command=${user_commands[i+1]}
        i=$[$i+2]

        run_command $uname $command
    done

}

start() {
    echo "IIIIIIIIII MMMMMMMM               MMMMMMMM IIIIIIIIII FFFFFFFFFFFFFFFFFFF"
    echo "I::::::::I M:::::::M             M:::::::M I::::::::I F:::::::::::::::::F"
    echo "I::::::::I M::::::::M           M::::::::M I::::::::I F:::::::::::::::::F"
    echo "II::::::II M:::::::::M         M:::::::::M II::::::II F:::::::FFFFFFFFFF "
    echo "  I::::I   M::::::::::M       M::::::::::M   I::::I   F:::::::F          "
    echo "  I::::I   M:::::::::::M     M:::::::::::M   I::::I   F:::::::F          "
    echo "  I::::I   M:::::::M::::M   M::::M:::::::M   I::::I   F:::::::FFFFFFFFFFF"
    echo "  I::::I   M::::::M M::::M M::::M M::::::M   I::::I   F:::::::::::::::::F"
    echo "  I::::I   M::::::M  M::::M::::M  M::::::M   I::::I   F:::::::::::::::::F"
    echo "  I::::I   M::::::M   M:::::::M   M::::::M   I::::I   F::::FFFFFFFFFFFFFF"
    echo "  I::::I   M::::::M    M:::::M    M::::::M   I::::I   F::::F             "
    echo "  I::::I   M::::::M     MMMMM     M::::::M   I::::I   F::::F             "
    echo "II::::::II M::::::M               M::::::M II::::::II F::::F             "
    echo "I::::::::I M::::::M               M::::::M I::::::::I F::::F             "
    echo "I::::::::I M::::::M               M::::::M I::::::::I F::::F             "
    echo "IIIIIIIIII MMMMMMMM               MMMMMMMM IIIIIIIIII FFFFFF             "
    echo ""

    cd $SCRIPT_PATH

    run_services $SERVICES_CONF_FILE

    echo "IMIF Started!"
    cd - &> /dev/null
}

free_ipcs() {
    IPCS_M=$(ipcs -m | grep -v Shared | grep -v shmid | awk '{print $2}' | sed '/^$/d') && echo $IPCS_M &&  for id in $IPCS_M; do ipcrm -m $id; done 
}

status() {
    echo "======"
    echo "Status"
    echo "======"
    echo "Running processes:"
    ps -ef | awk '{ $1="";print}' | grep -v $0 | grep imif_ | grep -v grep | grep -v log
}

stop() {
    echo "======================"
    echo "Stopping imif services"
    echo "======================"
    signal=${1-15}
    ps -ef | awk '{ $1="";print}' | grep -v $0 | grep imif_ | grep -v grep | grep -v log | awk '{print $1}' | xargs kill -$signal 2&>/dev/null
    sleep 1
    status
}

kill_forced() {
    echo "====================="
    echo "Killing imif services"
    echo "====================="
    SEC_TIMER=0
    while [ $SEC_TIMER -lt 5 ] 
    do
        STATUS=$(ps -ef | awk '{ $1="";print}' | grep -v $0 | grep imif_ | grep -v grep | grep -v log)
        if [ -z "$STATUS" ]; then
            echo "killall done"
            free_ipcs
            return
        fi
        stop
        sleep 1
        SEC_TIMER=`expr $SEC_TIMER + 1`
    done
    echo -e "\nkillall timeout!"
    stop 9
    free_ipcs
}

run_cli() {
    unset http_proxy && unset https_proxy && $SCRIPT_PATH/imif_cli "$@"
}

usage() {
    echo "Usage: $(basename $0) <command> [-h] [load config_file] [--block]"
    echo "  commands:"
    echo "      help            - show this help menu"
    echo "      start (default) - start all imif services"
    echo "      status          - show imif services status"
    echo "      stop            - stop all imif services"
    echo "      kill            - force stop all imif services"
    echo "      cli             - start imif cli"
    echo "      bash            - Drop to bash with imif environment set"
    echo "  options:"
    echo "      --cli <cmd1,cmd2,cmd3> - after start, drop to cli and execute commands. On exit stop all imif services "
    echo "      -s --services - override default services configuration file"
    echo "      --bash - fall to bash before exiting"
    echo "      --     - break args parsing"
}

parse_args() {
    POSITIONAL=()
    while [[ $# -gt 0 ]]
    do
    key="$1"

    case $key in
    -s|--services)
        SERVICES_CONF_FILE="$2"
        shift # past argument
        shift # past value
        ;;
    help)
        usage
        shift # past argument
        exit 0
        ;;
    bash)
        echo "Dropping to bash with imif environment."
        bash
        shift # past argument
        exit 0
        ;;
    stop)
        stop
        shift # past argument
        exit 0
        ;;
    kill)
        kill_forced
        shift # past argument
        exit 0
        ;;
    status)
        status
        shift # past argument
        exit 0
        ;;
    --bash)
        FALL_TO_BASH=1
        shift # past argument
        ;;
    --cli)
        break
        ;;
    --)
        shift
        break
        ;;
    *)    # unknown option
        POSITIONAL+=("$1") # save it in an array for later
        shift # past argument
        ;;
    esac
    done

    POSITIONAL+=("$@")
}

main() {

    if [ "$1" = "cli" ]; then
        run_cli ${@:2}
    elif [ -z "$1" ] || [ "$1" = "start" ] || [ "$1" = "--cli" ]; then
        kill_forced
        rm -rf $SCRIPT_PATH/../logs/*
        rm -rf $SCRIPT_PATH/../temp/*
        rm -rf $SCRIPT_PATH/_*.*
        
        start
        
        if [ "$1" = "--cli" ]; then
            sleep 2
            run_cli ${@:2}
            stop
        elif [ "$2" = "--cli" ]; then
            sleep 2
            run_cli ${@:3}
            stop
        fi

    else
        echo "Bad command! -->" "$@"
        exit 1
    fi

    [ ! -z $FALL_TO_BASH ] && [ $FALL_TO_BASH -gt 0 ] && bash

}


SCRIPT_PATH=$(dirname $(realpath $0))
ROOTPATH=${SCRIPT_PATH%"opt/intel/imif/bin"}
export LD_LIBRARY_PATH=$ROOTPATH/opt/intel/imif/lib:$ROOTPATH/opt/intel/imif/tools/lib:$LD_LIBRARY_PATH:$ROOTPATH/lib:$ROOTPATH/usr/lib:$ROOTPATH/usr/lib/dri:$ROOTPATH/usr/lib/mfx:$ROOTPATH/usr/share/openvino/lib
export LIBVA_DRIVERS_PATH=$ROOTPATH/usr/lib/dri 
export LIBVA_DRIVER_NAME=iHD
export LOGNAME=$USER
export no_proxy=localhost,127.0.0.0/8,::1

parse_args $@
set -- "${POSITIONAL[@]}" # restore positional parameters

[ -z $SERVICES_CONF_FILE ] && SERVICES_CONF_FILE="../config/services_mgmt.conf"

main $@
exit 0
