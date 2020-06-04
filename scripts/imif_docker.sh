#!/bin/bash

print_usage() {
    echo "Usage: $(basename $0) <command> [args]"
    echo "  commands:"
    echo "      init                                                             - One-time docker configuration initialization."
    echo "      pull <docker image name: centos-imif-run-xx:xxx-xxxx>            - Pull docker image form docker registry."
    echo "      run  <docker image name: centos-imif-run-xx:xxx-xxxx> [options]  - Create container from image, set IP via DHCP and run."
    echo "           options:   "
    echo "             bash - Drop to bash and attach devices."
    echo "             mgmt - Run all imif services and management."
    echo "             mgmt_only - Run management without imif services."
    echo "      attach  <docker container name>                                  - Attach to imif CLI in running container."
    echo "      help                                                             - Print command help."
}

load_configuration() {
    if [ -r ./imif_docker.rc ]; then
        source ./imif_docker.rc
    else
        echo "Error loading 'imif_docker.rc' !"
        exit 1
    fi

    if [ -z "$IMIF_DOCKER_IFACE" ] || [ "${IMIF_DOCKER_IFACE:0:1}" = '<' ]; then
        echo "Error, IMIF_DOCKER_IFACE not set"
        exit 1
    elif [ -z "$IMIF_DOCKER_USE_DHCP" ] || [ "${IMIF_DOCKER_USE_DHCP:0:1}" = '<' ]; then
        echo "Error, IMIF_DOCKER_USE_DHCP not set."
        exit 1
    fi
    if [ "$IMIF_DOCKER_USE_DHCP" != "y" ]; then
        if [ -z "$IMIF_DOCKER_STATIC_IP" ] || [ "${IMIF_DOCKER_STATIC_IP:0:1}" == '<' ]; then
            echo "Error, IMIF_DOCKER_STATIC_IP not set."
            exit 1
        elif [ -z "$IMIF_DOCKER_GATEWAY_IP" ] || [ "${IMIF_DOCKER_GATEWAY_IP:0:1}" == '<' ]; then
            echo "Error, IMIF_DOCKER_GATEWAY_IP not set."
            exit 1
        fi
    fi    
}

if [ "$1" == "init" ]; then

    load_configuration

    if [ -z "$IMIF_DOCKER_REGISTRY"  ] || [ "${IMIF_DOCKER_REGISTRY:0:1}" = '<' ]; then
        echo "Error, IMIF_DOCKER_REGISTRY not set."
        exit 1
    elif [ -z "$IMIF_DOCKER_REGISTRY_PORT" ] || [ "${IMIF_DOCKER_REGISTRY_PORT:0:1}" = '<' ]; then
        echo "Error, IMIF_DOCKER_REGISTRY_PORT not set."
        exit 1
    elif [ -z "$IMIF_DOCKER_REGISTRY_USER" ] || [ "${IMIF_DOCKER_REGISTRY_USER:0:1}" = '<' ]; then
        echo "Error, IMIF_DOCKER_REGISTRY_USER not set."
        exit 1
    fi
    
    echo "Enter docker registry password:"
    read -s IMIF_DOCKER_REGISTRY_PASS
    if [ -z "$IMIF_DOCKER_REGISTRY_PASS" ]; then echo "Error, bad password."; exit 1; fi

    echo "Logging in to docker registry..."
    echo  $IMIF_DOCKER_REGISTRY_PASS | docker login $IMIF_DOCKER_REGISTRY:5000 --username $IMIF_DOCKER_REGISTRY_USER --password-stdin
    unset IMIF_DOCKER_REGISTRY_PASS

elif [ "$1" == "pull" ] || [ "$1" == "run" ]; then
    if [ -z "$2" ]; then
        echo "Error, please provide image name as the second argument."
        exit 1
    fi
    IMIF_DOCKER_IMAGE="$2"

    load_configuration

    if [ "$1" = "pull" ]; then
        echo "Pulling image $IMIF_DOCKER_IMAGE from $IMIF_DOCKER_REGISTRY..."
        docker pull "$IMIF_DOCKER_REGISTRY:$IMIF_DOCKER_REGISTRY_PORT/$IMIF_DOCKER_IMAGE"

    elif [ "$1" = "run" ]; then
        ETH_BASE="${IMIF_DOCKER_IFACE}"
        ETH_VLAN="${IMIF_DOCKER_IFACE}.1"

        if [ "$IMIF_DOCKER_USE_DHCP" == "y" ]; then
            if [ ! -f  "imif_docker_dhcp.sh" ]; then
                echo "Obtaining DHCP IP for docker requiers script 'imif_docker_dhcp.sh' that sets IMIF_IP and IMIF_GATEWAY_IP."
                echo 'Error, "imif_docker_dhcp.sh" not found. Consider using IMIF_DOCKER_USE_DHCP="n"'
                echo "Aborting!"
                exit 1
            fi
            source imif_docker_dhcp.sh
            run_dhcp_client

        else # static IP
            echo "Using static IP configuration"
            IMIF_IP=$IMIF_DOCKER_STATIC_IP
            IMIF_GATEWAY_IP=$IMIF_DOCKER_GATEWAY_IP
        fi

        echo "Create docker network: IF=$ETH_BASE, IP=$IMIF_IP, GATEWAY=$IMIF_GATEWAY_IP"
        if [ ! -z "`docker network ls | grep imif_network`" ]; then
            docker network rm imif_network
        fi
        docker network create -d macvlan -o parent=$ETH_BASE --subnet=$IMIF_IP/24 --gateway=$IMIF_GATEWAY_IP imif_network

        GENERAL_OPTIONS=""
        IMIF_DOCKER_OPTIONS=("${IMIF_DOCKER_RUN_OPTIONS[@]}")
        for dev in "${IMIF_DOCKER_DEVICES[@]}"; do
            if [[ -c $dev || -d $dev ]]; then
                    IMIF_DOCKER_OPTIONS+=("--device=$dev")
            fi
        done

        if [ "$3" = "bash" ]; then
            IMIF_DOCKER_CMD="bash "
        else
            IMIF_DOCKER_CMD="/opt/intel/imif/bin/imif.sh "
            if [ "$3" = "mgmt_only" ]; then
                GENERAL_OPTIONS=${@:4}
                IMIF_DOCKER_CMD="${IMIF_DOCKER_CMD} -s ../config/services_mgmt_only.conf "
            elif [ "$3" = "mgmt" ]; then
                IMIF_DOCKER_CMD="${IMIF_DOCKER_CMD} -s ../config/services_mgmt.conf "
                GENERAL_OPTIONS=${@:4}
            else
                GENERAL_OPTIONS=${@:3}
                IMIF_DOCKER_CMD="$IMIF_DOCKER_CMD -s ../config/services.conf "
            fi

            if [ -z "$GENERAL_OPTIONS" ]; then
                GENERAL_OPTIONS="${GENERAL_OPTIONS} --bash"
                IMIF_DOCKER_OPTIONS+=('-d')
            fi
        fi
        IMIF_DOCKER_CMD="$IMIF_DOCKER_CMD $GENERAL_OPTIONS"

        if [ ! -z "$IMIF_DOCKER_REGISTRY" ]; then
            IMIF_DOCKER_IMAGE_FULL_NAME="$IMIF_DOCKER_REGISTRY:$IMIF_DOCKER_REGISTRY_PORT/$IMIF_DOCKER_IMAGE"
        else
            IMIF_DOCKER_IMAGE_FULL_NAME="$IMIF_DOCKER_IMAGE"
        fi

        echo "Running container:"
        echo "  IMAGE=$IMIF_DOCKER_IMAGE_FULL_NAME"
        echo "  IP=$IMIF_IP"
        echo "  GATEWAY=$IMIF_GATEWAY_IP"
        echo "  DOCKER_OPTIONS=${IMIF_DOCKER_OPTIONS[*]}"
        echo "  DOCKER_CMD=$IMIF_DOCKER_CMD"
        echo ""
        echo ""
        docker run --rm --net imif_network --ip=$IMIF_IP "${IMIF_DOCKER_OPTIONS[@]}" \
        -ti $IMIF_DOCKER_IMAGE_FULL_NAME $IMIF_DOCKER_CMD
    fi
elif [ "$1" == "attach" ]; then
    if [ -z "$2" ]; then
        echo "Error, please provide container image name as the second argument."
        docker ps
        exit 1
    fi
    IMIF_DOCKER_CONTAINER="$2"
    docker attach "$IMIF_DOCKER_CONTAINER"
    if [ $? -ne 0 ]; then docker ps; fi
elif [ "$1" == "help" ]; then
    print_usage
else
    echo "Error, Unknown command."
    print_usage
    exit 1
fi
