#!/bin/bash

# Load environment settings
if [ ! -f "${IMIF_ENV_FILE}" ]; then
  export IMIF_ENV_FILE="env.sh"
fi
source $IMIF_ENV_FILE
if [ $? -ne 0 ]; then
  echo "ERROR: can't source IMIF_ENV_FILE: '${IMIF_ENV_FILE}'"
  exit 1
fi

# Proxy environment variables
if [ ! -z "${HTTP_PROXY}" ]; then
  export http_proxy=${HTTP_PROXY}
fi
if [ ! -z "${HTTPS_PROXY}" ]; then
  export https_proxy=${HTTPS_PROXY}
fi
if [ ! -z "${FTP_PROXY}" ]; then
  export ftp_proxy=${FTP_PROXY}
fi
if [ ! -z "${NO_PROXY}" ]; then
  export no_proxy=${NO_PROXY}
fi

# Safe run
function run() {
  bash -c "$1"
  if [ $? -ne 0 ]; then
    ERROR=${2:-"Command '$1' failed!"}
    echo "ERROR: $ERROR"
    exit 1
  fi
}

function gitrev() {
    GIT_REV=`git describe 2>/dev/null`
    if [ $? -ne 0 ]; then
      COMMIT_CNT=`git rev-list --all --count`
      COMMIT_HASH=`git rev-parse --short HEAD`
      GIT_REV="0.0.0-$COMMIT_CNT-g$COMMIT_HASH"
    fi
    echo "$GIT_REV"
}

function validate_docker_install() {
  # Check if docker is installed
  run "which docker > /dev/null 2>&1" "IMIF_NATIVE_BUILD not defined and Docker is not installed!"
  run "docker info > /dev/null 2>&1" "Docker is installed, but user '$USER' doesn't have permissions to use it!"
  return 0
}

function parse_docker_tag() {
  
  if [ -z "${DOCKER_IMAGE}" ]; then
    echo "Error, DOCKER_IMAGE not set!"
    exit 1
  fi

  IFS=":" tokens=( ${DOCKER_IMAGE} )
  DOCKER_IMAGE_NAME="imif-"${tokens[0]}
  DOCKER_IMAGE_TAG=${tokens[1]}
  unset IFS
}

function docker_build() {
  
  validate_docker_install
  parse_docker_tag

  # Copy docker build files
  cp -ar "docker/run/${DOCKER_IMAGE_NAME}.${DOCKER_IMAGE_TAG}.Dockerfile" _build_/_install_/Dockerfile
  cp -ar docker/run/scripts/* _build_/_install_/
  
  cd _build_/_install_

  # Build the container
  BUILD_DOCKER_IMAGE=${1:-"${DOCKER_IMAGE_NAME}-${DOCKER_IMAGE_TAG}-run-$USER:$(gitrev)"}
  echo "Build docker image: "${BUILD_DOCKER_IMAGE}
  docker build \
  --build-arg http_proxy \
  --build-arg https_proxy \
  --build-arg ftp_proxy \
  --build-arg no_proxy \
  -t "${BUILD_DOCKER_IMAGE}" .
  if [ $? -ne 0 ]; then exit 1; fi
  printf "\nDocker image is ready: ${BUILD_DOCKER_IMAGE}\n"
  cd -
}

function docker_push() {
  
  validate_docker_install
  parse_docker_tag

  # Check environment variables
  if [[ -z "${IMIF_DOCKER_REGISTRY}" ]]; then
    echo "ERROR: IMIF_DOCKER_REGISTRY not set (e.g. registry.intel.com:5000)"
    exit 1
  fi

  # Check environment variables
  if [[ -z "${IMIF_DOCKER_REGISTRY_USER}" ]]; then
    echo "ERROR: IMIF_DOCKER_REGISTRY_USER not set"
    exit 1
  fi

  # Check environment variables
  if [[ -z "${IMIF_DOCKER_REGISTRY_PASS}" ]]; then
    echo "ERROR: IMIF_DOCKER_REGISTRY_PASS not set"
    exit 1
  fi

  # Login into the registry
  run "docker login -u ${IMIF_DOCKER_REGISTRY_USER} -p ${IMIF_DOCKER_REGISTRY_PASS} ${IMIF_DOCKER_REGISTRY}"

  # Build a docker image if it doesn't exists
  RUN_DOCKER_IMAGE="${DOCKER_IMAGE_NAME}-${DOCKER_IMAGE_TAG}-run-$USER:$(gitrev)"
  if [[ "$(docker images -q ${RUN_DOCKER_IMAGE} 2> /dev/null)" == "" ]]; then
    echo "Building ${RUN_DOCKER_IMAGE}..."
    docker_build $RUN_DOCKER_IMAGE
  fi

  # Tag and push
  run "docker tag ${RUN_DOCKER_IMAGE} ${IMIF_DOCKER_REGISTRY}/${RUN_DOCKER_IMAGE}"
  run "docker push ${IMIF_DOCKER_REGISTRY}/${RUN_DOCKER_IMAGE}"

  # Cleanup
  run "docker rmi ${IMIF_DOCKER_REGISTRY}/${RUN_DOCKER_IMAGE}"
  run "docker rmi ${RUN_DOCKER_IMAGE}"

  printf "\nDevelopment docker is ready. Pull on remote:\n"
  echo "docker pull ${IMIF_DOCKER_REGISTRY}/${RUN_DOCKER_IMAGE}"
}

# CMake and Build Options
BUILD_COMMAND="make -j 16 && make install"
DOCKER_OPTS=""

for var in "$@"
do
  # Clean ALL
  if [ "$var" == "distclean" ]; then
    echo "Clean EVERYTHING!"
    rm -rf ./_build*_
    exit
  # Clean only imif related build items
  elif [ "$var" == "clean" ]; then
    echo "Clean build dir"
    REMOVE=$(find ./_build_/ -maxdepth 1 -mindepth 1 -type d ! \( -name "CMakeFiles" -o -name "external" -o -name "oss" \) 2>/dev/null )

    rm -rf $REMOVE
    
    exit
  elif [ "$var" == "test" ]; then
    BUILD_COMMAND="env CTEST_OUTPUT_ON_FAILURE=1 make test"
  # Parse GIT revision
  elif [ "$var" == "gitrev" ]; then
    echo $(gitrev)
    exit
  # Pack the installation folder into an archive
  elif [ "$var" == "pack" ]; then
    if [ ! -d _build_/_install_ ]; then
      echo "Nothing to pack..."
      exit 1
    fi

    # Build the archive name
    ARCHIVE_NAME=imif_$(gitrev)_`date "+%F_%H-%M-%S"`

    # Create the archives directory
    mkdir -p _archives_
    
    # Pack the files
    run "tar -C _build_/_install_ --exclude=Dockerfile -czvf _archives_/$ARCHIVE_NAME.tar.gz ."

    printf "\nPacked version to: $PWD/_archives_/$ARCHIVE_NAME.tar.gz\n"
    exit
  # Send the installation folder with rsync
  elif [ "$var" == "rsync" ]; then
    if [ ! -d _build_/_install_ ]; then
      echo "Nothing to deploy..."
      exit 1
    fi

    if [ "$IMIF_DEST_RSYNC" == "" ]; then
      echo "You should set IMIF_DEST_RSYNC environment variable to point to the rsync deploy destination."
      echo "It will typically be username@hostname:path"
      echo "You can use env.sh for that"
      echo "Note: Files will be overwritten but not be deleted from the destination."
      exit 1
    fi

    RSYNC_RSH=$RSYNC_RSH rsync -ar --info=progress2 _build_/_install_/ $IMIF_DEST_RSYNC
    exit
  elif [ "$var" == "docker" ]; then
    docker_build
    exit
  elif [ "$var" == "docker_push" ]; then
    docker_push
    exit
  else
    echo "Unsupported command: $var"
    exit 1
  fi
done

BUILD_DIR="_build_"
[ ! -d $BUILD_DIR ] && mkdir -p $BUILD_DIR

# Docker build
if [[ -z "${IMIF_NATIVE_BUILD}" ]]; then
  DOCKER_DIR="docker/build"

  validate_docker_install
  parse_docker_tag

  # Check if the build docker image exists
  if [ -z "`docker images -q ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}`" ]; then
    echo "Docker Build image ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} not found. Building..."
    cd $DOCKER_DIR
    
    docker build \
    --build-arg http_proxy \
    --build-arg https_proxy \
    --build-arg ftp_proxy \
    --build-arg no_proxy \
    -f "${DOCKER_IMAGE_NAME}.${DOCKER_IMAGE_TAG}.Dockerfile" -t "${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" .
    if [ $? -ne 0 ]; then exit 1; fi
    cd -
  fi

  # SSH Key for cloning GIT repositories
  if [ -z "$IMIF_GIT_SSH_KEY" ]; then
    echo "NOTICE: IMIF_GIT_SSH_KEY not defined. Using defualt SSH key: ~/.ssh/id_rsa"
    if [ -f "~/.ssh/id_rsa" ]; then
      echo "WARNING: Default SSH key not found. Aborting!"
    fi
  fi
  SSH_KEY=${IMIF_GIT_SSH_KEY:-$(readlink -f ~/.ssh/id_rsa)}

  # Start an ssh-agent
  eval `ssh-agent -s`
  ssh-add "${SSH_KEY}"

  DOCKER_OPTS+="-v $(dirname $SSH_AUTH_SOCK):$(dirname $SSH_AUTH_SOCK) \
    --env GIT_COMMITTER_NAME="root" \
    --env SSH_AUTH_SOCK="${SSH_AUTH_SOCK}" \
    --env CMAKE_OPTIONS="${CMAKE_OPTIONS}" \
    --env IMIF_ENV_FILE="${PWD}/${BUILD_DIR}/env.sh" \
    --env IMIF_NATIVE_BUILD="1" "

  DOCKER_OPTS+="-u $(id -u ${USER}):$(id -g ${USER}) "
  
  cp $IMIF_ENV_FILE $BUILD_DIR/env.sh

  # Build inside the container
  echo "Running build in docker image: ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} ..."
  docker run --rm -v $PWD:$PWD \
    ${DOCKER_OPTS} \
    -ti "${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" bash -c "\
	cd $PWD && ./build.sh $@; chown -R $UID:$UID $BUILD_DIR; echo Done!"
  
  # Kill the ssh-agent
  ssh-agent -k

  exit
# Native build (or in-docker build)
else

  # Determine the build host
  if [ -f "/etc/centos-release" ]; then
    echo "Building on:""`cat /etc/centos-release`"
    if [ ! -z "`cat /etc/centos-release | grep "CentOS Linux release 7"`" ]; then
      source scl_source enable devtoolset-7
      if [ $? -ne 0 ]; then exit 1; fi
    fi
  fi

  # Run Cmake
  if [ ! -f $BUILD_DIR/Makefile ]; then
    cd $BUILD_DIR
    cmake $CMAKE_OPTIONS ../
    cd -
  fi

  # Build and install
  cd $BUILD_DIR
  bash -c "$BUILD_COMMAND"
  cd -
  
fi
