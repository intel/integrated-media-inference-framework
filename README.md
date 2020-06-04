# Integrated Media Inference Framework (IMIF)

A Linux C++ reference software framework that enables integrated Media & AI-inference workloads on Intel platforms.<br>
Designed for dense multi stream media analytics processing with flexible and dynamic pipeline configuration.

Key features:<br>
•	Event based microservices architecture allowing simple integration of external logic.<br>
•	Multi flow / multi pipeline deployment using a single yaml configuration file.<br>
•	RTSP, gRPC and file media input stream processing including JPEG and h264 video. <br>
•	gRPC management interface, enabling operations such as add/remove flow and pipeline configuration.<br>
•	Control, management and media streaming CLI (using gRPC connectivity to framework).<br>
•	OpenVINO integration for AI inference runtime.<br>
•	Media SDK integration for media processing and decoding.<br>
•	CMake build system with native and Docker container build environments.<br>
•	Framework deployment using Docker container on top of CentOS or Ubuntu 18.04 official OS images.<br>


## Project Layout

    .
    +-- _build_                   # Compiled files and build artifacts
    +-- _archives_                # Location of packed archives containing the contained/dockerized binaries
    +-- .vscode                   # Visual Studio Code related envrionment files and configuration
    +-- broker                    # Broker service (pub/sub bus implementation)
    +-- cli                       # Command Line Interface tool for interacting with IMIF management
    +-- common                    # Commonly used utilities and includes
    +-- config                    # Examples for IMIF configuration files (yaml)
    +-- docker                    # Docker related scripts
    +-- external                  # External utilities and libraries
    |   +-- easylogging           # EasyLogging++ tracing utility
    |   +-- grpc                  # The C based gRPC framework
    |   +-- mediasdk              # Intel Media SDK provides hardware acceleration for video processing
    |   +-- opencv                # Open Source Computer Vision Library
    |   +-- openvino              # OpenVINO Toolkit - Deep Learning Deployment Toolkit
    |   +-- protobuf              # Google Protobuf messaging service
    |   +-- replxx                # readline replacement
    |
    +-- mdecode                   # Video Decoder service
    +-- inference                 # Inference service
    |   +-- plugins               # Post-inference plugins
    |
    +-- lib
    |   +-- mgmt                  # Managament Library - Serves as an example for how to communicate with
    |   |                         # a running IMIF instance in order to perform management operations, such
    |   |                         # as adding and removing flows.
    |   +-- msl                   # Media Streaming Library - Serves as an example for how to communicate
    |                             # with a running IMIF instance in order to deliver media for inference and
    |                             # retrieving inference results.
    +-- mstream                   # Media Stream service
    +-- scripts                   # Some scripts
    +-- rtsp_client               # Interface for RTSP client. Implement this to enable inference from RTSP.
    +-- yaml                      # YAML parsing library
    +-- tutorial                  # Example files
    +-- env.sh.example            # Example for how to write `env.sh`
    +-- README.md                 # This file

## Building

Clone the repository and initialize the submodules:<br>
`git clone ssh://git@gitlab.devtools.intel.com:29418/dea-avei-idc/imif-oss.git`


Refer to `env.sh.example` for the configuration needed. You can either create the file `env.sh` with these configurations or set the environment variable `IMIF_ENV_FILE` to point to one.

Use the `build.sh` script with the following commands:
* `./build.sh all` - Build the IMIF and all dependencies (MediaSDK, OpenVINO etc.)
* `./build.sh distclean` - Clean everything
* `./build.sh clean` - Clean only IMIF projects
* `./build.sh pack` - Archive the built artifacts into a `tar.gz` file
* `./build.sh rsync` - Send the artifacts via rsync. Set `IMIF_DEST_RSYNC` environment variable and `RSYNC_RSH` if needed.
* `./build.sh docker` - Build a Docker container with all the artifacts (requires installed Docker server and access permissions)
* `./build.sh docker_push` - Build a docker container and push it into a registry.<br> Registry address and credentials can be specified using environment variables:<br>
  * `IMIF_DOCKER_REGISTRY` - Registry address (e.g. registry.intel.com:5000)
  * `IMIF_DOCKER_REGISTRY_USER` - Registry authentication user
  * `IMIF_DOCKER_REGISTRY_PASS` - Registry authentication password

By default the repository is built using a CentOS 7 docker container.<BR>
To force a native build, the `IMIF_NATIVE_BUILD` environment variable should be defined.

## Extending IMIF

### Management and Streaming Libraries

IMIF exposes a management interface to allow management operations such as configuring media pipelines. It also exposes a Media Streaming interface allowing delivery and collection of media and data over network interface. Both interfaces use gRPC so any language supporting gRPC can be used. Use the proto files under `common/include/messages/grpc`. C++ binding is provided by way of two libraries under `lib/` directory,documented in the reference manual in file `lib/docs/refman.pdf`.

### RTSP

IMIF supports RTSP for media delivery via the interface defined in `rtsp_client` directory. In order to enable RTSP, you should replace the stub witn an implementation using an RTSP client library of your choosing. An example of such library is myRtspClient (https://github.com/simonbaren/myRtspClient/commit/4260e7f000b662c361aa0dde8ea260c322cbb607).

### Intel GPU support

OpenVINO GPU plugin dependency "Intel Graphics Compiler" is not installed by default in the Docker run container.<br>
Dependency source code can be found here: https://github.com/intel/intel-graphics-compiler<br>
Unofficial dependency binary package can be installed from copr/ppa repositories:<br>

CentOS:

        yum install -y yum-plugin-copr
        yum -y copr enable jdanecki/intel-opencl
        yum install -y intel-opencl

Ubuntu:

        apt-get install -yq software-properties-common
        add-apt-repository ppa:intel-opencl/intel-opencl
        apt-get update --fix-missing
        apt-get -yq install intel-opencl-icd

## Tutorial: Building and using with Docker

### Building

        ./build
        ./build docker


### Deploying using a Docker repository (optional)

        ./build docker_push
<br>

        Development docker is ready. Pull on remote:
        docker pull <hostname>:<port>/imif-xxxxx:0.0.0-yyy-zzzzzzzz

### Usage
1. Prepare your working directory:

        cp <this-repository>/scripts/imif_docker.sh .
        cp <this-repository>/scripts/imif_docker.rc .
        mkdir downloads

2. For this tutorial we will use the pretrained `mobilenet-ssd` from OpenVINO™ Toolkit Open Model Zoo repository. The repository at https://github.com/opencv/open_model_zoo includes instructions on how to download the models. You'd end with two files in the directory `public/mobilenet-ssd/FP32`, namely `mobilenet-ssd.xml` and `mobilenet-ssd.bin`. You also need a text file with the labels, one label per line. You can prepare one yourself based on the pre-trained model repository, or download a copy from https://github.com/intel/ros2_openvino_toolkit/blob/cd8aba4e97f96da60655391e89021400d6a4ba8f/data/labels/object_detection/mobilenet-ssd.labels .Save this file under the name `mobilenet-ssd_labels.txt`. Place all three files in a directory `downloads/openvino/mobilenet-ssd_fp32/`.

3. Download some car images in jpeg format and place them under `downloads/`. The `downloads` folder by default is mounted in the IMIF docker.

4. Edit `./imif_docker.rc` and fill in the blanks with your Docker repository details, if needed. If you don't use a repository for deployment, empty the relevant variables in this file. Also, edit in the network settings for the IMIF container.

5. If you want to pull the image from the Docker registry you configured, follow these commands.

        ./imif_docker.sh init
        ./imif_docker.sh pull imif-xxxxx:0.0.0-yyy-zzzzzzzz


6. Start the IMIF docker:

        ./imif_docker.sh run imif-xxxxx:0.0.0-yyy-zzzzzzzz mgmt --bash

    IMIF is started and you are presented with bash prompt inside IMIF docker. Current directory is `/opt/intel/imif/bin`

7. To access IMIF CLI, run

        ./imif.sh cli

    You are now presented with IMIF CLI prompt. You can use `help` to see supported commands.

8. Load the config file we've prepared for this tutorial, and enable the flows.

        load ../config/config_mobilenet-ssd_grpc.yaml
        enable all


9. Subscribe to see inference results for flow 100:

        msl connect
        msl subscribe 100


10. Send all JPEG images in `../downloads/` for inference in flow 100:

        msl infer once 100 ../downloads/*.jpg

    Inference results for the files you downloaded will be presented on screen.