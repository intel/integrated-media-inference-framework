FROM ubuntu:18.04

# Proxy
ARG http_proxy=""
ARG https_proxy=""
ARG ftp_proxy=""
ARG no_proxy=""

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy
ENV ftp_proxy=$ftp_proxy
ENV no_proxy=$no_proxy

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update

# Install dev tools
RUN apt-get -yq install build-essential gcc-multilib patch autoconf automake libtool wget
RUN apt-get -yq install 

# Install cmake
ARG CMAKE_VERSION=3.15.7
ARG CMAKE_FILE=cmake-$CMAKE_VERSION-Linux-x86_64.sh
RUN mkdir ~/temp && cd ~/temp && \
 wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${CMAKE_FILE} && \
 mkdir /opt/cmake && sh $CMAKE_FILE --prefix=/opt/cmake --skip-license && cd - && rm -rf ~/temp && \
 ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake

# Install Git v2.x (with LFS support)
RUN apt-get -yq install git git-lfs

# Install build dependecies
RUN apt-get -yq install libdrm-dev libpciaccess-dev \
  libxfixes-dev libxext-dev libx11-dev libusb-1.0-0-dev

# Install extra tools
RUN apt-get -yq install file bc bzip2 libextutils-makemaker-cpanfile-perl
RUN apt-get -yq install bison flex libssl-dev libelf-dev gtk2.0

RUN apt-get -yq install libarchive-dev libyaml-dev

# Cleanup
RUN apt-get clean all

# Entry command
CMD ["/usr/sbin/init"]
