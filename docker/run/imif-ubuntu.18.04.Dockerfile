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

RUN apt-get update --fix-missing

# Install MediaSDK/OpenVINO runtime dependecies
RUN apt-get -yq install libdrm2 libxfixes3 libxext6 libpciaccess0 libx11-6 libgomp1 libarchive13 libyaml-0-2

# Install gRPC runtime dependecies
RUN apt-get -yq install zlibc openssl

# Install general tools
RUN apt-get -yq install net-tools wget && apt-get clean all

# Create a user for running the processes and add it the 'video' group
# RUN useradd --quiet  --disabled-password --home /opt/intel/imif imif && usermod -a -G imif video 
RUN useradd -M -d /opt/intel/imif imif && gpasswd -a imif video 

# Copy artifacts
COPY usr /usr
COPY bashrc.sh /opt/intel/imif/.bashrc
COPY bash_profile /opt/intel/imif/.bash_profile
COPY opt /opt

# Update permissions
RUN chown -R imif /opt/intel/imif

# Define environment variables
ENV PATH=$PATH:/opt/intel/imif/bin:/usr/share/mfx/samples:/usr/share/openvino
ENV LD_LIBRARY_PATH=/usr/lib:/usr/lib/mfx:/usr/share/openvino/lib:/opt/intel/imif/lib
ENV LIBVA_DRIVERS_PATH=/usr/lib/dri
ENV LIBVA_DRIVER_NAME=iHD

# User and Workdir
USER imif
WORKDIR /opt/intel/imif/bin

# Entry command (using CMD and not ENTRYPOINT to allow overriding)
CMD [ "/opt/intel/imif/bin/imif.sh", "-s services.conf"]
