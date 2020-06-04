FROM centos:7.7.1908

# Proxy
ARG http_proxy=""
ARG https_proxy=""
ARG ftp_proxy=""
ARG no_proxy=""

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy
ENV ftp_proxy=$ftp_proxy
ENV no_proxy=$no_proxy

# Disable yum http caching
RUN echo "http_caching=none" >> /etc/yum.conf

# Install development tools
RUN yum install -y centos-release-scl \
  && yum-config-manager --enable rhel-server-rhscl-7-rpms \
  && yum install -y devtoolset-7 python3

# Install extra tools
RUN yum install -y epel-release \
  && yum install -y wget git patch autoconf automake libtool rsync glibc.i686

# Install cmake
ARG CMAKE_VERSION=3.15.7
ARG CMAKE_FILE=cmake-$CMAKE_VERSION-Linux-x86_64.sh
RUN mkdir ~/temp && cd ~/temp && \
 wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${CMAKE_FILE} && \
 mkdir /opt/cmake && sh $CMAKE_FILE --prefix=/opt/cmake --skip-license && cd - && rm -rf ~/temp && \
 ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake

# Install Git v2.x (with LFS support)
RUN yum install -y http://opensource.wandisco.com/centos/7/git/x86_64/wandisco-git-release-7-2.noarch.rpm \
  && yum -y install git git-lfs

# Install MediaSDK/OpenVINO build dependecies
RUN yum install -y libdrm-devel libpciaccess-devel \
  libXfixes-devel libXext-devel libX11-devel libusb-devel libusbx-devel

RUN yum install -y libarchive-devel libyaml-devel

# Install gRPC build dependecies
RUN yum install -y zlib-devel openssl-devel

# Cleanup
RUN yum clean all

# Entry command
CMD ["/usr/sbin/init"]
