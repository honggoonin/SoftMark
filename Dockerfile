# Copyright(c) 2018, Hyungjoon Koo
# Copyright(c) 2021, Honggoo Kang
#####################################################################
#  SoftMark: Software Watermarking via a Binary Function Relocation #
#   (In the Annual Computer SEcurity Applications Conference 2021)  # 
#                                                                   #
#  Author: Honggoo Kang <honggoonin@korea.ac.kr>                    #
#          Cybersecurity@Korea University                           #
#                                                                   #
#  This file can be distributed under the MIT License.              #
#  See the LICENSE.TXT for details.                                 #
#####################################################################

FROM       ubuntu:16.04
MAINTAINER Honggoo Kang (honggoonin@korea.ac.kr)

RUN apt-get -y update && apt-get install -y \
    git \
    texinfo \
    byacc \
    flex \
    bison \
    automake \
    autoconf \
    build-essential \
    libtool \
    cmake \
    gawk \
    python \
    python-dev \
    wget \
    elfutils \
    sudo \
    python-pip \
    radare2

RUN pip install protobuf==3.1.0 pyelftools capstone r2pipe==1.4.2 pathlib

RUN git clone https://github.com/honggoonin/SoftMark.git
WORKDIR /SoftMark
RUN ./build_docker.sh
RUN ldconfig