FROM ubuntu:20.04

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get update
RUN apt-get install -y llvm-11 clang-11 libclang-11-dev \
    linux-headers-5.4.0-58-generic \
    make binutils curl coreutils

WORKDIR /src
CMD make clean all