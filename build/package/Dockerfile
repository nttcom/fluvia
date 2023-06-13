FROM ubuntu:22.04
LABEL maintainer "WATARU MISHIMA <w.mishima@ntt.com>"

# Install packages
RUN apt-get update \
 && apt-get install -y curl

# Setup Go 1.20.5
RUN curl -o ~/go1.20.5.linux-amd64.tar.gz -LO https://go.dev/dl/go1.20.5.linux-amd64.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf ~/go1.20.5.linux-amd64.tar.gz \
    && echo "export PATH=$PATH:/usr/local/go/bin" > ~/.bashrc

# Install Pola
SHELL ["/bin/bash", "-l", "-c"]

ENV GOBIN /usr/local/go/bin
RUN go install github.com/nttcom/fluvia/cmd/...@latest
