FROM ubuntu:16.04

ARG RIAKKV_VERSION
ARG ULIMIT_FD
ENV RIAKKV_VERSION=${RIAKKV_VERSION:-2.2.0}
ENV ULIMIT_FD=${ULIMIT_FD:-262144}

## -----------------------------------------------------------------------------
## Installing dependencies
## -----------------------------------------------------------------------------
ENV DEBIAN_FRONTEND noninteractive
RUN set -xe \
	&& apt-get update \
	&& apt-get -y --no-install-recommends install \
		software-properties-common \
		apt-transport-https \
		ca-certificates \
		lsb-release \
		curl \
	&& apt-get update \
	&& apt-get -y --no-install-recommends install \
		rsyslog \
		vim-nox \
		sudo \
		less \
		make \
		g++ \
		git \
		jq

## -----------------------------------------------------------------------------
## Installing Riak KV
## -----------------------------------------------------------------------------
RUN set -xe \
	&& add-apt-repository -s -y "deb https://packagecloud.io/basho/riak/ubuntu/ $(lsb_release -sc) main" \
	&& curl -fSL https://packagecloud.io/gpg.key 2>&1 | apt-key add -- \
	&& apt-get update \
	&& apt-get -y --no-install-recommends install \
		riak=${RIAKKV_VERSION}-1

## -----------------------------------------------------------------------------
## Configuring Riak KV
## -----------------------------------------------------------------------------
RUN set -xe \
	&& echo "ulimit -n ${ULIMIT_FD}" >> /etc/default/riak \
	&& perl -pi -e 's/(listener.http.internal = )127\.0\.0\.1/${1}0.0.0.0/' /etc/riak/riak.conf \
	&& perl -pi -e 's/(listener.protobuf.internal = )127\.0\.0\.1/${1}0.0.0.0/' /etc/riak/riak.conf \
	&& perl -pi -e 's/(?:(log.syslog = ).*)/${1}on/' /etc/riak/riak.conf

## -----------------------------------------------------------------------------
## Enabling Riak Search
## -----------------------------------------------------------------------------
RUN set -xe \
	&& apt-get -y --no-install-recommends install \
		default-jre-headless \
	&& perl -pi -e 's/(search = )off/${1}on/' /etc/riak/riak.conf
