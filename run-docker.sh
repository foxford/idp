#!/bin/bash

PROJECT='idp'
PROJECT_DIR="/opt/sandbox/${PROJECT}"
DOCKER_CONTAINER_NAME="sandbox/${PROJECT}"
DOCKER_CONTAINER_COMMAND=${DOCKER_CONTAINER_COMMAND:-'/bin/bash'}
DOCKER_RUN_OPTIONS=${DOCKER_RUN_OPTIONS:-'-ti --rm'}
DOCKER_RIAKKV_PROTOBUF_PORT=${DOCKER_RIAKKV_PROTOBUF_PORT:-8087}
DOCKER_RIAKKV_HTTP_PORT=${DOCKER_RIAKKV_HTTP_PORT:-8098}
DEVELOP_ENVIRONMENT='.develop-environment'
ULIMIT_FD=262144

function CREATE_DEVELOP_ENVIRONMENT() {
	local DOCKER_MACHINE_IP=$(docker-machine ip)
	local DOCKER_IP=${DOCKER_MACHINE_IP:-'localhost'}
	printf \
		"#{kv_protobuf => #{host => \"%s\", port => %s}, kv_http => #{host => \"%s\", port => %s}}." \
		"${DOCKER_IP}" "${DOCKER_RIAKKV_PROTOBUF_PORT}" \
		"${DOCKER_IP}" "${DOCKER_RIAKKV_HTTP_PORT}" \
		> "${DEVELOP_ENVIRONMENT}"
}

function PROPS() {
	local INDEX_NAME="${1}"
	local BUCKET_OPTIONS="${2}"
	if [[ ${BUCKET_OPTIONS} ]]; then
		echo "{\"props\":{\"search_index\":\"${INDEX_NAME}\",${BUCKET_OPTIONS}}}"
	else
		echo "{\"props\":{\"search_index\":\"${INDEX_NAME}\"}}"
	fi
}

function CREATE_TYPE() {
	local HOST='http://localhost:8098'
	local SCHEMA_NAME="${1}"
	local INDEX_NAME="${1}_idx"
	local TYPE_NAME="${1}_t"
	local BUCKET_OPTIONS="${2}"
	read -r RESULT <<-EOF
		curl -fSL \
			-XPUT "${HOST}/search/schema/${SCHEMA_NAME}" \
			-H 'Content-Type: application/xml' \
			--data-binary @"${PROJECT_DIR}/priv/riak-kv/schemas/${SCHEMA_NAME}.xml" \
		&& curl -fSL \
			-XPUT "${HOST}/search/index/${INDEX_NAME}" \
			-H 'Content-Type: application/json' \
			-d '{"schema":"${SCHEMA_NAME}"}' \
		&& riak-admin bucket-type create ${TYPE_NAME} '$(PROPS ${INDEX_NAME} ${BUCKET_OPTIONS})' \
		&& riak-admin bucket-type activate ${TYPE_NAME}
	EOF
	echo "${RESULT}"
}

read -r DOCKER_RUN_COMMAND <<-EOF
	service rsyslog start \
	&& riak start \
	&& riak-admin wait-for-service riak_kv \
	&& $(CREATE_TYPE idp_account '"datatype":"map"') \
	&& $(CREATE_TYPE idp_account_aclsubject '"datatype":"map"')
EOF

CREATE_DEVELOP_ENVIRONMENT
docker build -t ${DOCKER_CONTAINER_NAME} .
docker run ${DOCKER_RUN_OPTIONS} \
	-v $(pwd):${PROJECT_DIR} \
	--ulimit nofile=${ULIMIT_FD}:${ULIMIT_FD} \
	-p ${DOCKER_RIAKKV_PROTOBUF_PORT}:8087 \
	-p ${DOCKER_RIAKKV_HTTP_PORT}:8098 \
	${DOCKER_CONTAINER_NAME} \
	/bin/bash -c "set -x && cd ${PROJECT_DIR} && ${DOCKER_RUN_COMMAND} && set +x && ${DOCKER_CONTAINER_COMMAND}"
