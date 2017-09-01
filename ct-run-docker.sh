#!/bin/bash

DOCKER_CONTAINER_NAME='ct'
DOCKER_EVENT_DONE='.docker.event.done'
COMMON_TEST_OPTIONS=${COMMON_TEST_OPTIONS:-''}

function CLEAN() {
	rm "${DOCKER_EVENT_DONE}" 2>/dev/null \
		; docker stop ${DOCKER_CONTAINER_NAME} 2>/dev/null \
		; docker rm ${DOCKER_CONTAINER_NAME} 2>/dev/null \
		; true
}

set -e
CLEAN \
	&& DOCKER_RUN_OPTIONS="-dt --name ${DOCKER_CONTAINER_NAME}" \
		DOCKER_CONTAINER_COMMAND="touch ${DOCKER_EVENT_DONE} && riak attach" \
		./run-docker.sh \
	&& while [ ! -f "${DOCKER_EVENT_DONE}" ]; do sleep 3; done \
	&& make ct ${COMMON_TEST_OPTIONS}
CLEAN &
