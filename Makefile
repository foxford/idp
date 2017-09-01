.PHONY: update-schemas

PROJECT = idp
PROJECT_DESCRIPTION = Identity Provider.

DEP_PLUGINS = \
	version.mk

DEPS = \
	lager \
	lager_syslog \
	riakc_pool \
	riakauth \
	riakacl \
	jose \
	uuid \
	cowboy \
	exometer

IGNORE_DEPS = \
	folsom \
	bear

NO_AUTOPATCH = \
	riak_pb

dep_lager = git https://github.com/erlang-lager/lager.git 3.5.1
dep_lager_syslog = git git://github.com/basho/lager_syslog.git 3.0.3
dep_riakc_pool = git git://github.com/manifest/riak-connection-pool.git v0.2.1
dep_riakauth = git git://github.com/manifest/riak-auth.git v0.1.3
dep_riakacl = git git://github.com/manifest/riak-acl.git v0.2.0
dep_jose = git git://github.com/manifest/jose-erlang.git v0.1.2
dep_uuid = git git://github.com/okeuday/uuid.git v1.7.1
dep_cowboy = git git://github.com/ninenines/cowboy.git 2.0.0-rc.2
dep_exometer = git git://github.com/Feuerlabs/exometer.git 1.2.1

BUILD_DEPS = version.mk
dep_version.mk = git git://github.com/manifest/version.mk.git master

TEST_DEPS = ct_helper gun
dep_ct_helper = git git://github.com/ninenines/ct_helper.git master
dep_gun = git git://github.com/manifest/gun.git feature/head-1xx

SHELL_DEPS = tddreloader
SHELL_OPTS = \
	-eval 'application:ensure_all_started($(PROJECT), permanent)' \
	-s tddreloader start \
	-config rel/sys

include erlang.mk

GEN_IDP_ACCOUNT_SCHEMA_OUT = priv/riak-kv/schemas/idp_account.xml
GEN_IDP_ACCOUNT_SCHEMA_SRC = deps/riakauth/priv/riak-kv/schemas/riakauth_account.xml
GEN_IDP_ACCOUNT_ACLSUBJECT_SCHEMA_OUT = priv/riak-kv/schemas/idp_account_aclsubject.xml
GEN_IDP_ACCOUNT_ACLSUBJECT_SCHEMA_SRC = deps/riakacl/priv/riak-kv/schemas/riakacl_subject.xml

update-schemas: fetch-shell-deps
	$(verbose) cp $(GEN_IDP_ACCOUNT_SCHEMA_SRC) $(GEN_IDP_ACCOUNT_SCHEMA_OUT)
	$(verbose) cp $(GEN_IDP_ACCOUNT_ACLSUBJECT_SCHEMA_SRC) $(GEN_IDP_ACCOUNT_ACLSUBJECT_SCHEMA_OUT)

export DEVELOP_ENVIRONMENT = $(shell if [ -f .develop-environment ]; then cat .develop-environment; fi)
export EXOMETER_PACKAGES='(minimal)'
