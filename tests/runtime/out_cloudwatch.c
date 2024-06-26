/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

#define ERROR_ALREADY_EXISTS "{\"__type\":\"ResourceAlreadyExistsException\"}"
/* not a real error code, but tests that the code can respond to any error */
#define ERROR_UNKNOWN "{\"__type\":\"UNKNOWN\"}"

/* It writes a big JSON message (copied from TD test) */
void flb_test_cloudwatch_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* It writes a json/emf formatted metrics */
void flb_test_cloudwatch_success_with_metrics(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_format", "json_emf", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent-health", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-cmetrics-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_already_exists_create_group(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_GROUP_ERROR", ERROR_ALREADY_EXISTS, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_already_exists_create_stream(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_STREAM_ERROR", ERROR_ALREADY_EXISTS, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_error_create_group(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_GROUP_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_error_create_stream(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_STREAM_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_error_put_log_events(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_LOG_EVENTS_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_put_retention_policy_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"log_retention_days", "14", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_already_exists_create_group_put_retention_policy(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_GROUP_ERROR", ERROR_ALREADY_EXISTS, 1);

    /* PutRetentionPolicy is not called if the group already exists */
    setenv("TEST_PUT_RETENTION_POLICY_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"log_retention_days", "14", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_error_put_retention_policy(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RETENTION_POLICY_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"log_retention_days", "14", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"success", flb_test_cloudwatch_success },
    {"success_with_metrics", flb_test_cloudwatch_success_with_metrics},
    {"group_already_exists", flb_test_cloudwatch_already_exists_create_group },
    {"stream_already_exists", flb_test_cloudwatch_already_exists_create_stream },
    {"create_group_error", flb_test_cloudwatch_error_create_group },
    {"create_stream_error", flb_test_cloudwatch_error_create_stream },
    {"put_log_events_error", flb_test_cloudwatch_error_put_log_events },
    {"put_retention_policy_success", flb_test_cloudwatch_put_retention_policy_success },
    {"already_exists_create_group_put_retention_policy", flb_test_cloudwatch_already_exists_create_group_put_retention_policy },
    {"error_put_retention_policy", flb_test_cloudwatch_error_put_retention_policy },
    {NULL, NULL}
};
