"""PyFlink job for real-time API security detection.

Consumes enriched events from Kafka topic pattern events.enriched.*
and emits alert events to events.alerts.
"""
from __future__ import annotations

import os
from datetime import timedelta
from typing import Iterable, Tuple, Optional, List, Dict

from pyflink.common import Row, Types, WatermarkStrategy
from pyflink.common.time import Time
from pyflink.datastream import StreamExecutionEnvironment, TimeCharacteristic
from pyflink.datastream.connectors.kafka import (
    KafkaSource,
    KafkaOffsetsInitializer,
    KafkaSink,
    DeliveryGuarantee,
)
from pyflink.datastream.formats.json import JsonRowDeserializationSchema, JsonRowSerializationSchema
from pyflink.datastream.functions import AggregateFunction, KeyedProcessFunction, ProcessWindowFunction
from pyflink.datastream.window import SlidingEventTimeWindows, TumblingEventTimeWindows
from pyflink.datastream.state import MapStateDescriptor, ValueStateDescriptor


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


def _env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, str(default)))


AUTH_FAILURE_THRESHOLD = _env_int("FLINK_AUTH_FAILURE_THRESHOLD", 100)
DISTINCT_ACTOR_THRESHOLD = _env_int("FLINK_AUTH_DISTINCT_ACTORS", 50)
DISTINCT_ACTOR_CAP = _env_int("FLINK_DISTINCT_ACTOR_CAP", 5000)

RATE_SPIKE_THRESHOLD = _env_int("FLINK_RATE_SPIKE_THRESHOLD", 1000)
RATE_SPIKE_MIN = _env_int("FLINK_RATE_SPIKE_MIN", 200)

ERROR_RATE_THRESHOLD = _env_float("FLINK_ERROR_RATE_THRESHOLD", 0.30)
ERROR_RATE_MIN = _env_int("FLINK_ERROR_RATE_MIN", 200)

ACTOR_BURST_THRESHOLD = _env_int("FLINK_ACTOR_BURST_THRESHOLD", 200)

LATENCY_P95_THRESHOLD_MS = _env_float("FLINK_LATENCY_P95_THRESHOLD_MS", 1000.0)
LATENCY_MIN_SAMPLES = _env_int("FLINK_LATENCY_MIN_SAMPLES", 50)
LATENCY_SAMPLE_CAP = _env_int("FLINK_LATENCY_SAMPLE_CAP", 2048)

ENUM_DISTINCT_THRESHOLD = _env_int("FLINK_ENUM_DISTINCT_THRESHOLD", 120)
ENUM_SEQUENCE_RATIO = _env_float("FLINK_ENUM_SEQUENCE_RATIO", 0.7)
ENUM_SAMPLE_CAP = _env_int("FLINK_ENUM_SAMPLE_CAP", 2048)
MIN_QUALITY_SCORE = _env_float("FLINK_MIN_QUALITY_SCORE", 0.5)
WORKFLOW_WINDOW_MS = _env_int("FLINK_WORKFLOW_WINDOW_MS", 60_000)
WORKFLOW_TRANSITION_THRESHOLD = _env_int("FLINK_WORKFLOW_TRANSITION_THRESHOLD", 3)
WORKFLOW_MAX_TRANSITIONS = _env_int("FLINK_WORKFLOW_MAX_TRANSITIONS", 2000)

ENDPOINT_SWEEP_THRESHOLD = _env_int("FLINK_ENDPOINT_SWEEP_THRESHOLD", 30)
ENDPOINT_SWEEP_MIN_EVENTS = _env_int("FLINK_ENDPOINT_SWEEP_MIN_EVENTS", 50)
NOT_FOUND_THRESHOLD = _env_int("FLINK_NOT_FOUND_THRESHOLD", 120)
NOT_FOUND_DISTINCT_THRESHOLD = _env_int("FLINK_NOT_FOUND_DISTINCT_THRESHOLD", 40)
NOT_FOUND_WINDOW_MINUTES = _env_int("FLINK_NOT_FOUND_WINDOW_MINUTES", 5)


EVENT_FIELDS = [
    "account_id",
    "endpoint_id",
    "actor_id",
    "response_code",
    "timestamp_ms",
    "path",
    "method",
    "latency_ms",
    "quality_score",
    "protocol",
]
EVENT_TYPES = [
    Types.LONG(),
    Types.STRING(),
    Types.STRING(),
    Types.INT(),
    Types.LONG(),
    Types.STRING(),
    Types.STRING(),
    Types.FLOAT(),
    Types.FLOAT(),
    Types.STRING(),
]

ALERT_FIELDS = [
    "account_id",
    "endpoint_id",
    "actor_id",
    "type",
    "severity",
    "message",
    "endpoint",
    "category",
    "timestamp_ms",
    "window_start",
    "window_end",
    "count",
    "distinct_actors",
    "error_rate",
    "p95_latency",
    "evidence",
]
ALERT_TYPES = [
    Types.LONG(),
    Types.STRING(),
    Types.STRING(),
    Types.STRING(),
    Types.STRING(),
    Types.STRING(),
    Types.STRING(),
    Types.STRING(),
    Types.LONG(),
    Types.LONG(),
    Types.LONG(),
    Types.INT(),
    Types.INT(),
    Types.FLOAT(),
    Types.FLOAT(),
    Types.MAP(Types.STRING(), Types.STRING()),
]


def _alert_row(
    account_id: int,
    endpoint_id: str,
    actor_id: str,
    alert_type: str,
    severity: str,
    message: str,
    endpoint: str,
    window_start: int,
    window_end: int,
    count: int = 0,
    distinct: int = 0,
    error_rate: float | None = None,
    p95_latency: float | None = None,
    extra_evidence: Optional[Dict[str, str]] = None,
) -> Row:
    severity_conf = {"HIGH": 0.9, "MEDIUM": 0.75, "LOW": 0.6}.get(severity, 0.5)
    evidence = {
        "count": str(count),
        "distinct_actors": str(distinct),
        "error_rate": str(error_rate or 0.0),
        "p95_latency": str(p95_latency or 0.0),
        "confidence": str(severity_conf),
    }
    if extra_evidence:
        evidence.update(extra_evidence)
    return Row(
        account_id,
        endpoint_id,
        actor_id or "",
        alert_type,
        severity,
        message,
        endpoint or "",
        alert_type,
        window_end,
        window_start,
        window_end,
        count,
        distinct,
        float(error_rate) if error_rate is not None else 0.0,
        float(p95_latency) if p95_latency is not None else 0.0,
        evidence,
    )


class AuthFailureAgg(AggregateFunction):
    def create_accumulator(self) -> Tuple[int, set, Tuple | None]:
        return 0, set(), None

    def add(self, value, accumulator):
        count, actors, sample = accumulator
        count += 1
        actor_id = value[2] or ""
        if actor_id and len(actors) < DISTINCT_ACTOR_CAP:
            actors.add(actor_id)
        if sample is None:
            sample = value
        return count, actors, sample

    def get_result(self, accumulator):
        return accumulator

    def merge(self, acc1, acc2):
        count = acc1[0] + acc2[0]
        actors = acc1[1]
        if len(actors) < DISTINCT_ACTOR_CAP:
            actors |= acc2[1]
        sample = acc1[2] or acc2[2]
        return count, actors, sample


class CountAgg(AggregateFunction):
    def create_accumulator(self) -> Tuple[int, Tuple | None]:
        return 0, None

    def add(self, value, accumulator):
        count, sample = accumulator
        count += 1
        if sample is None:
            sample = value
        return count, sample

    def get_result(self, accumulator):
        return accumulator

    def merge(self, acc1, acc2):
        return acc1[0] + acc2[0], acc1[1] or acc2[1]


class ErrorRateAgg(AggregateFunction):
    def create_accumulator(self) -> Tuple[int, int, Tuple | None]:
        return 0, 0, None

    def add(self, value, accumulator):
        total, errors, sample = accumulator
        total += 1
        if value[3] >= 400:
            errors += 1
        if sample is None:
            sample = value
        return total, errors, sample

    def get_result(self, accumulator):
        return accumulator

    def merge(self, acc1, acc2):
        total = acc1[0] + acc2[0]
        errors = acc1[1] + acc2[1]
        sample = acc1[2] or acc2[2]
        return total, errors, sample


class LatencyAgg(AggregateFunction):
    def create_accumulator(self) -> Tuple[int, list, Tuple | None]:
        return 0, [], None

    def add(self, value, accumulator):
        count, latencies, sample = accumulator
        latency = value[7]
        if latency is not None:
            count += 1
            if len(latencies) < LATENCY_SAMPLE_CAP:
                latencies.append(float(latency))
        if sample is None:
            sample = value
        return count, latencies, sample

    def get_result(self, accumulator):
        return accumulator

    def merge(self, acc1, acc2):
        count = acc1[0] + acc2[0]
        latencies = acc1[1]
        if len(latencies) < LATENCY_SAMPLE_CAP:
            latencies.extend(acc2[1][: max(0, LATENCY_SAMPLE_CAP - len(latencies))])
        sample = acc1[2] or acc2[2]
        return count, latencies, sample


class EnumAgg(AggregateFunction):
    def create_accumulator(self) -> Tuple[List[int], Tuple | None]:
        return [], None

    def add(self, value, accumulator):
        ids, sample = accumulator
        path = value[5] or ""
        parsed = extract_numeric_id(path)
        if parsed is not None and len(ids) < ENUM_SAMPLE_CAP:
            ids.append(parsed)
        if sample is None:
            sample = value
        return ids, sample

    def get_result(self, accumulator):
        return accumulator

    def merge(self, acc1, acc2):
        ids = acc1[0]
        if len(ids) < ENUM_SAMPLE_CAP:
            ids.extend(acc2[0][: max(0, ENUM_SAMPLE_CAP - len(ids))])
        sample = acc1[1] or acc2[1]
        return ids, sample


class DistinctEndpointAgg(AggregateFunction):
    def create_accumulator(self) -> Tuple[set, int, Tuple | None]:
        return set(), 0, None

    def add(self, value, accumulator):
        endpoints, count, sample = accumulator
        endpoint = value[1] or ""
        if endpoint:
            endpoints.add(endpoint)
        count += 1
        if sample is None:
            sample = value
        return endpoints, count, sample

    def get_result(self, accumulator):
        return accumulator

    def merge(self, acc1, acc2):
        endpoints = acc1[0]
        endpoints |= acc2[0]
        count = acc1[1] + acc2[1]
        sample = acc1[2] or acc2[2]
        return endpoints, count, sample


class AuthFailureWindow(ProcessWindowFunction):
    def process(self, key, context, elements: Iterable, out):
        for count, actors, sample in elements:
            if count < AUTH_FAILURE_THRESHOLD or len(actors) < DISTINCT_ACTOR_THRESHOLD:
                continue
            account_id, endpoint_id, actor_id, _, _, path, _, _, _, protocol = sample
            msg = f"{count} auth failures from {len(actors)} actors in 1m"
            out.collect(
                _alert_row(
                    account_id,
                    endpoint_id,
                    actor_id,
                    "CREDENTIAL_STUFFING",
                    "HIGH",
                    msg,
                    path,
                    int(context.window().start),
                    int(context.window().end),
                    count,
                    len(actors),
                )
            )


class RateSpikeWindow(ProcessWindowFunction):
    def process(self, key, context, elements: Iterable, out):
        for count, sample in elements:
            if count < RATE_SPIKE_THRESHOLD or count < RATE_SPIKE_MIN:
                continue
            account_id, endpoint_id, actor_id, _, _, path, _, _, _, protocol = sample
            msg = f"Rate spike: {count} requests in 1m"
            out.collect(
                _alert_row(
                    account_id,
                    endpoint_id,
                    actor_id,
                    "RATE_SPIKE",
                    "MEDIUM",
                    msg,
                    path,
                    int(context.window().start),
                    int(context.window().end),
                    count,
                )
            )


class ErrorRateWindow(ProcessWindowFunction):
    def process(self, key, context, elements: Iterable, out):
        for total, errors, sample in elements:
            if total < ERROR_RATE_MIN:
                continue
            rate = errors / total if total else 0.0
            if rate < ERROR_RATE_THRESHOLD:
                continue
            account_id, endpoint_id, actor_id, _, _, path, _, _, _, protocol = sample
            msg = f"Error rate spike: {errors}/{total} in 5m"
            out.collect(
                _alert_row(
                    account_id,
                    endpoint_id,
                    actor_id,
                    "ERROR_RATE_SPIKE",
                    "MEDIUM",
                    msg,
                    path,
                    int(context.window().start),
                    int(context.window().end),
                    total,
                    0,
                    error_rate=rate,
                )
            )


class ActorBurstWindow(ProcessWindowFunction):
    def process(self, key, context, elements: Iterable, out):
        for count, sample in elements:
            if count < ACTOR_BURST_THRESHOLD:
                continue
            account_id, endpoint_id, actor_id, _, _, path, _, _, _, protocol = sample
            msg = f"Actor burst: {count} requests in 1m"
            out.collect(
                _alert_row(
                    account_id,
                    endpoint_id,
                    actor_id,
                    "ACTOR_BURST",
                    "MEDIUM",
                    msg,
                    path,
                    int(context.window().start),
                    int(context.window().end),
                    count,
                )
            )


class LatencyWindow(ProcessWindowFunction):
    def process(self, key, context, elements: Iterable, out):
        for count, latencies, sample in elements:
            if count < LATENCY_MIN_SAMPLES or not latencies:
                continue
            latencies.sort()
            idx = int(0.95 * (len(latencies) - 1))
            p95 = latencies[idx]
            if p95 < LATENCY_P95_THRESHOLD_MS:
                continue
            account_id, endpoint_id, actor_id, _, _, path, _, _, _, protocol = sample
            msg = f"Latency spike: p95={p95:.2f}ms in 5m"
            out.collect(
                _alert_row(
                    account_id,
                    endpoint_id,
                    actor_id,
                    "LATENCY_SPIKE",
                    "LOW",
                    msg,
                    path,
                    int(context.window().start),
                    int(context.window().end),
                    count,
                    0,
                    p95_latency=p95,
                )
            )


class WorkflowTransitionFunc(KeyedProcessFunction):
    def open(self, runtime_context):
        self.last_endpoint_state = runtime_context.get_state(ValueStateDescriptor("last_endpoint", Types.STRING()))
        self.last_ts_state = runtime_context.get_state(ValueStateDescriptor("last_ts", Types.LONG()))
        self.transition_counts = runtime_context.get_map_state(
            MapStateDescriptor("transition_counts", Types.STRING(), Types.INT())
        )

    def process_element(self, value, ctx, out):
        actor_id = value[2] or "anonymous"
        endpoint = value[5] or ""
        now = ctx.timestamp() or 0
        last_endpoint = self.last_endpoint_state.value()
        last_ts = self.last_ts_state.value() or 0
        if last_endpoint and endpoint and last_endpoint != endpoint:
            transition = f"{last_endpoint}->{endpoint}"
            key = f"{actor_id}:{transition}"
            count = self.transition_counts.get(key)
            count = (count or 0) + 1
            self.transition_counts.put(key, count)
            size = 0
            for _ in self.transition_counts.keys():
                size += 1
                if size > WORKFLOW_MAX_TRANSITIONS:
                    self.transition_counts.clear()
                    break
            duration = now - last_ts
            if count < WORKFLOW_TRANSITION_THRESHOLD and duration < WORKFLOW_WINDOW_MS:
                msg = f"Workflow anomaly: {transition} after {duration}ms"
                out.collect(
                    _alert_row(
                        value[0],
                        value[1],
                        actor_id,
                        "WORKFLOW_SEQUENCE_BREAK",
                        "HIGH",
                        msg,
                        endpoint,
                        max(0, now - WORKFLOW_WINDOW_MS),
                        now,
                        count,
                        0,
                    )
                )
        self.last_endpoint_state.update(endpoint)
        self.last_ts_state.update(now)


class EnumWindow(ProcessWindowFunction):
    def process(self, key, context, elements: Iterable, out):
        for ids, sample in elements:
            if not ids:
                continue
            unique_ids = sorted(set(ids))
            if len(unique_ids) < ENUM_DISTINCT_THRESHOLD:
                continue
            seq_pairs = 0
            for i in range(1, len(unique_ids)):
                if unique_ids[i] == unique_ids[i - 1] + 1:
                    seq_pairs += 1
            ratio = seq_pairs / max(1, len(unique_ids) - 1)
            if ratio < ENUM_SEQUENCE_RATIO:
                continue
            account_id, endpoint_id, actor_id, _, _, path, _, _, _, protocol = sample
            msg = f"Object ID enumeration: {len(unique_ids)} ids, seq_ratio={ratio:.2f}"
            out.collect(
                _alert_row(
                    account_id,
                    endpoint_id,
                    actor_id,
                    "OBJECT_ENUMERATION",
                    "HIGH",
                    msg,
                    path,
                    int(context.window().start),
                    int(context.window().end),
                    len(unique_ids),
                    1,
                    extra_evidence={"seq_ratio": f"{ratio:.2f}"},
                )
            )


class EndpointSweepWindow(ProcessWindowFunction):
    def process(self, key, context, elements: Iterable, out):
        for endpoints, count, sample in elements:
            distinct = len(endpoints)
            if distinct < ENDPOINT_SWEEP_THRESHOLD or count < ENDPOINT_SWEEP_MIN_EVENTS:
                continue
            account_id, endpoint_id, actor_id, _, _, path, _, _, _, protocol = sample
            msg = f"Endpoint sweep: {distinct} distinct endpoints in 5m"
            out.collect(
                _alert_row(
                    account_id,
                    endpoint_id,
                    actor_id,
                    "ENDPOINT_SWEEP",
                    "MEDIUM",
                    msg,
                    path,
                    int(context.window().start),
                    int(context.window().end),
                    count,
                    distinct,
                    extra_evidence={"distinct_endpoints": str(distinct)},
                )
            )


class NotFoundWindow(ProcessWindowFunction):
    def process(self, key, context, elements: Iterable, out):
        for endpoints, count, sample in elements:
            distinct = len(endpoints)
            if count < NOT_FOUND_THRESHOLD or distinct < NOT_FOUND_DISTINCT_THRESHOLD:
                continue
            account_id, endpoint_id, actor_id, _, _, path, _, _, _, protocol = sample
            msg = f"Path scanning: {count} 404s across {distinct} endpoints"
            out.collect(
                _alert_row(
                    account_id,
                    endpoint_id,
                    actor_id,
                    "PATH_SCANNING",
                    "HIGH",
                    msg,
                    path,
                    int(context.window().start),
                    int(context.window().end),
                    count,
                    distinct,
                    extra_evidence={"distinct_endpoints": str(distinct), "status_code": "404"},
                )
            )


def extract_numeric_id(path: str) -> Optional[int]:
    if not path:
        return None
    segment = path.strip("/").split("/")[-1]
    if not segment.isdigit():
        return None
    try:
        return int(segment)
    except Exception:
        return None


def build_job() -> None:
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    group_id = os.environ.get("FLINK_CONSUMER_GROUP", "api-sec-flink")

    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(_env_int("FLINK_PARALLELISM", 2))
    env.set_stream_time_characteristic(TimeCharacteristic.EventTime)
    checkpoint_ms = _env_int("FLINK_CHECKPOINT_INTERVAL_MS", 60000)
    if checkpoint_ms > 0:
        env.enable_checkpointing(checkpoint_ms)
        cfg = env.get_checkpoint_config()
        cfg.set_min_pause_between_checkpoints(_env_int("FLINK_CHECKPOINT_MIN_PAUSE_MS", 10000))
        cfg.set_checkpoint_timeout(_env_int("FLINK_CHECKPOINT_TIMEOUT_MS", 600000))
        cfg.set_max_concurrent_checkpoints(_env_int("FLINK_CHECKPOINT_MAX_CONCURRENT", 1))

    json_schema = JsonRowDeserializationSchema.builder().type_info(
        Types.ROW_NAMED(EVENT_FIELDS, EVENT_TYPES)
    ).build()

    source = KafkaSource.builder() \
        .set_bootstrap_servers(bootstrap) \
        .set_topics_pattern("events.enriched.*") \
        .set_group_id(group_id) \
        .set_starting_offsets(KafkaOffsetsInitializer.latest()) \
        .set_value_only_deserializer(json_schema) \
        .build()

    watermark = (
        WatermarkStrategy
        .for_bounded_out_of_orderness(timedelta(seconds=10))
        .with_timestamp_assigner(lambda event, ts: event[4])
    )

    stream = env.from_source(
        source,
        watermark,
        "enriched-events",
    )
    stream = stream.filter(lambda r: r[1] is not None and r[1] != "")
    stream = stream.filter(lambda r: r[8] is None or r[8] >= MIN_QUALITY_SCORE)

    auth_failures = stream.filter(lambda r: r[3] in (401, 403))
    auth_alerts = (
        auth_failures
        .key_by(lambda r: (r[0], r[1]))
        .window(SlidingEventTimeWindows.of(Time.minutes(1), Time.seconds(10)))
        .aggregate(AuthFailureAgg(), AuthFailureWindow(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    rate_alerts = (
        stream
        .key_by(lambda r: (r[0], r[1]))
        .window(TumblingEventTimeWindows.of(Time.minutes(1)))
        .aggregate(CountAgg(), RateSpikeWindow(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    error_alerts = (
        stream
        .key_by(lambda r: (r[0], r[1]))
        .window(TumblingEventTimeWindows.of(Time.minutes(5)))
        .aggregate(ErrorRateAgg(), ErrorRateWindow(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    actor_alerts = (
        stream
        .key_by(lambda r: (r[0], r[2] or ""))
        .window(TumblingEventTimeWindows.of(Time.minutes(1)))
        .aggregate(CountAgg(), ActorBurstWindow(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    latency_alerts = (
        stream
        .key_by(lambda r: (r[0], r[1]))
        .window(TumblingEventTimeWindows.of(Time.minutes(5)))
        .aggregate(LatencyAgg(), LatencyWindow(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    enum_alerts = (
        stream
        .key_by(lambda r: (r[0], r[1], r[2] or ""))
        .window(TumblingEventTimeWindows.of(Time.minutes(5)))
        .aggregate(EnumAgg(), EnumWindow(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    sweep_alerts = (
        stream
        .key_by(lambda r: (r[0], r[2] or ""))
        .window(TumblingEventTimeWindows.of(Time.minutes(5)))
        .aggregate(DistinctEndpointAgg(), EndpointSweepWindow(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    not_found_alerts = (
        stream
        .filter(lambda r: r[3] == 404)
        .key_by(lambda r: (r[0], r[2] or ""))
        .window(TumblingEventTimeWindows.of(Time.minutes(NOT_FOUND_WINDOW_MINUTES)))
        .aggregate(DistinctEndpointAgg(), NotFoundWindow(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    workflow_alerts = (
        stream
        .key_by(lambda r: (r[0], r[2] or ""))
        .process(WorkflowTransitionFunc(), output_type=Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES))
    )

    alerts = auth_alerts.union(
        rate_alerts,
        error_alerts,
        actor_alerts,
        latency_alerts,
        enum_alerts,
        sweep_alerts,
        not_found_alerts,
        workflow_alerts,
    )

    sink_schema = JsonRowSerializationSchema.builder().with_type_info(
        Types.ROW_NAMED(ALERT_FIELDS, ALERT_TYPES)
    ).build()

    sink = KafkaSink.builder() \
        .set_bootstrap_servers(bootstrap) \
        .set_record_serializer(
            KafkaSink.record_serializer_builder()
            .set_topic("events.alerts")
            .set_value_serialization_schema(sink_schema)
            .build()
        ) \
        .set_delivery_guarantee(DeliveryGuarantee.AT_LEAST_ONCE) \
        .build()

    alerts.sink_to(sink)
    env.execute("api-security-flink-job")


if __name__ == "__main__":
    build_job()
