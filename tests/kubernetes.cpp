// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

/// @file
/// @brief Tests for the Kubernetes audit profile of the `json` module.
///
/// Every case runs on both JSON paths: the plain record and the `nul_tail` copy that takes the
/// retry before the NUL.

#include "check.hpp"
#include "json_backends.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <string>

namespace {
using Json = nlohmann::json; ///< JSON type used to build audit records.
using lumtail::test::checked;
using lumtail::test::nul_tail;
using lumtail::test::require;

/// @brief Build a complete audit.k8s.io/v1 event: a forbidden pod creation by `alice`.
///
/// @return The record as a JSON object.
[[nodiscard]] Json record() {
    return {{"apiVersion", "audit.k8s.io/v1"},
            {"kind", "Event"},
            {"level", "Metadata"},
            {"auditID", "synthetic-request"},
            {"stage", "ResponseComplete"},
            {"verb", "create"},
            {"requestURI", "/api/v1/namespaces/demo/pods"},
            {"user", {{"username", "alice"}, {"uid", "actor-1"}, {"groups", {"developers"}}}},
            {"sourceIPs", {"192.0.2.1", "2001:db8::1"}},
            {"objectRef", {{"namespace", "demo"}, {"resource", "pods"}, {"name", "example"}}},
            {"responseStatus", {{"status", "Failure"}, {"code", 403}, {"reason", "Forbidden"}}},
            {"requestReceivedTimestamp", "2026-11-08T12:00:00.123456Z"},
            {"stageTimestamp", "2026-11-08T12:00:01.654321Z"}};
}

/// @brief Serialize an audit record, optionally with a trailing NUL.
///
/// @param source   Audit record.
/// @param fallback True to append a NUL so the JSON module takes its retry path.
/// @return The record text.
[[nodiscard]] std::string input_text(const Json& source, bool fallback) {
    return fallback ? nul_tail(source.dump()) : source.dump();
}

/// @brief Check aliases for every audit stage and policy level on both JSON paths.
///
/// @details The audit `level` is policy detail, not severity, so the event level stays unknown
/// and `auditID` becomes `request_id`, not `event_id`. Authenticated and impersonated users map
/// to `actor` and `target_user`, and `sourceIPs` does not become `src_ip` because the list can
/// be forwarded. Parsing a later record checks that aliases own their storage.
void stages_roles_and_ownership() {
    const lumtail::Registry registry;
    const auto* module = registry.find("json");
    require(module != nullptr, "JSON module must exist");
    for (const auto stage : {"RequestReceived", "ResponseStarted", "ResponseComplete", "Panic"}) {
        for (const auto level : {"None", "Metadata", "Request", "RequestResponse"}) {
            for (const bool fallback : {false, true}) {
                auto source = record();
                source["level"] = level;
                source["stage"] = stage;
                source["impersonatedUser"] = {{"username", "bob"}, {"uid", "target-1"}};
                const auto input = input_text(source, fallback);
                const auto parsed = checked(registry.parse(input));
                const auto forced = checked(registry.parse(input, module));
                require(parsed.event.format == "json" && parsed.event.raw == input &&
                            parsed.event.fields == forced.event.fields &&
                            parsed.event.level == lumtail::Level::unknown,
                        "stages/levels/backends must preserve JSON identity without inferring "
                        "severity");
                require(parsed.event.get("audit_id") == "synthetic-request" &&
                            parsed.event.get("request_id") == "synthetic-request" &&
                            parsed.event.get("audit_stage") == stage &&
                            parsed.event.get("audit_level") == level &&
                            parsed.event.get("original_level") == level &&
                            !parsed.event.fields.contains("event_id"),
                        "audit level is policy detail and audit ID is request correlation");
                require(
                    parsed.event.get("actor") == "alice" &&
                        parsed.event.get("target_user") == "bob" &&
                        parsed.event.get("k8s_user_uid") == "actor-1" &&
                        parsed.event.get("k8s_impersonated_uid") == "target-1" &&
                        parsed.event.get("user") == source["user"].dump(),
                    "native user object and authenticated/impersonated roles must remain distinct");
                require(
                    parsed.event.get("http_status") == "403" &&
                        parsed.event.get("outcome") == "failure" &&
                        parsed.event.get("reason") == "Forbidden" &&
                        parsed.event.get("action") == "create" &&
                        parsed.event.get("k8s_resource") == "pods" &&
                        parsed.event.get("timestamp") == "2026-11-08T12:00:01.654321Z" &&
                        parsed.event.get("message") == "create /api/v1/namespaces/demo/pods" &&
                        !parsed.event.fields.contains("src_ip"),
                    "typed aliases must preserve supplied context without guessing network trust");
                require(checked(lumtail::render(parsed, "audit.jsonl", 4, lumtail::Output::raw,
                                                false, {})) == input,
                        "raw output must preserve bytes");
                const std::string next_input = R"({"message":"ordinary JSON"})";
                const auto next = checked(registry.parse(next_input));
                require(!next.event.fields.contains("k8s_profile") &&
                            parsed.event.get("actor") == "alice",
                        "aliases must own storage and must not leak into later events");
            }
        }
    }
}

/// @brief Check that incomplete or unsupported audit records stay generic JSON.
///
/// @details A missing or null required key, an unsupported API version, kind or enum, or an
/// empty identity must publish no profile alias. Records that also carry Suricata EVE or Zeek
/// markers keep those profiles.
void rejection_and_precedence() {
    const lumtail::Registry registry;
    for (const bool fallback : {false, true}) {
        for (const auto key :
             {"apiVersion", "kind", "level", "auditID", "stage", "verb", "requestURI", "user"}) {
            for (const bool wrong_type : {false, true}) {
                auto source = record();
                if (wrong_type)
                    source[key] = nullptr;
                else
                    source.erase(key);
                const auto input = input_text(source, fallback);
                const auto parsed = checked(registry.parse(input));
                require(parsed.event.format == "json" &&
                            !parsed.event.fields.contains("k8s_profile") &&
                            !parsed.event.fields.contains("actor") &&
                            !parsed.event.fields.contains("audit_id"),
                        "failed recognition must not publish partial aliases");
            }
        }
        for (const auto& [key, value] : std::array<std::pair<std::string_view, Json>, 8>{
                 {{"apiVersion", "audit.k8s.io/v1beta1"},
                  {"kind", "EventList"},
                  {"kind", "event"},
                  {"level", "Error"},
                  {"stage", "UnknownStage"},
                  {"auditID", ""},
                  {"verb", ""},
                  {"user", Json::array()}}}) {
            auto source = record();
            source[key] = value;
            const auto input = input_text(source, fallback);
            require(!checked(registry.parse(input)).event.fields.contains("k8s_profile"),
                    "unsupported schemas/enums and invalid identities must remain generic");
        }
    }
    for (const auto type : {"alert", "http", "dns", "tls", "fileinfo", "anomaly", "flow"}) {
        auto source = record();
        source["event_type"] = type;
        source[type] = Json::object();
        const auto input = source.dump();
        require(!checked(registry.parse(input)).event.fields.contains("k8s_profile"),
                "existing EVE profile behavior must retain precedence");
    }
    auto source = record();
    source["zeek_log_type"] = "custom";
    const auto input = source.dump();
    require(!checked(registry.parse(input)).event.fields.contains("k8s_profile"),
            "ambiguous producer-profile markers must retain existing precedence");
}

/// @brief Check native key collisions, empty optional values and duplicate keys.
///
/// @details Native members win over aliases even when empty. Empty or wrongly typed optional
/// members publish no alias, and `requestReceivedTimestamp` is used only when
/// `stageTimestamp` is absent. With duplicate keys the last one wins on both JSON paths, and an
/// invalid last `level` drops the profile.
void optional_values_duplicates_and_collisions() {
    const lumtail::Registry registry;
    for (const bool fallback : {false, true}) {
        auto source = record();
        source.update(Json{{"actor", ""},
                           {"source", ""},
                           {"timestamp", ""},
                           {"message", ""},
                           {"audit_level", "native"},
                           {"audit_id", "native"},
                           {"http_status", "native"},
                           {"outcome", "native"},
                           {"event_type", "custom"}});
        const auto input = input_text(source, fallback);
        const auto parsed = checked(registry.parse(input));
        require(parsed.event.get("actor").empty() && parsed.event.get("source").empty() &&
                    parsed.event.get("timestamp").empty() && parsed.event.get("message").empty() &&
                    parsed.event.get("audit_level") == "native" &&
                    parsed.event.get("audit_id") == "native" &&
                    parsed.event.get("http_status") == "native" &&
                    parsed.event.get("outcome") == "native" &&
                    parsed.event.get("event_type") == "custom",
                "native values, including empty ones, win collisions");
        source = record();
        source["user"] = Json::object();
        source["requestURI"] = "";
        source["stageTimestamp"] = nullptr;
        source["objectRef"] = Json::array();
        source["responseStatus"] = nullptr;
        const auto empty_input = input_text(source, fallback);
        const auto empty = checked(registry.parse(empty_input));
        require(empty.event.get("k8s_profile") == "audit/v1" &&
                    empty.event.get("message") == "create" &&
                    !empty.event.fields.contains("actor") &&
                    !empty.event.fields.contains("http_status") &&
                    !empty.event.fields.contains("outcome") &&
                    !empty.event.fields.contains("timestamp") &&
                    !empty.event.fields.contains("k8s_resource"),
                "unknown/anonymous optional fields must stay unavailable");
        source.erase("stageTimestamp");
        const auto timestamp_input = input_text(source, fallback);
        const auto timestamp = checked(registry.parse(timestamp_input));
        require(timestamp.event.get("timestamp") == "2026-11-08T12:00:00.123456Z",
                "only an absent stage timestamp may use request reception time");

        auto base = record().dump();
        base.pop_back();
        const std::string suffix = fallback ? std::string("}\0", 2) : "}";
        const auto duplicate =
            base +
            R"(,"user":{"username":"first","username":null},"responseStatus":{"code":200,"code":403,"status":"Failure"})" +
            suffix;
        const auto last = checked(registry.parse(duplicate));
        require(!last.event.fields.contains("actor") && last.event.get("http_status") == "403" &&
                    last.event.get("outcome") == "failure",
                "last nested type/value must win in both backends");
        const auto invalid_last = base + ",\"level\":50" + suffix;
        const auto invalid = checked(registry.parse(invalid_last));
        require(!invalid.event.fields.contains("k8s_profile") &&
                    invalid.event.level == lumtail::Level::error,
                "a last invalid audit level must leave generic JSON severity unchanged");
    }
}

/// @brief Check `outcome` and `http_status` for every combination of code type and status.
///
/// @details `http_status` is published only for an integer code from 100 to 599. An outcome
/// requires the status to agree with the code class (2xx for `Success`); without a code the
/// status alone decides. Severity stays unknown in every case.
void outcome_consistency() {
    const lumtail::Registry registry;
    const std::array<Json, 12> codes{100, 200, 299, 300, 403, 599, 0, 600, -1, 403.0, "403", true};
    for (const bool fallback : {false, true}) {
        for (const auto& code : codes) {
            for (const auto status : {"Success", "Failure", "unknown"}) {
                auto source = record();
                source["responseStatus"] = {{"code", code}, {"status", status}};
                const auto input = input_text(source, fallback);
                const auto parsed = checked(registry.parse(input));
                const bool valid_code = code.is_number_integer() && code >= 100 && code <= 599;
                const bool successful = valid_code && code >= 200 && code <= 299;
                const auto expected =
                    valid_code && std::string_view(status) == "Success" && successful    ? "success"
                    : valid_code && std::string_view(status) == "Failure" && !successful ? "failure"
                                                                                         : "";
                require(parsed.event.get("outcome") == expected &&
                            parsed.event.fields.contains("http_status") == valid_code &&
                            parsed.event.level == lumtail::Level::unknown,
                        "typed HTTP code consistency must not invent status/outcome/severity");
            }
        }
    }
    for (const auto status : {"Success", "Failure"}) {
        auto source = record();
        source["responseStatus"] = {{"status", status}};
        const auto input = source.dump();
        const auto parsed = checked(registry.parse(input));
        require(parsed.event.get("outcome") ==
                        (std::string_view(status) == "Success" ? "success" : "failure") &&
                    !parsed.event.fields.contains("http_status"),
                "an absent code does not erase explicit status");
    }
}
} // namespace

/// @brief Run every Kubernetes audit test; any failure aborts.
int main() {
    stages_roles_and_ownership();
    rejection_and_precedence();
    optional_values_duplicates_and_collisions();
    outcome_consistency();
}
