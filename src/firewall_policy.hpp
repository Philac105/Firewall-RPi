// Fait par: Philippe Lacasse (lacp2116)
// Dernière modification par: Xavier Breton (brex1001)

#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "packet_capture.hpp"
#include "structs/acl_rule.hpp"
#include "structs/decision_context.hpp"
#include "structs/firewall_decision.hpp"
#include "structs/flow_key.hpp"
#include "structs/token_bucket.hpp"

class FirewallPolicy {
public:
    using Decision = FirewallDecision;

    FirewallPolicy();

    Decision evaluate(const PacketMeta &packet, std::uint64_t now_ns) noexcept;

    std::string report_counters();

private:
    static constexpr std::uint8_t kProtoTcp = 6;
    static constexpr std::uint8_t kProtoUdp = 17;
    static constexpr std::uint16_t kAdminPortSsh = 22;
    static constexpr std::uint16_t kAdminPortHttps = 443;
    static constexpr std::uint16_t kAllowedAdminPorts[] = {kAdminPortSsh, kAdminPortHttps};

    void initialize_default_acl();
    static std::uint32_t ip_to_u32(const std::array<std::uint8_t, 4> &ip) noexcept;
    static FlowKey forward_flow(const PacketMeta &packet) noexcept;
    static FlowKey reverse_flow(const PacketMeta &packet) noexcept;
    bool is_established_flow(const PacketMeta &packet) noexcept;
    void remember_flow(const PacketMeta &packet) noexcept;
    bool is_admin_traffic(const PacketMeta &packet) const noexcept;
    bool apply_rate_limit(const PacketMeta &packet, std::uint64_t now_ns, bool high_priority) noexcept;
    Decision apply_acl(const PacketMeta &packet, DecisionContext &ctx) noexcept;

    std::vector<ACLRule> acl_rules_;
    std::unordered_map<std::uint32_t, std::uint64_t> rule_hits_;
    std::unordered_set<FlowKey, FlowKeyHash> established_flows_;
    std::unordered_map<std::uint32_t, TokenBucket> rate_limiters_;
    std::deque<FlowKey> flow_eviction_queue_;
    std::uint64_t rate_limited_drops_ = 0;
};
