// Fait par: Philippe Lacasse (lacp2116)
// Dernière modification par: Philippe Lacasse (lacp2116)

#include "firewall_policy.hpp"

#include <chrono>
#include <sstream>

FirewallPolicy::FirewallPolicy() {
    initialize_default_acl();
}

void FirewallPolicy::initialize_default_acl() {
    acl_rules_.push_back({2, kProtoTcp, 22, true, "allow_ssh"});
    acl_rules_.push_back({3, kProtoTcp, 443, true, "allow_https"});
    acl_rules_.push_back({4, kProtoUdp, 53, true, "allow_dns_udp"});
    acl_rules_.push_back({5, kProtoTcp, 53, true, "allow_dns_tcp"});

    acl_rules_.push_back({1000, 0, 0, false, "deny_all"});

    for (const ACLRule &rule: acl_rules_) {
        rule_hits_[rule.id] = 0;
    }
    rule_hits_[1] = 0;
}

std::uint32_t FirewallPolicy::ip_to_u32(const std::array<std::uint8_t, 4> &ip) noexcept {
    return (static_cast<std::uint32_t>(ip[0]) << 24U)
           | (static_cast<std::uint32_t>(ip[1]) << 16U)
           | (static_cast<std::uint32_t>(ip[2]) << 8U)
           | static_cast<std::uint32_t>(ip[3]);
}

FlowKey FirewallPolicy::forward_flow(const PacketMeta &packet) noexcept {
    return FlowKey{
        .protocol = packet.ip_protocol,
        .src_port = packet.src_port,
        .dst_port = packet.dst_port,
        .src_ip = ip_to_u32(packet.src_ip),
        .dst_ip = ip_to_u32(packet.dst_ip),
    };
}

FlowKey FirewallPolicy::reverse_flow(const PacketMeta &packet) noexcept {
    return FlowKey{
        .protocol = packet.ip_protocol,
        .src_port = packet.dst_port,
        .dst_port = packet.src_port,
        .src_ip = ip_to_u32(packet.dst_ip),
        .dst_ip = ip_to_u32(packet.src_ip),
    };
}

bool FirewallPolicy::is_established_flow(const PacketMeta &packet) noexcept {
    const FlowKey rev = reverse_flow(packet);
    return established_flows_.find(rev) != established_flows_.end();
}

void FirewallPolicy::remember_flow(const PacketMeta &packet) noexcept {
    const FlowKey fwd = forward_flow(packet);
    if (established_flows_.insert(fwd).second) {
        flow_eviction_queue_.push_back(fwd);
        constexpr std::size_t kMaxTrackedFlows = 8192;
        while (flow_eviction_queue_.size() > kMaxTrackedFlows) {
            const FlowKey &oldest = flow_eviction_queue_.front();
            established_flows_.erase(oldest);
            flow_eviction_queue_.pop_front();
        }
    }
}

bool FirewallPolicy::is_admin_traffic(const PacketMeta &packet) const noexcept {
    if (packet.ip_protocol != kProtoTcp) {
        return false;
    }

    for (std::uint16_t allowed_port: kAllowedAdminPorts) {
        if (packet.dst_port == allowed_port) {
            return true;
        }
    }
    return false;
}

bool FirewallPolicy::apply_rate_limit(
    const PacketMeta &packet,
    const std::uint64_t now_ns,
    const bool high_priority
) noexcept {
    if (high_priority) {
        return true;
    }

    constexpr double kRatePerSecond = 2000.0;
    constexpr double kBurst = 4000.0;
    constexpr double kNsPerSec = 1'000'000'000.0;

    const std::uint32_t src = ip_to_u32(packet.src_ip);
    TokenBucket &bucket = rate_limiters_[src];
    if (bucket.last_refill_ns == 0) {
        bucket.last_refill_ns = now_ns;
    }

    const std::uint64_t elapsed_ns = now_ns - bucket.last_refill_ns;
    const double refill = (static_cast<double>(elapsed_ns) / kNsPerSec) * kRatePerSecond;
    bucket.tokens = bucket.tokens + refill;
    if (bucket.tokens > kBurst) {
        bucket.tokens = kBurst;
    }
    bucket.last_refill_ns = now_ns;

    if (bucket.tokens >= 1.0) {
        bucket.tokens -= 1.0;
        return true;
    }

    ++rate_limited_drops_;
    return false;
}

FirewallPolicy::Decision FirewallPolicy::apply_acl(const PacketMeta &packet, DecisionContext &ctx) noexcept {
    if (is_established_flow(packet)) {
        ++rule_hits_[1];
        ctx.is_admin_traffic = is_admin_traffic(packet);
        return Decision::Pass;
    }

    for (const ACLRule &rule: acl_rules_) {
        if (rule.id == 1000) {
            continue;
        }

        if (rule.protocol != 0 && packet.ip_protocol != rule.protocol) {
            continue;
        }

        if (rule.dst_port != 0 && packet.dst_port != rule.dst_port) {
            continue;
        }

        ++rule_hits_[rule.id];
        ctx.is_admin_traffic = is_admin_traffic(packet);
        if (rule.allow) {
            remember_flow(packet);
            return Decision::Pass;
        }
        return Decision::Drop;
    }

    ++rule_hits_[1000];
    return Decision::Drop;
}

FirewallPolicy::Decision FirewallPolicy::evaluate(const PacketMeta &packet, const std::uint64_t now_ns) noexcept {
    DecisionContext ctx{};
    Decision decision = apply_acl(packet, ctx);
    if (decision == Decision::Drop) {
        return decision;
    }

    if (!apply_rate_limit(packet, now_ns, ctx.is_admin_traffic)) {
        return Decision::Drop;
    }

    return Decision::Pass;
}

std::string FirewallPolicy::report_counters() {
    auto hits_for = [this](const std::uint32_t id) -> std::uint64_t {
        const auto it = rule_hits_.find(id);
        return (it != rule_hits_.end()) ? it->second : 0;
    };

    std::ostringstream oss;
    oss << "rules"
            << " est=" << hits_for(1)
            << " p22=" << hits_for(2)
            << " p443=" << hits_for(3)
            << " p53u=" << hits_for(4)
            << " p53t=" << hits_for(5)
            << " deny=" << hits_for(1000)
            << " rate_drop=" << rate_limited_drops_;

    for (auto &entry: rule_hits_) {
        entry.second = 0;
    }
    rate_limited_drops_ = 0;

    return oss.str();
}
