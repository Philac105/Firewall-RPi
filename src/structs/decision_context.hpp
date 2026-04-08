#pragma once

struct DecisionContext {
    // True when packet belongs to prioritized admin traffic.
    bool is_admin_traffic = false;
};
