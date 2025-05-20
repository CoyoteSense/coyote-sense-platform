# Channels Overview

This document describes the messaging channels used in the CoyoteSense platform. Channels are used for communication between units, system components, and external systems.

## Channel List

| Channel Name                  | Scope      | Purpose                                                        |
|-------------------------------|------------|----------------------------------------------------------------|
| units-registration            | Common     | Register/unregister events for all units                       |
| {unitid}-command              | Per-Unit   | Commands sent to a specific unit                               |
| {unitid}-reply                | Per-Unit   | Replies from a specific unit                                   |
| logs / {unitid}-logs          | Common/Per | Logging (common or per-unit, depending on requirements)        |
| external-notifications        | Common     | External system notifications (Trading/Payment/etc)            |
| {unitid}-notification         | Per-Unit   | Notification from a specific unit                              |
| {unitid}-order-notification   | Per-Unit   | Special notification channel for order-related events          |
| {unitid}-market-notification  | Per-Unit   | Special notification channel for market-related events         |
| broadcast-command             | Common     | Broadcast commands to all units                                |
| units-heartbeat               | Common     | Health/heartbeat signals from units                            |
| system-broadcast              | Common     | System-wide announcements or configuration changes             |
| alerts / {unitid}-alerts      | Common/Per | Critical errors or alerts (common or per-unit)                 |

## Channel Descriptions

- **units-registration**: All units notify about register/unregister events here.
- **{unitid}-command**: Commands sent to a specific unit.
- **{unitid}-reply**: Replies from a specific unit to commands.
- **logs / {unitid}-logs**: Collect logs either in a common channel or per unit.
- **external-notifications**: External system notifications (e.g., trading, payment, etc.).
- **{unitid}-notification**: Notification from a specific unit.
- **{unitid}-order-notification**: Special notification channel for order-related events from a specific unit.
- **{unitid}-market-notification**: Special notification channel for market-related events from a specific unit.
- **broadcast-command**: Send a command to all units at once.
- **units-heartbeat**: Periodic heartbeat messages from units to indicate they are alive.
- **system-broadcast**: System-wide announcements or configuration changes.
- **alerts / {unitid}-alerts**: Critical errors or alerts, either common or per-unit.

> Adjust per-unit vs. common channels based on scalability and filtering needs.

> It is possible to define additional special notification channels as needed, such as {unitid}-order-notification or {unitid}-market-notification, to separate different types of notifications per unit.
