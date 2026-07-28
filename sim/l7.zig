//! L7 pieces of the deterministic-simulation gate (§9), split by role:
//! the request scripts as data (`l7/scripts.zig`), the canonical wire
//! bytes both sides check against (`l7/canon.zig`), the §7-oracle origin
//! (`l7/origin.zig`), and the script-driven client with the transcript
//! oracles (`l7/client.zig`). The sim mixes these with the L4 population
//! in one scenario so the shared pools feel cross-protocol pressure.

pub const canon = @import("l7/canon.zig");
pub const scripts = @import("l7/scripts.zig");

pub const Script = scripts.Script;
pub const OriginMode = @import("l7/origin.zig").OriginMode;
pub const HttpOrigin = @import("l7/origin.zig").HttpOrigin;
pub const Client = @import("l7/client.zig").Client;
pub const ClientError = @import("l7/client.zig").ClientError;
