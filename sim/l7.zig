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
pub const H2Client = @import("l7/h2_client.zig").Client;
pub const H2ClientError = @import("l7/h2_client.zig").ClientError;
pub const H2Mode = @import("l7/h2_client.zig").Mode;
pub const H2Plan = @import("l7/h2_client.zig").Plan;
pub const H2Tuning = @import("l7/h2_client.zig").Tuning;
pub const H2Ask = @import("l7/h2_client.zig").Ask;
pub const h2_canonical_chunked_body = @import("l7/h2_client.zig").canonical_chunked_body;
pub const h2_body_bytes_max = @import("l7/h2_client.zig").body_bytes_max;
pub const h2_body_frames_max = @import("l7/h2_client.zig").body_frames_max;
pub const H3Client = @import("l7/h3_client.zig").Client;
pub const H3Violation = @import("l7/h3_client.zig").Violation;
pub const VersionProbe = @import("l7/version_probe.zig").VersionProbe;
pub const H3ClientError = @import("l7/h3_client.zig").ClientError;
pub const h3_body_bytes_max = @import("l7/h3_client.zig").body_bytes_max;
