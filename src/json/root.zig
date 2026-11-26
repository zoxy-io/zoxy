//! zoxy's JSON (#417): the stock binary's front-end onto the library's
//! options — the config file's DTOs and their translation (`loader`), the
//! JSON Schema emitted from those same DTOs (`schema`), and the validator
//! the schema/loader differential gate runs (`validator`).
//!
//! Private to this repository's own builds: build.zig creates it rather
//! than adding it, so a package depending on zoxy cannot import it. A
//! custom build states `zoxy.Options` in code.

pub const loader = @import("loader.zig");
pub const schema = @import("schema.zig");
pub const validator = @import("validator.zig");

pub const FileSource = loader.FileSource;
pub const NameSource = loader.NameSource;
pub const ParseError = loader.ParseError;
pub const optionsFromJson = loader.optionsFromJson;
pub const parse = loader.parse;
pub const parseWithFiles = loader.parseWithFiles;
pub const parseWithSources = loader.parseWithSources;

test {
    _ = loader;
    _ = schema;
    _ = validator;
}
