//! zoxy-edge (#417): a proxy built by a dependent of zoxy rather than by
//! zoxy itself. For now it proves only that the library compiles and links
//! — libcrypto included — inside a dependent's build; the slices of #417
//! grow it into a proxy configured entirely in code.

const zoxy = @import("zoxy");

pub fn main() void {
    // Taking the address forces the whole serving path behind `init` to be
    // analysed and linked, which merely naming the type would not.
    _ = &zoxy.Server(zoxy.Io.XevIo).init;
}
