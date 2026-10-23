#[cfg(windows)]
use std::env;
#[cfg(windows)]
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Embed the application icon + version metadata into the Windows binary.
    // (winres is a Windows-host build dependency; the block is host-gated so
    // Linux builds of build.rs never reference it.)
    #[cfg(windows)]
    {
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            let mut res = winres::WindowsResource::new();
            res.set_icon("assets/ifoxy.ico");
            res.set("ProductName", "iFoxy");
            res.set("FileDescription", "iFoxy VPN Client");
            res.set("CompanyName", "PishiKuchulu");
            res.set("LegalCopyright", "PishiKuchulu");
            if let Err(e) = res.compile() {
                println!("cargo:warning=winres compile failed: {}", e);
            }
        }

        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();

        // Ensure the linker can find WebView2LoaderStatic.lib for static linking
        // (the dynamic-link WebView2Loader.dll is no longer required).
        let static_lib = Path::new(&manifest_dir).join("WebView2LoaderStatic.lib");
        if static_lib.exists() {
            println!(
                "cargo:rustc-link-search=native={}",
                manifest_dir.replace('\\', "/")
            );
        } else {
            println!("cargo:warning=WebView2LoaderStatic.lib missing; WebView2 will fall back to DLL");
        }
    }
}
