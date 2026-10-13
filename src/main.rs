#![windows_subsystem = "windows"]

use ifoxy_windows::control_api::{run_hardened_ui_server, ControlApiConfig};
use ifoxy_windows::security::enforce_safe_dll_search;
use ifoxy_windows::tauri_bridge::{bind_ui_server, AppState};
use ifoxy_windows::vpn::routing::{is_admin, request_elevation};
use std::path::PathBuf;
use std::sync::Arc;

/// This is a GUI-subsystem executable, so `eprintln!` is invisible: show a
/// message box instead so the user learns why the program did not start.
#[cfg(windows)]
fn show_fatal_error(message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let text: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    let caption: Vec<u16> = "iFoxy".encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: both buffers are NUL-terminated UTF-16 and outlive the call.
    unsafe {
        MessageBoxW(0, text.as_ptr(), caption.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

#[cfg(not(windows))]
fn show_fatal_error(message: &str) {
    eprintln!("{}", message);
}

/// Warning dialog with Yes / No (default: No). Returns true only for Yes.
#[cfg(windows)]
fn ask_yes_no_default_no(message: &str) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO,
    };
    let text: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    let caption: Vec<u16> = "iFoxy - security warning"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: both buffers are NUL-terminated UTF-16 and outlive the call.
    let answer = unsafe {
        MessageBoxW(
            0,
            text.as_ptr(),
            caption.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
        )
    };
    answer == IDYES
}

#[cfg(not(windows))]
fn ask_yes_no_default_no(_message: &str) -> bool {
    false
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0. Enforce safe DLL search (C3: no current directory or untrusted DLL searching)
    enforce_safe_dll_search();

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    // Verify WebView2Loader.dll integrity if a stray copy sits next to the exe.
    // The loader is statically linked, so a present DLL is suspicious; a
    // tampered one must still be rejected (defense in depth).
    if let Err(e) = ifoxy_windows::security::verify_webview2_loader_dll_at(&exe_dir) {
        show_fatal_error(&format!(
            "Fatal security error: WebView2Loader.dll failed verification: {:?}",
            e
        ));
        return Err(Box::new(e));
    }

    // 1. Initialize rolling file logger with bounded size (R-13, H10)
    let _logger_guard = ifoxy_windows::logging::init_rolling_logger();

    // 2. Elevate process if needed for Wintun adapter and system routing
    // Elevate BEFORE acquiring single instance mutex to prevent handover deadlock (R-14, M10)
    if !is_admin() {
        request_elevation();
        return Ok(());
    }

    // C3: we are now running ELEVATED. If this folder is writable by normal
    // users, any local program could replace the exe or a DLL in it and gain
    // administrator rights. The check lives here (not before elevation) so it
    // is asked once, in the process that actually has the privileges.
    //
    // Instead of silently refusing (which blocked every development run from
    // `target\release`), the user gets an explicit decision, defaulting to No.
    // IFOXY_ALLOW_PORTABLE=1 skips the question for development machines.
    let allow_portable = std::env::var("IFOXY_ALLOW_PORTABLE")
        .map(|v| v == "1")
        .unwrap_or(false);
    if let Err(e) = ifoxy_windows::security::check_install_location(&exe_dir, allow_portable) {
        let proceed = ask_yes_no_default_no(&format!(
            "iFoxy is running as Administrator from this folder:\n\n{}\n\n\
             Because this folder can be modified by a normal user, a local \
             program could replace iFoxy or its DLLs and gain administrator \
             rights. For everyday use, install to an administrator-only \
             folder with install.ps1.\n\n\
             Choose Yes to run anyway (for development only), or No to exit.\n\n\
             To skip this warning permanently, set IFOXY_ALLOW_PORTABLE=1.",
            exe_dir.display()
        ));
        if !proceed {
            // Show a clear "why we exited" message instead of a bare error code.
            show_fatal_error(&format!(
                "iFoxy stopped because it was not started from a secure folder.\n\n\
                 To run it safely, install with install.ps1 (which uses\n\
                 %ProgramFiles%\\iFoxy, writable only by Administrators).\n\n\
                 For a portable/development run, answer Yes at the warning or\n\
                 set the environment variable IFOXY_ALLOW_PORTABLE=1."
            ));
            return Err(Box::new(e));
        }
        tracing::warn!(
            "Running elevated from a user-writable location by explicit user choice: {}",
            exe_dir.display()
        );
    }

    // 3. Single instance check with owned handle guard (M10, R-14)
    let _instance_guard = match ifoxy_windows::security::acquire_single_instance(
        "Global\\iFoxy_SingleInstance_Mutex",
    ) {
        Some(guard) => guard,
        None => {
            eprintln!("Another instance of iFoxy is already running.");
            return Ok(());
        }
    };

    // 4. Crash recovery: replay recovery journal if dirty before any network changes (R-9)
    let native_backend = ifoxy_windows::vpn::network_backend::WindowsNativeBackend::new();
    if let Err(e) = ifoxy_windows::vpn::recovery_journal::RecoveryJournal::recover_if_dirty(
        &ifoxy_windows::vpn::recovery_journal::RecoveryJournal::default_path(),
        &native_backend,
    ) {
        tracing::error!("Recovery journal replay error on startup: {:?}", e);
    }

    // 5. Initialize background Tokio runtime for async VPN core & UI API server
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let state = Arc::new(AppState::new());
    let server_state = state.clone();

    // Generate cryptographically random token for control API (C2)
    let api_cfg = ControlApiConfig::default();
    let api_token = api_cfg.token.clone();

    // Bind UI server synchronously to guarantee availability before opening WebView
    let (listener, port) = rt.block_on(async { bind_ui_server(44123).await })?;

    let server_token = api_token.clone();
    rt.spawn(async move {
        let _ = run_hardened_ui_server(server_state, listener, server_token).await;
    });

    // 6. Create native desktop window using tao (Win32 windowing)
    let event_loop = tao::event_loop::EventLoop::new();
    let mut win_builder = tao::window::WindowBuilder::new()
        .with_title("iFoxy")
        .with_inner_size(tao::dpi::LogicalSize::new(400.0, 720.0))
        .with_resizable(false);
    // Window/taskbar icon (32x32 raw RGBA, generated from icon/icon.png).
    if let Ok(icon) = tao::window::Icon::from_rgba(
        include_bytes!("../assets/ifoxy_icon_32_rgba.bin").to_vec(),
        32,
        32,
    ) {
        win_builder = win_builder.with_window_icon(Some(icon));
    }
    let window = win_builder.build(&event_loop)?;

    // 7. Attach native Microsoft Edge WebView2 rendering inside the window
    let webview_data_dir = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("iFoxy")
        .join("webview_data");
    let _ = std::fs::create_dir_all(&webview_data_dir);

    let mut web_context = wry::WebContext::new(Some(webview_data_dir));
    // Out-of-band token delivery (C2, R-10): inject token directly into JavaScript runtime
    let _webview = wry::WebViewBuilder::new_with_web_context(&mut web_context)
        .with_initialization_script(format!("window.__IFOXY_TOKEN__ = '{}';", api_token))
        .with_url(format!("http://127.0.0.1:{}", port))
        .build(&window)?;

    // 6. Run native Windows event loop
    let shutdown_state = state.clone();
    let rt_handle = rt.handle().clone();
    event_loop.run(move |event, _, control_flow| {
        *control_flow = tao::event_loop::ControlFlow::Wait;
        if let tao::event::Event::WindowEvent {
            event: tao::event::WindowEvent::CloseRequested,
            ..
        } = event
        {
            // Wait (bounded) for the actor to finish tearing down routes,
            // kill switch, adapter and proxy BEFORE the process exits.
            // Previously this only queued a Disconnect command and exited
            // immediately, so cleanup frequently never ran (S-8).
            let svc = &shutdown_state.vpn_service;
            rt_handle.block_on(async {
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(8), svc.disconnect_async())
                        .await;
            });
            *control_flow = tao::event_loop::ControlFlow::Exit;
        }
    });
}
