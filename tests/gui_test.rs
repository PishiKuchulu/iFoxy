#![cfg(windows)]
// Uses the Windows tao platform extension and builds a real window, so
// this smoke test is Windows-only (the Linux GUI is exercised by running
// the app; the shared wry/tao types are covered by the main build).

#[test]
fn test_tao_and_wry_types() {
    use tao::dpi::LogicalSize;
    let size = LogicalSize::new(400.0, 700.0);
    assert_eq!(size.width, 400.0);
    assert_eq!(size.height, 700.0);

    use tao::platform::windows::EventLoopBuilderExtWindows;
    let event_loop = tao::event_loop::EventLoopBuilder::new()
        .with_any_thread(true)
        .build();
    let _window = tao::window::WindowBuilder::new()
        .with_title("iFoxy")
        .with_inner_size(size)
        .build(&event_loop)
        .unwrap();

    let _builder = wry::WebViewBuilder::new().with_url("http://127.0.0.1:44123");
}
