//! The tray icon: the way back to a window that is hidden.
//!
//! It exists whenever hiding is possible -- because the operator asked for closing to hide, or
//! because the operating system started the app in the background -- and only then. A window
//! that can vanish with no way back is a machine quietly running containers nobody can see, so
//! hiding and this icon are the same feature.
//!
//! The menu's Quit is the honest one: it exits, which runs the ordinary shutdown and stops the
//! sandboxes. Opening from here never stops anything.

use tauri::Manager as _;

/// The icon's id, so it can be found again when the setting changes.
pub const TRAY_ID: &str = "deepsand-tray";

/// Whether the icon should exist at all.
///
/// Separate from the code that builds it so the rule can be read, and tested, without a window
/// server: the icon is needed exactly when the window can be hidden.
pub fn wanted(close_to_tray: bool, started_hidden: bool) -> bool {
    close_to_tray || started_hidden
}

/// Put the icon in place, if it is not already there.
pub fn install(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    // Only the instance that owns the app may have an icon. A second launch is on its way out
    // and must not leave one behind.
    if !crate::instance::is_primary() {
        return Ok(());
    }
    // And only one at a time, even if two callers race: the lookup below and the build are
    // not atomic together.
    static INSTALLING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serialised = INSTALLING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if app.tray_by_id(TRAY_ID).is_some() {
        return Ok(());
    }
    let open = MenuItem::with_id(app, "open", "Open Deepsand", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit and stop the sandboxes", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Deepsand")
        .menu(&menu)
        // A left click opens the window, which is what a tray icon is for; the menu is still
        // there on a right click.
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            // The same path as closing for real, so the sandboxes are stopped rather than
            // orphaned.
            "quit" => {
                tracing::info!("quitting from the tray");
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Any button state: Windows delivers the press and the release, and only one of them
            // has to open the window. Requiring `Up` meant a left click did nothing at all.
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
            // Windows users double-click tray icons; the first click of a double is a plain Click,
            // so this only matters when the platform sends a DoubleClick without the Click.
            if let tauri::tray::TrayIconEvent::DoubleClick {
                button: tauri::tray::MouseButton::Left,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// Show or hide the icon, creating it the first time it is wanted.
pub fn set_visible(app: &tauri::AppHandle, visible: bool) {
    if visible {
        if let Err(err) = install(app) {
            tracing::warn!(%err, "could not put the tray icon in place");
        }
    }
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        if let Err(err) = tray.set_visible(visible) {
            tracing::warn!(%err, "could not change the tray icon's visibility");
        }
    }
}

/// Bring the window back, from the tray or from a second launch.
pub fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tray_tests {
    use super::*;

    /// The icon is needed exactly when the window can be hidden. Shipping it when it is not
    /// would put an icon in the tray of every operator who never asked for one, and leaving it
    /// out when it is would strand the window.
    #[test]
    fn the_icon_exists_exactly_when_the_window_can_be_hidden() {
        assert!(!wanted(false, false));
        assert!(wanted(true, false), "closing to the tray needs a way back");
        assert!(wanted(false, true), "starting hidden needs a way in");
        assert!(wanted(true, true));
    }
}
