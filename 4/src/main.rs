
#![windows_subsystem = "windows"]

use native_windows_gui as nwg;
use sha3::{Digest, Sha3_512};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default)]
pub struct NwgUi {
    window: nwg::Window,
    input: nwg::TextInput,
    generate_button: nwg::Button,
    clear_button: nwg::Button,
    output: nwg::TextBox,
}

fn main() {
    nwg::init().expect("Failed to initialize GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");

    let mut ui = NwgUi::default();

    nwg::Window::builder()
        .size((1000, 600))
        .position((300, 300))
        .title("SHA3-512 Hash Generator")
        .build(&mut ui.window)
        .unwrap();

    nwg::TextInput::builder()
        .size((980, 25))
        .position((10, 10))
        .parent(&ui.window)
        .build(&mut ui.input)
        .unwrap();

    nwg::Button::builder()
        .size((480, 30))
        .position((10, 40))
        .text("Generate Hash")
        .parent(&ui.window)
        .build(&mut ui.generate_button)
        .unwrap();

    nwg::Button::builder()
        .size((480, 30))
        .position((510, 40))
        .text("Clear")
        .parent(&ui.window)
        .build(&mut ui.clear_button)
        .unwrap();

    let mut output_font = nwg::Font::default();
    nwg::Font::builder()
        .size(12) // Standard font size
        .family("Consolas") // Monospaced font for consistent hash display
        .build(&mut output_font)
        .unwrap();

    nwg::TextBox::builder()
        .size((980, 500))
        .position((10, 75))
        .text("")
        .parent(&ui.window)
        .readonly(true)
        .font(Some(&output_font))
        .build(&mut ui.output)
        .unwrap();

    let ui_ref = Rc::new(RefCell::new(ui));
    let ui_handler = Rc::clone(&ui_ref);

    let handler = move |evt, _evt_data, handle| {
        let ui = ui_handler.borrow_mut();
        match evt {
            nwg::Event::OnButtonClick => {
                if handle == ui.generate_button {
                    let input_text = nwg::TextInput::text(&ui.input);
                    let mut hasher = Sha3_512::new();
                    hasher.update(input_text.as_bytes());
                    let result = hasher.finalize();
                    let hash_str = format!("{:x}", result);
                    let current_text = ui.output.text();
                    let new_text = if current_text.is_empty() {
                        hash_str
                    } else {
                        format!("{}\r\n{}", current_text, hash_str)
                    };
                    ui.output.set_text(&new_text);
                } else if handle == ui.clear_button {
                    ui.output.set_text("");
                }
            }
            nwg::Event::OnWindowClose => {
                if handle == ui.window {
                    nwg::stop_thread_dispatch();
                }
            }
            _ => {}
        }
    };

    nwg::full_bind_event_handler(&ui_ref.borrow().window.handle, handler);
    nwg::dispatch_thread_events();
}