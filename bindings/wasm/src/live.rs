//! Live sync over the browser's (or Node's) `WebSocket`.
//!
//! The protocol logic is the same sans-IO code the native client uses
//! (`kith_client::{hello_frame, auth_frame, announce_frame, broadcast_frame}` and
//! `Client::handle_frame`); this module only moves frames between the socket and
//! the client and turns events into plain JS objects for the app's callback.

use std::{cell::RefCell, rc::Rc};

use js_sys::{Array, Function, Object, Reflect, Uint8Array};
use kith_client::{
    Change, Client, Event, Store, announce_frame, auth_frame, broadcast_frame, hello_frame,
};
use kith_protocol::{Frame, decode, encode};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{BinaryType, CloseEvent, MessageEvent, WebSocket};

pub type SharedClient = Rc<RefCell<Client<Box<dyn Store>>>>;

pub struct Live {
    ws: WebSocket,
    org: String,
    // Kept alive for as long as the socket can call them.
    _on_open: Closure<dyn FnMut()>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
    _on_error: Closure<dyn FnMut(web_sys::Event)>,
}

fn send_frame(ws: &WebSocket, frame: &Frame) {
    if let Ok(bytes) = encode(frame) {
        // Fails only if the socket is not open; the relay then simply misses this frame.
        let _ = ws.send_with_u8_array(&bytes);
    }
}

fn set(obj: &Object, key: &str, value: impl Into<JsValue>) {
    let _ = Reflect::set(obj, &key.into(), &value.into());
}

fn strings(items: &[String]) -> Array {
    items.iter().map(|s| JsValue::from_str(s)).collect()
}

fn simple_event(kind: &str) -> Object {
    let o = Object::new();
    set(&o, "type", kind);
    o
}

/// Turn a client event into the JS object passed to the app's callback.
/// `None` for frames the app has no use for.
fn to_js(ev: Event) -> Option<Object> {
    let o = Object::new();
    match ev {
        Event::Received {
            org,
            from,
            change,
            is_new,
        } => {
            set(&o, "type", "received");
            set(&o, "org", org);
            set(&o, "from", from);
            set(&o, "objectId", change.body.object_id.to_hex());
            set(&o, "changeId", change.change_id.to_hex());
            set(&o, "isNew", is_new);
        }
        Event::Rejected { org, from, reason } => {
            set(&o, "type", "rejected");
            set(&o, "org", org);
            set(&o, "from", from);
            set(&o, "reason", reason);
        }
        Event::Presence { org, online } => {
            set(&o, "type", "presence");
            set(&o, "org", org);
            set(&o, "online", strings(&online));
        }
        Event::Receipt { delivered } => {
            set(&o, "type", "receipt");
            set(&o, "delivered", strings(&delivered));
        }
        Event::RelayError { code, message } => {
            set(&o, "type", "relayError");
            set(&o, "code", code);
            set(&o, "message", message);
        }
        Event::Ignored => return None,
    }
    Some(o)
}

fn emit(on_event: &Function, ev: Object) {
    if let Err(e) = on_event.call1(&JsValue::NULL, &ev) {
        web_sys::console::error_2(&"kith: event callback threw".into(), &e);
    }
}

impl Live {
    /// Open a WebSocket to `url`, authenticate as the client's device and join `org`.
    /// `on_event` is called with one plain object per event (see `to_js`), plus
    /// `{type: "closed"}` and `{type: "error"}` for the connection itself.
    pub fn connect(
        client: SharedClient,
        url: &str,
        org: &str,
        on_event: Function,
    ) -> Result<Self, JsValue> {
        let ws = WebSocket::new(url)?;
        ws.set_binary_type(BinaryType::Arraybuffer);

        let on_open = {
            let (ws, client) = (ws.clone(), client.clone());
            Closure::<dyn FnMut()>::new(move || {
                send_frame(&ws, &hello_frame(client.borrow().signer()));
            })
        };

        let on_message = {
            let (ws, client, on_event, org) = (
                ws.clone(),
                client.clone(),
                on_event.clone(),
                org.to_string(),
            );
            Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                let data = e.data();
                let bytes = match data.as_string() {
                    Some(text) => text.into_bytes(),
                    None => Uint8Array::new(&data).to_vec(),
                };
                let Ok(frame) = decode(&bytes) else {
                    emit(&on_event, {
                        let o = simple_event("relayError");
                        set(&o, "code", "bad-frame");
                        set(
                            &o,
                            "message",
                            "the relay sent something that is not a frame",
                        );
                        o
                    });
                    return;
                };
                if let Frame::Challenge { nonce } = &frame {
                    let c = client.borrow();
                    send_frame(&ws, &auth_frame(c.signer(), nonce));
                    // Pipelined: a failed auth makes the relay send an error and close.
                    send_frame(&ws, &announce_frame(&org, ""));
                    return;
                }
                // Release the borrow before calling into JS, which may call back into the client.
                let event = client.borrow_mut().handle_frame(frame);
                match event {
                    Ok(ev) => {
                        if let Some(o) = to_js(ev) {
                            emit(&on_event, o);
                        }
                    }
                    Err(err) => emit(&on_event, {
                        let o = simple_event("relayError");
                        set(&o, "code", "storage");
                        set(&o, "message", err.to_string());
                        o
                    }),
                }
            })
        };

        let on_close = {
            let on_event = on_event.clone();
            Closure::<dyn FnMut(CloseEvent)>::new(move |_| emit(&on_event, simple_event("closed")))
        };
        let on_error = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            emit(&on_event, simple_event("error"));
        });

        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        Ok(Self {
            ws,
            org: org.to_string(),
            _on_open: on_open,
            _on_message: on_message,
            _on_close: on_close,
            _on_error: on_error,
        })
    }

    /// Tell the other online devices about a new local change.
    pub fn broadcast(&self, change: &Change) {
        send_frame(&self.ws, &broadcast_frame(&self.org, change));
    }

    pub fn close(&self) {
        let _ = self.ws.close();
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.ws.set_onopen(None);
        self.ws.set_onmessage(None);
        self.ws.set_onclose(None);
        self.ws.set_onerror(None);
        let _ = self.ws.close();
    }
}
