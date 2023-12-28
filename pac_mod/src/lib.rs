extern crate alloc;
extern crate core;
extern crate wee_alloc;

use alloc::vec::Vec;
use std::slice;
use boa_engine::{Source, Context, NativeFunction, JsResult, JsValue as NativeJsValue};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

static BUILTIN_JS: &str = include_str!("builtin.js");

pub fn eval_pac(src: &str, url: &str, host: &str) -> String {
    fn to_js_resp(resp: String) -> JsResult<NativeJsValue> {
        if resp.is_empty() {
            Ok(NativeJsValue::null())
        } else {
            Ok(NativeJsValue::new(resp))
        }
    }
    let mut cb = Context::default();
    cb.register_global_builtin_callable("dnsResolve", 1, NativeFunction::from_fn_ptr(
        |_, a, _| if let Some(host) = a[0].as_string() {
            to_js_resp(dns_resolve(host.to_std_string_escaped().as_str()))
        } else {
            Ok(NativeJsValue::null())
        })).unwrap();
    cb.register_global_builtin_callable(
        "myIpAddress", 0, NativeFunction::from_fn_ptr(|_, _, _| to_js_resp(my_ip_addr())),
    ).unwrap();
    match cb.eval(Source::from_bytes(format!("{}\n{}\nFindProxyForURL({:?},{:?})", BUILTIN_JS,
                                             src, url.trim(), host.trim()).as_str())) {
        Ok(NativeJsValue::String(s)) => s.to_std_string_escaped(),
        Ok(t) => format!("!!Wrong type: {}", t.display().to_string()),
        Err(e) => format!("!!Uncaught {e}"),
    }
}

fn dns_resolve(host: &str) -> String {
    unsafe {
        let (ptr, len) = str_to_ptr(host);
        ret_to_str(_dns_resolve(ptr, len))
    }
}

fn my_ip_addr() -> String {
    unsafe { ret_to_str(_my_ip_addr()) }
}

#[link(wasm_import_module = "env")]
extern "C" {
    #[link_name = "dns_resolve"]
    fn _dns_resolve(ptr: u32, size: u32) -> u64;
    #[link_name = "my_ip_addr"]
    fn _my_ip_addr() -> u64;
}

// ---------------------------------------------------------------

#[cfg_attr(all(target_arch = "wasm32"), export_name = "eval_pac")]
#[no_mangle]
pub unsafe extern "C" fn _eval_pac(src_ptr: u32, src_len: u32,
                                   url_ptr: u32, url_len: u32,
                                   hst_ptr: u32, hst_len: u32) -> u64 {
    let s = eval_pac(&ptr_to_str(src_ptr, src_len),
                     &ptr_to_str(url_ptr, url_len),
                     &ptr_to_str(hst_ptr, hst_len));
    let (p, l) = str_to_ptr(&s);
    std::mem::forget(s);
    ((p as u64) << 32) | l as u64
}

#[cfg_attr(all(target_arch = "wasm32"), export_name = "reserve")]
#[no_mangle]
pub extern "C" fn _allocate(size: u32) -> *mut u8 {
    Box::into_raw(vec![0; size as usize].into_boxed_slice()) as *mut u8
}

#[cfg_attr(all(target_arch = "wasm32"), export_name = "release")]
#[no_mangle]
pub unsafe extern "C" fn _deallocate(ptr: u32, size: u32) {
    let _ = Vec::from_raw_parts(ptr as *mut u8, 0, size as usize);
}

const MASK_32: u64 = (1u64 << 32) - 1;

unsafe fn ret_to_str(v: u64) -> String {
    ptr_to_str(((v >> 32) & MASK_32) as u32, (v & MASK_32) as u32)
}

unsafe fn ptr_to_str(ptr: u32, len: u32) -> String {
    String::from(std::str::from_utf8_unchecked_mut(
        slice::from_raw_parts_mut(ptr as *mut u8, len as usize)))
}

unsafe fn str_to_ptr(s: &str) -> (u32, u32) {
    (s.as_ptr() as u32, s.len() as u32)
}
