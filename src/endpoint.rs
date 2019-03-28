use ffi;

#[derive(Copy, Clone)]
pub struct Endpoint {
    c_endpoint: ffi::mam_endpoint_t,
}