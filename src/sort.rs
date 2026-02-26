//! This module implements the Server Side Sort control in `ldap3`'s `Adapter` framework.

// This is all heavily inspired by the `PagedResults` implementation.

pub(crate) mod adapter;

// Control is the low level component of the implementation.
mod control;

const SERVER_SIDE_SORT_REQUEST_OID: &str = "1.2.840.113556.1.4.473";
const SERVER_SIDE_SORT_RESPONSE_OID: &str = "1.2.840.113556.1.4.474";
