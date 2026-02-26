//! This module implements Server Side Sort (SSS) search extension
//! as described in [RFC 2891](datatracker.ietf.org/doc/rfc2891/).

use async_trait::async_trait;
use itertools::Itertools;
use ldap3::{
    LdapError, LdapResult, ResultEntry, Scope, SearchStream,
    adapters::{Adapter, SoloMarker},
    controls::{Control, MakeCritical, RawControl},
};
use std::{fmt::Debug, mem};
use thiserror::Error;
use tracing::debug;

use crate::sort::{
    SERVER_SIDE_SORT_REQUEST_OID, SERVER_SIDE_SORT_RESPONSE_OID,
    control::{self, ServerSideSortResponse, SortResult},
};

/// Search adapter for sorting the results serverside.
#[derive(Debug, Clone)]
pub(crate) struct ServerSideSort {
    /// The server evaluates these sort criteria in order.
    /// If there's a tie, the next criteria will be consulted.
    ///
    ///
    /// Invariant: This vec doesn't contain elements with the same `attribute` field.
    //
    //  (It shouldn't be empty either but that's not enforced at this level.)
    sorts: Vec<SortBy>,
}

#[derive(Debug, Error)]
#[error("Attributes {} occur more than once in the sort list.",
    attributes.iter().format(", ")
)]
pub struct DuplicateSortAttributes {
    attributes: Vec<String>,
}

impl ServerSideSort {
    /// Create new adapter instance.
    ///
    /// Duplicate attributes aren't allowed.
    ///
    /// Servers are allowed to limit the amount of attributes to sort by.
    /// In this case the search should just err.
    pub fn new(sorts: Vec<SortBy>) -> Result<Self, DuplicateSortAttributes> {
        // First validate the inputs.
        let duplicates = sorts
            .iter()
            .map(|SortBy { attribute, .. }| attribute)
            .duplicates()
            .collect_vec();

        if !duplicates.is_empty() {
            let attributes = duplicates.into_iter().map(ToOwned::to_owned).collect();
            Err(DuplicateSortAttributes { attributes })
        }
        // Everything is good in this branch.
        else {
            Ok(ServerSideSort { sorts })
        }
    }
}

/// A sort directive
///
// Not exposing the `orderingRule` as I don't know how it's supposed to work.
#[derive(Debug, Clone)]
pub struct SortBy {
    /// Name of the attribute to sort by.
    pub attribute: String,
    /// Should the ordering be reversed?
    pub reverse: bool,
}

/// Can be used by itself.
impl SoloMarker for ServerSideSort {}

#[async_trait]
impl<'a, S, A> Adapter<'a, S, A> for ServerSideSort
where
    S: AsRef<str> + Clone + Debug + Send + Sync + 'a,
    A: AsRef<[S]> + Clone + Debug + Send + Sync + 'a,
{
    async fn start(
        &mut self,
        stream: &mut SearchStream<'a, S, A>,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: A,
    ) -> ldap3::result::Result<()> {
        let stream_ldap = stream.ldap_handle();

        // Check that SSS isn't defined already.
        let sort_control_already_defined = stream_ldap.controls.as_ref().is_some_and(|vec| {
            vec.iter()
                .any(|control| control.ctype == SERVER_SIDE_SORT_REQUEST_OID)
        });
        if sort_control_already_defined {
            return Err(LdapError::AdapterInit(String::from(
                "found Server Side Sort control in op set already",
            )));
        }

        // No need to keep these around in the adapter.
        let sorts = mem::take(&mut self.sorts);
        let new_control = control::ServerSideSortRequest {
            // Convert the sort args to control parts.
            sort_key_list: sorts.into_iter().map_into().collect(),
        } // We want the search to fail if sorting isn't supported.
        .critical();

        // Adding the control to the search.
        stream_ldap
            .controls
            .get_or_insert_default()
            .push(new_control.into());

        // Continue the chain.
        stream.start(base, scope, filter, attrs).await
    }

    async fn next(
        &mut self,
        stream: &mut SearchStream<'a, S, A>,
    ) -> ldap3::result::Result<Option<ResultEntry>> {
        match stream.next().await? {
            Some(result_entry) => {
                // It's a little unclear to me whether I should be looking at this res in `stream`
                // or the result_entry directly? Are the controls just the same?
                let sss_control = stream.res.as_ref().and_then(
                    |LdapResult {
                         ctrls: controls, ..
                     }| get_response_control(controls.as_slice()),
                );

                match sss_control {
                    Some(ServerSideSortResponse {
                        sort_result: SortResult::Success,
                        ..
                    }) => {
                        // All good, passing on the result.
                        Ok(Some(result_entry))
                    }
                    Some(ServerSideSortResponse { sort_result, .. }) => {
                        panic!(
                            "Server side sort result was {sort_result:?}. This should never be the case in this branch as the control was set to critical and so should have caused an error earlier."
                        )
                    }
                    None => {
                        debug!("No server side sort response control.");
                        Ok(Some(result_entry))
                    }
                }
            }
            // I suppose we could check for the control here too, but my understanding is that it's only
            // used when there are actually results.
            None => Ok(None),
        }
    }

    async fn finish(&mut self, stream: &mut SearchStream<'a, S, A>) -> LdapResult {
        // Just logging here

        let result = stream.finish().await;

        let sss_control = get_response_control(result.ctrls.as_slice());

        match sss_control {
            None => debug!("No Server Side Sort control in the final result"),
            Some(control) => debug!("The final Server Side Sort control: {control:?}"),
        };

        result
    }
}

// Get and parse the SSS response control if there is one.
//
// My understanding from RFC 2981 section 2 is that whenever there is at least one search result,
// there should also be the SSS response control.
fn get_response_control(controls: &[Control]) -> Option<ServerSideSortResponse> {
    controls
        .iter()
        // Control type isn't parsed since this control is implemented outside ldap3
        // so we're just working with the raw values.
        .map(|Control(_, raw)| raw)
        .find(|raw| raw.ctype == SERVER_SIDE_SORT_RESPONSE_OID)
        .map(RawControl::parse)
}
