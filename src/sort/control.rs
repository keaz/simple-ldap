//! The low level control implementation of Server Side Sort (SSS)
//!

use bytes::BytesMut;
use derive_more::TryFrom;
use itertools::Itertools;
use ldap3::{
    asn1::{
        ASNTag, Boolean, OctetString, Sequence, Tag, TagClass, Types, parse_tag, parse_uint, write,
    },
    controls::{ControlParser, MakeCritical, RawControl},
};

use crate::sort::{SERVER_SIDE_SORT_REQUEST_OID, adapter::SortBy};

/// Request control for SSS.
pub(crate) struct ServerSideSortRequest {
    pub sort_key_list: Vec<SortKey>,
}

/// May be critical.
///
/// RFC 2891 1.1
impl MakeCritical for ServerSideSortRequest {}

impl From<ServerSideSortRequest> for RawControl {
    fn from(value: ServerSideSortRequest) -> Self {
        let tagged = Tag::Sequence(Sequence {
            // Just converting the vec elements to tags.
            inner: value.sort_key_list.into_iter().map_into().collect(),
            ..Default::default()
        })
        .into_structure();

        // We could try to guess the required capacity.
        let mut buffer = BytesMut::new();
        write::encode_into(&mut buffer, tagged).expect("Encoding should pass");

        RawControl {
            ctype: SERVER_SIDE_SORT_REQUEST_OID.to_owned(),
            crit: false,
            val: Some(buffer.into()),
        }
    }
}

/// An individual sort key, i.e. a piece of the control specifying one sort criterion.
#[derive(Debug)]
pub(crate) struct SortKey {
    /// Name of the attribute to sort by.
    pub attribute_type: String,
    /// A `MatchingRuleId`, as defined in section 4.1.9 of LDAPv3 spec (or so I hear)
    pub ordering_rule: Option<String>,
    /// Should the ordering be reversed?
    pub reverse_order: bool,
}

impl From<SortBy> for SortKey {
    fn from(value: SortBy) -> Self {
        SortKey {
            attribute_type: value.attribute,
            ordering_rule: None,
            reverse_order: value.reverse,
        }
    }
}

// Implicit tags
const ORDERING_RULE_TAG: u64 = 0;
const REVERSE_ORDER_TAG: u64 = 1;

/// It will be a sequence.
impl From<SortKey> for Tag {
    fn from(value: SortKey) -> Self {
        let iterator = [
            // AttributeDescription
            Some(Tag::OctetString(OctetString {
                inner: value.attribute_type.into(),
                ..Default::default()
            })),
            value.ordering_rule.map(|rule| {
                Tag::OctetString(OctetString {
                    id: ORDERING_RULE_TAG,
                    class: TagClass::Context,
                    inner: rule.into(),
                })
            }),
            Some(Tag::Boolean(Boolean {
                id: REVERSE_ORDER_TAG,
                class: TagClass::Context,
                inner: value.reverse_order,
            })),
        ]
        .into_iter()
        .flatten(); // The Options

        Tag::Sequence(Sequence {
            inner: iterator.collect(),
            ..Sequence::default()
        })
    }
}

/*******************************
 *  Then the response control  *
 *******************************/

/// Request control for SSS.
#[derive(Debug)]
pub(crate) struct ServerSideSortResponse {
    pub sort_result: SortResult,

    /// This may contain the name of a troublesome attribute if the sort fails.
    ///
    /// RFC 2891 2:
    ///
    /// > Optionally, the server MAY set the attributeType to the first attribute
    /// > type specified in the SortKeyList that was in error. The client SHOULD
    /// > ignore the attributeType field if the sortResult is success.
    ///
    /// [0] AttributeDescription OPTIONAL
    #[expect(
        dead_code,
        reason = "It's here per the spec. May have some uses in error cases."
    )]
    pub attribute_type: Option<String>,
}

/// Potential results to SSS.
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFrom)]
#[try_from(repr)]
// Unnecessary big size but it matches what the parser spits out.
#[repr(u64)]
pub(crate) enum SortResult {
    /// Results are sorted
    Success = 0,
    /// Server internal failure
    OperationsError = 1,
    /// Timelimit reached before sorting was completed
    TimeLimitExceeded = 3,
    /// Refused to return sorted results via insecure protocol
    StrongAuthRequired = 8,
    /// Too many matching entries for the server to sort
    AdminLimitExceeded = 11,
    /// Unrecognized attribute type in sort key
    NoSuchAttribute = 16,
    /// Unrecognized or inappropriate matching rule in sort key
    InappropriateMatching = 18,
    /// Refused to return sorted results to this client
    InsufficientAccessRights = 50,
    /// Too busy to process
    Busy = 51,
    /// Unable to sort
    UnwillingToPerform = 53,
    Other = 80,
}

const ATTRIBUTE_TYPE_TAG: u64 = 0;

impl ControlParser for ServerSideSortResponse {
    fn parse(val: &[u8]) -> Self {
        let mut sequence_components = match parse_tag(val) {
            Ok((_, tag)) => tag,
            _ => panic!("failed to parse server side sort response control components"),
        }
        .expect_constructed()
        .expect("server side sort results components")
        .into_iter();

        let raw_sort_result = sequence_components
            .next()
            .expect("server side sort element 1")
            .match_class(TagClass::Universal)
            .and_then(|tag| tag.match_id(Types::Enumerated as u64))
            .and_then(|tag| tag.expect_primitive())
            .expect("sortResult");

        let (_, numeric_sort_result) =
            parse_uint(raw_sort_result.as_slice()).expect("should have been a sort result");

        let sort_result = SortResult::try_from(numeric_sort_result)
            .expect("should have been a valid sort result code");

        // The RFC tells us to ignore the other field if the result is a success.
        if sort_result == SortResult::Success {
            ServerSideSortResponse {
                sort_result,
                attribute_type: None,
            }
        } else {
            // This is an optional field even in the case of error result.
            let attribute_type = sequence_components
                .next()
                .and_then(|tag| tag.match_class(TagClass::Context))
                .and_then(|tag| tag.match_id(ATTRIBUTE_TYPE_TAG))
                .and_then(|tag| tag.expect_primitive())
                // I think it should be a string.
                .map(String::from_utf8)
                .transpose()
                .expect("should be an AttributeType Description");

            ServerSideSortResponse {
                sort_result,
                attribute_type,
            }
        }
    }
}
