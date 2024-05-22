use crate::Error;

#[derive(Debug)]
pub struct DIDURIComponents<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub query_o: Option<&'a str>,
    pub fragment_o: Option<&'a str>,
}

impl<'a> TryFrom<&'a str> for DIDURIComponents<'a> {
    type Error = Error;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if !s.starts_with("did:") {
            return Err(Error::Malformed("DID URI is expected to start with 'did:'"));
        }
        // Get rid of the "did:" prefix.
        let s = s.split_once(':').unwrap().1;
        let (method, post_method_str) = s.split_once(':').unwrap();
        // TODO: Validation on the method string.

        let (host, post_host_str) = post_method_str.split_once(':').unwrap();
        // TODO: Validation on host

        let (path, query_o, fragment_o) =
            if let Some((path, query_and_maybe_fragment)) = post_host_str.split_once('?') {
                if let Some((query, fragment)) = query_and_maybe_fragment.split_once('#') {
                    (path, Some(query), Some(fragment))
                } else {
                    (path, Some(query_and_maybe_fragment), None)
                }
            } else {
                if let Some((path, fragment)) = post_host_str.split_once('#') {
                    (path, None, Some(fragment))
                } else {
                    (post_host_str, None, None)
                }
            };
        // TODO: Validation on path, query_o, and fragment_o

        Ok(Self {
            method,
            host,
            path,
            query_o,
            fragment_o,
        })
    }
}
