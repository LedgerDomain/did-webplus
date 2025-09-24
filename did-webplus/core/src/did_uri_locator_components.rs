use crate::Error;

/// Contains everything after "did:webplus:" and before the first root-self-hash.  This will
/// end with a '/' char.
///
/// E.g. if the string is "did:webplus:example.com:9999/abc/xyz/<root-self-hash>" then locator will
/// be "example.com:9999/abc/xyz/" with hostname "example.com", port_o Some(9999), and path "/abc/xyz/".
#[derive(Debug)]
pub struct DIDURILocatorComponents<'a> {
    /// The hostname of the VDR that acts as the authority/origin for this DID, not including the port number,
    /// e.g. "example.com" for host "example.com:9999".
    pub hostname: &'a str,
    /// Optional port number of the VDR that acts as the authority/origin for this DID, e.g. 9999 for host
    /// "example.com:9999".
    pub port_o: Option<u16>,
    /// Path after the hostname+port and before the root self-hash, including the leading and/or trailing '/' chars.
    /// This can be "/" if there are no path components besides the root self-hash.
    pub path: &'a str,
}

impl<'a> std::fmt::Display for DIDURILocatorComponents<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hostname)?;
        if let Some(port) = self.port_o {
            write!(f, ":{}", port)?;
        }
        write!(f, "{}", self.path)?;
        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for DIDURILocatorComponents<'a> {
    type Error = Error;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if !s.is_ascii() {
            return Err(Error::Malformed("did:webplus URI locator (everything after 'did:webplus:' and before the root-self-hash) must be ASCII"));
        }
        if !s.ends_with('/') {
            return Err(Error::Malformed("did:webplus URI locator (everything after 'did:webplus:' and before the root-self-hash) must end with '/'"));
        }
        // Find the first '/' char, as that begins the path component.
        let first_slash_idx = s.find('/').unwrap();
        let host = &s[..first_slash_idx];
        let path = &s[first_slash_idx..];
        // Split the host into hostname and port
        let (hostname, port_o) = if let Some((hostname, port_str)) = host.split_once(':') {
            // host includes a port number.
            let port: u16 = port_str
                .parse()
                .map_err(|_| Error::Malformed("did:webplus URI port must be a valid integer"))?;
            (hostname, Some(port))
        } else {
            // host does not include a port number, and is hostname only.
            let hostname = host;
            (hostname, None)
        };
        Ok(Self {
            hostname,
            port_o,
            path,
        })
    }
}
