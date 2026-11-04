# Experimental scan-group reverse proxy

`nginx.conf` is the proxy configuration used by the isolated review stack.
It serves a branch-built GSA bundle, checks the existing GSAD session with
an internal `/gmp?cmd=ping` auth request, then forwards `/credential-api/`
to the companion controller from the matching gvmd branch. `config.js`
enables the integrated GSA task UI.

The config is for the local TLS review stack and its `localhost` hostname.
The controller port must remain reachable only from this proxy. GSAD itself
continues to serve its normal GMP API. The standalone C wire proposal files
remain for a future native GMP implementation; the current running review
path uses this authenticated proxy.
