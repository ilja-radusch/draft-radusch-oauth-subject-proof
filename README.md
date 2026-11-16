# OAuth 2.0 Subject-Proof Callers for Token Introspection and Revocation

Source for `draft-radusch-oauth-subject-proof`, an individual Internet-Draft.

Discussion: the OAuth WG mailing list (oauth@ietf.org) or issues in this repository.

## Build

```bash
gem install kramdown-rfc
pipx install xml2rfc
kramdown-rfc draft-radusch-oauth-subject-proof.md > draft-radusch-oauth-subject-proof-02.xml
xml2rfc --text --html draft-radusch-oauth-subject-proof-02.xml
```
