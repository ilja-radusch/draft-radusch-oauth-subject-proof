---
title: "OAuth 2.0 Subject-Proof Callers for Token Introspection and Revocation"
abbrev: "OAuth Subject-Proof Callers"
category: std
docname: draft-radusch-oauth-subject-proof-02
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - OAuth
 - token introspection
 - token revocation
 - delegation
 - AI agents
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "ilja-radusch/draft-radusch-oauth-subject-proof"

author:
 -
    fullname: Ilja Radusch
    organization: Fraunhofer FOKUS
    email: ilja.radusch@fokus.fraunhofer.de

normative:
  RFC6749:
  RFC7009:
  RFC7662:
  RFC8414:
  RFC8693:
  RFC9068:

informative:
  ACTOR-PROFILE: I-D.mcguinness-oauth-actor-profile
  GLOBAL-REVOCATION: I-D.parecki-oauth-global-token-revocation
  REVOCATION-CLOSURE: I-D.watts-oauth-agent-revocation-closure
  RFC8936:
  GRANT-MANAGEMENT:
    title: "Grant Management for OAuth 2.0"
    author:
      - name: T. Lodderstedt
      - name: S. Low
      - name: D. Postnikov
    target: https://openid.net/specs/fapi-grant-management.html
    date: 2021
  CAEP:
    title: "OpenID Continuous Access Evaluation Profile 1.0"
    target: https://openid.net/specs/openid-caep-1_0.html
    date: 2025

--- abstract

OAuth 2.0 Token Introspection (RFC 7662) and Token Revocation (RFC 7009)
recognize two kinds of caller: the client a token was issued to, and
(for introspection) a protected resource the authorization server chooses
to trust. Neither covers a common case: a client that acts for the end user
and wants to see, or end, a grant that the same user gave to a different
client, for example a user disconnecting one AI agent from inside a web
application. This document defines a third kind of caller, the
subject-proof caller. The caller presents a token that the authorization
server issued to that same caller for the same end user. If the proof is
valid and names the same subject as the target grant, the authorization
server discloses the grant's delegation metadata at the introspection
endpoint, or revokes exactly that one grant at the revocation endpoint.

--- middle

# Introduction

A user often connects several clients to the same protected resource. In
agent deployments, a user signs in to a web application (client A) and also
authorizes one or more AI agents (clients B, C, ...) to call the same
resources on the user's behalf. The resulting access tokens carry an actor
claim ({{RFC8693}}, {{ACTOR-PROFILE}}) and are issued to the agents, not to
client A.

Users expect client A to show "your connected agents" and to offer a
"disconnect" button for each. That requires client A to:

1. read metadata about another client's grant for this user (who acts, the
   delegation correlation identifier, a user-chosen label), and
2. ask the authorization server (AS) to revoke that one grant.

Existing mechanisms do not allow this:

* {{RFC7662}} lets the AS vary its response by caller ({{Section 2.2 of
  RFC7662}}) but names no caller of the form "acts for the token's subject"
  and defines no way to prove it. Deployments either answer only the
  token's own client, or trust every registered protected resource for all
  users. The second option discloses every user's grants to the resource.
* {{RFC7009}} lets only the client the token was issued to revoke it.
* Grant Management {{GRANT-MANAGEMENT}} lets only the client that owns a
  grant query or delete it.
* Global Token Revocation {{GLOBAL-REVOCATION}} is a privileged action that
  revokes all of a subject's tokens. It is too broad for "disconnect this
  one agent", and it authorizes the caller as an administrator, not as a
  party acting for the user.

This document defines the subject-proof caller. The caller proves that it
acts for the end user by presenting a token that the AS issued to the
caller for that user. The AS then treats the caller as entitled to the
user's own grants, and only to those.

The mechanism is not specific to AI agents. It applies to any case where
one client manages, for the user, grants that the user gave to other
clients (connected apps, devices, integrations).

## Requirements Language

{::boilerplate bcp14-tagged}

## Terminology

This document uses the terms "access token", "authorization server",
"client", "protected resource" and "resource owner" defined by
{{RFC6749}}, and "actor" as defined by {{RFC8693}}.

Subject-proof caller:
: An authenticated client that presents a subject proof token.

Subject proof token:
: An access token issued by this AS to the subject-proof caller, used as
  evidence that the caller currently acts for the end user named in it.

Target token:
: The token being introspected.

Grant:
: The set of access and refresh tokens that descend from one authorization
  decision by the end user, including tokens obtained through refresh.

# Subject Proof Verification {#verification}

A subject proof token is presented in the `subject_proof_token` request
parameter. The AS MUST verify it as follows and MUST treat a failure of any
step as "no proof":

1. The caller MUST have authenticated to the endpoint with client
   credentials ({{Section 2.3 of RFC6749}}). See {{public-clients}}.
2. The subject proof token MUST be an access token that this AS issued
   and that is valid: for a JWT access token {{RFC9068}}, a valid signature,
   `iss` equal to this AS's issuer identifier and an `exp` in the future.
3. The subject proof token MUST have been issued to the authenticated
   caller: its `client_id` MUST equal the caller's client identifier.
4. The subject proof token MUST NOT be revoked or replaced. The AS MUST
   check its own token state, not only the signature, because a JWT
   remains cryptographically valid after revocation.
5. The subject proof token MUST identify a subject. The proven subject is
   that subject, as the AS identifies the end user internally.
6. The subject proof token MUST NOT be a delegated token: it MUST NOT
   carry an `act` claim ({{Section 4.1 of RFC8693}}), and the AS MUST NOT
   have issued it under a grant that delegates the user's authority to
   an actor. See {{delegated-proofs}}.

Step 3 is essential. Without it, any party that obtains a user's access
token for some other client could use it as a proof.

When an AS issues different `sub` values for the same end user to
different clients or resources (pairwise or resource-specific
identifiers), the AS MUST compare subjects using its internal user
identifier, not the `sub` strings as issued.

# Introspection {#introspection}

## Request

A subject-proof caller adds the `subject_proof_token` parameter to an
introspection request ({{Section 2.1 of RFC7662}}):

~~~ http-message
POST /introspect HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50LWE6c2VjcmV0

token=eyJhbGciOiJFUzI1NiIs...agent-token
&subject_proof_token=eyJhbGciOiJFUzI1NiIs...client-a-token
~~~

## Processing

The AS processes the request as defined in {{RFC7662}}. In addition, if
the proof verifies ({{verification}}) and the proven subject is the same
end user as the subject of the target token, the AS MUST treat the caller
as entitled to the full introspection response for the target token,
including delegation metadata such as `act` {{RFC8693}} and any
correlation identifiers or user-authored labels the AS holds for the
grant.

If the proof is absent, fails verification, or names a different subject,
the AS MUST respond exactly as it would have without the parameter. It
MUST NOT return an error that reveals whether the proof was valid or
whether the subjects matched.

A valid subject proof entitles the caller only to read. The AS MUST NOT
use it as an input to any authorization decision about the target token
itself, such as its scope or whether it is active.

# Revocation {#revocation}

## Request

A subject-proof caller sends a revocation request ({{Section 2.1 of
RFC7009}}) with the `subject_proof_token` parameter and exactly one grant
selector:

`dlg_id`:
: The delegation correlation identifier of the grant, as issued in the
  grant's tokens and returned by introspection. This is the preferred
  selector.

`act_sub`:
: The `sub` of the actor ({{RFC8693}} `act` claim) of the grant. Selects
  every grant of that actor for the proven subject. Use only when the grant
  has no `dlg_id`.

The `token` parameter, REQUIRED by {{RFC7009}}, is not used in a
subject-proof revocation request. An AS that supports this specification
MUST NOT reject such a request for lacking `token`.

~~~ http-message
POST /revoke HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50LWE6c2VjcmV0

subject_proof_token=eyJhbGciOiJFUzI1NiIs...client-a-token
&dlg_id=Jx4sP0b5mQ9mZ0WbJm2T2w7m8V3X1R6Yk0fQe2H9a1c
~~~

If `subject_proof_token` is absent, the request is an ordinary
{{RFC7009}} request.

## Processing

The AS MUST:

1. Verify the proof ({{verification}}).
2. Select the grants owned by the proven subject that match the selector.
   Ownership MUST come from the AS's own records, never from the request.
   A selector that matches no grant of the proven subject selects nothing.
3. Revoke every access and refresh token of each selected grant, as
   {{Section 2.1 of RFC7009}} describes for refresh tokens.
4. Leave all other grants of the subject untouched, including the grant
   the subject proof token belongs to.

The AS MUST respond with HTTP status 200 in every case: an invalid proof,
an unknown selector, a selector owned by another user, or a successful
revocation. This keeps the endpoint from revealing which grants exist.

An AS that publishes security events SHOULD emit a session-revoked event
{{CAEP}} for each revoked grant, so that other receivers stop accepting its
tokens before they expire.

## Effect of Revocation {#revocation-effect}

Revocation takes effect at the AS before the AS sends the response. From
that point the AS:

* MUST NOT issue a new access or refresh token for a selected grant,
  including through a refresh request that was in progress when the
  revocation was processed;
* MUST return `"active": false` when a token of a selected grant is
  introspected ({{RFC7662}}).

A protected resource that validates self-contained access tokens
({{RFC9068}}) locally can still accept a token of a revoked grant until
the token expires, until the resource introspects it, or until it
processes the session-revoked event. Short access token lifetimes limit
this window.

The session-revoked event notifies receivers that the grant was revoked.
It is not a receipt that every effect of the grant has stopped. This
document adds no delivery or ordering guarantee beyond those of the
delivery method in use, for example the at-least-once delivery of
{{RFC8936}}. A receiver MUST NOT infer, from the event or from its
absence, that no operation admitted under the grant can still complete.

Operations that a protected resource or the agent admitted or queued
before the revocation, and credentials derived from the grant's tokens
(for example through token exchange {{RFC8693}}), are out of scope.
Closing them is a matter for the party that holds them;
{{REVOCATION-CLOSURE}} describes one model for proving such closure.

# Authorization Server Metadata {#metadata}

This document defines the following AS metadata parameters {{RFC8414}}:

`introspection_subject_proof_token_supported`:
: OPTIONAL. Boolean. `true` if the introspection endpoint processes the
  `subject_proof_token` parameter as defined in {{introspection}}. If
  omitted, the default is `false`.

`revocation_subject_proof_token_supported`:
: OPTIONAL. Boolean. `true` if the revocation endpoint processes the
  `subject_proof_token` parameter as defined in {{revocation}}. If
  omitted, the default is `false`.

# Security Considerations

## Public Clients {#public-clients}

A public client authenticates by its client identifier alone. For a
public client X, any leaked access token issued to X is also a valid
subject proof for X. The AS therefore MUST NOT accept a subject proof from
a caller that did not authenticate with a credential, unless a deployment
explicitly opts in for a specific client and accepts that risk.

## What the Proof Shows

A valid proof shows that the caller currently holds a live token for the
end user. It does not show that the end user approved the specific
disclosure or revocation. The caller MUST perform these requests only on
the end user's instruction, for example after the user selects
"disconnect" in the caller's interface. Revocation through this mechanism
can only remove access, never add it.

## Scope of Disclosure

A subject-proof caller can read the delegation metadata of every grant of
the end user whose tokens it can obtain. Deployments SHOULD limit the
metadata they return to what a user interface for managing connections
needs.

## Proof Token Exposure

The subject proof token is sent only to the AS that issued it, over TLS.
The AS MUST NOT log its value. A sender-constrained subject proof token
(DPoP or mutual TLS) does not need to be presented with a proof of
possession at this endpoint, because the caller already authenticated as
the client the token was issued to.

## Delegated Tokens Are Not Proofs {#delegated-proofs}

A subject proof stands for the end user acting through the caller. A
token that an AS issued to an actor, such as an AI agent, under a
delegated grant does not: the actor uses it without step-by-step
instruction from the user. If such a token were accepted, one delegated
actor could read the delegation metadata of the user's other grants, or
revoke the grants of other actors, using authority the user gave it for
a different purpose. Step 6 of {{verification}} therefore rejects
delegated tokens, whether the delegation is visible in the token (an
`act` claim) or only in the AS's records.

## Correlation Identifiers Are Selectors, Not Authorization

`dlg_id` and `act_sub` only select which of the proven subject's grants to
revoke. Whether the caller may revoke is decided only by the proof. A
guessed or foreign selector selects nothing.

# Privacy Considerations

The mechanism gives one client of the end user knowledge of the user's
other clients and grants. This is the purpose of the mechanism, but an AS
SHOULD offer it only to clients that the deployment trusts to present
connection management to the user, for example through client
registration policy.

# Implementation Status

{::boilerplate rfc7942}

* Organization: Fraunhofer FOKUS.
* Implementation: an OAuth 2.1 / OpenID Connect authorization server
  (TypeScript, private repository), deployed in production for a document
  signing application with AI agent access over MCP.
* Coverage: introspection ({{introspection}}) and revocation
  ({{revocation}}) as described, including the public-client rule, the
  internal-subject comparison and session-revoked events. Both are behind
  configuration flags that are off by default. Both metadata parameters
  ({{metadata}}) are published when the matching feature is enabled.
  Session-revoked events are delivered by poll ({{RFC8936}}). Delegated
  tokens are rejected as proofs ({{delegated-proofs}}). The rule in
  {{revocation-effect}} for a refresh request in progress during the
  revocation is being implemented.
* Level of maturity: production.
* Contact: Ilja Radusch.

# IANA Considerations

## OAuth Parameters Registration

IANA is requested to add the following entries to the "OAuth Parameters"
registry:

| Parameter Name | Parameter Usage Location | Change Controller | Reference |
|---|---|---|---|
| `subject_proof_token` | token introspection request, token revocation request | IETF | {{verification}} of this document |
| `dlg_id` | token revocation request | IETF | {{revocation}} of this document |
| `act_sub` | token revocation request | IETF | {{revocation}} of this document |

## OAuth Authorization Server Metadata Registration

IANA is requested to add the following entries to the "OAuth
Authorization Server Metadata" registry:

* Metadata Name: `introspection_subject_proof_token_supported`
* Metadata Description: Whether the introspection endpoint supports
  subject-proof callers
* Change Controller: IETF
* Specification Document(s): {{metadata}} of this document

* Metadata Name: `revocation_subject_proof_token_supported`
* Metadata Description: Whether the revocation endpoint supports
  subject-proof callers
* Change Controller: IETF
* Specification Document(s): {{metadata}} of this document

--- back

# Open Issues
{:numbered="false"}

* RFC 8693 already defines `subject_token` and `subject_token_type`.
  Should this document reuse that pair? A separate name is used here
  because the proof is restricted to an access token that this AS issued
  to the caller, while an RFC 8693 subject token may be any token type,
  including one from another issuer.
* `dlg_id` is being defined in {{ACTOR-PROFILE}}. If it is not adopted
  there, this document needs another way to name one grant, for example a
  token of the grant in the `token` parameter.
* Should the revocation endpoint return a distinct error for a caller that
  is not allowed to use subject proofs at all, as opposed to an invalid
  proof?

# Acknowledgments
{:numbered="false"}

The problem was first raised on the issue tracker of
{{ACTOR-PROFILE}}, as part of the discussion of where user-authored
metadata about a delegated connection should live.
