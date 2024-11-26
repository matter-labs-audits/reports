# ZK Email: Unveiling Classic Attacks and Why Zero-Knowledge Proofs Alone Are Not a Panacea

The MatterLabs' red team was created to help foundational projects of the ZKsync ecosystem to be as secure as possible and to ensure that, in the end, user funds remain safe in every corner of ZKsync. During October, we did a security review of the Email Recovery Module of the joint ZK Email and Clave project. It was exciting to delve into the security assessment of the cutting-edge ZK Email project. In addition to publishing the full final [report](https://github.com/matter-labs-audits/reports/blob/main/reports/zkemail/ZKEmail%20Security%20Review%20Report.pdf), we wanted to share some of the most exciting findings with the ZKsync community.

Our researchers identified 17 unique security issues, with severities ranging from Critical to Low. This blog post focuses on three critical vulnerabilities that could enable attackers to take over smart wallets without user interaction. These vulnerabilities are associated with the following attack vectors:

- Discrepancies in email parsing between email servers and ZK Email
- Underconstrained circuits for ZK regular expressions
- [URL parameter injection](https://en.wikipedia.org/wiki/HTTP_parameter_pollution)

## Overview of ZK Email

The ZK Email technology allows one to initiate on-chain transactions via emails. It achieves this by relying on DKIM signatures and zero-knowledge proofs.

The Domain Keys Identified Mail (DKIM) signatures [standard](https://datatracker.ietf.org/doc/html/rfc6376) allows the sending email provider (akin Gmail) to incorporate the `dkim-signature` header with a digital signature, protecting the email’s headers and body from tampering and authenticating the sending email provider. At the time, most email providers supported DKIM, allowing anyone to check that a particular email was genuine and came from Alice to Bob, in case the email provider’s public key was considered trustworthy.

However, a few caveats prevent straightforward usage of email data and DKIM signatures on-chain. The main ones are that verifying DKIM in a smart contract is expensive and that an email might contain private data we aren’t keen to expose on-chain.  Zero-knowledge proofs are a pertinent solution for this scenario, where an off-chain prover can process an email and verify its DKIM signature, producing a succinct proof for the correctness of the signature verification routine to use on-chain.

According to the [ZK Email’s blog](https://prove.email/blog), it brings to the table a slew of prolific applications, including Email account recovery, Anonymous KYC, Identity Claims, Whistleblowing, and On-chain Legal Documents, to name a few. 

On the whole, the ZK Email system comprises five main components: 

- The **ZK regex compiler** generates a Cicrom circuit from a regular expression.
- **Circom circuits** are used to verify the email’s DKIM signature, process the email’s data, and extract public information while keeping the email content confidential to protect any private data it may contain.
- The **DKIM oracle** is responsible for fetching DKIM public keys for email providers and producing signed data to be submitted to the DKIM registry smart contract.
- **Solidity smart contracts** process ZK proofs alongside the email’s public data. The DKIM registry smart contract among them incorporates public key hashes for whitelisted email providers.
- The **Relayer** is responsible for coordinating off-chain components by receiving emails, producing ZK-proofs, and posting them on-chain. The protocol allows for the relayer to be self-hosted which has stronger privacy guarantees.

The email account recovery of ZK Email is being utilized by the Clave wallet and was a key focus during the security review. While social recovery is already possible, the number of users who can participate is limited to those who use blockchain. However, as mentioned in [Universal Recovery: A Social Recovery Solution Utilizes ZK-Email, integrating ZK Email](https://blog.getclave.io/p/universal-recovery-a-social-recovery) allows to expand the scope of social recovery to include email users who may or may not use blockchains, which is a much larger group of people.

The account recovery flow includes the following steps:

1. The account owner configures recovery and assigns one or more guardians with corresponding weights by calling `configureRecovery` of the `EmailRecoveryManager` smart contract.
2. The relayer then sends an email to each guardian with the acceptance command and the account code for the respective account owner. The guardian should respond to the email to confirm their participation in the recovery process. The acceptance command in the email is structured as follows: `Accept guardian request for ETH_ADDRESS`.
3. Subsequently, the relayer produces a ZK-proof for the `EmailAuth` circuit based on the guardian’s acceptance email and proceeds with calling `handleAcceptance` of the `EmailAccountRecovery` contract. The `EmailAuth` circuit is essential as it verifies the DKIM signature and extracts information from the email with the help of ZK regexes. This includes email nullifier, DKIM public key hash, email provider’s domain name, account salt, and masked ZK email command
4. At the time of recovery, guardians send emails with recovery commands to the relayer, which produces a ZK-proof for the `EmailAuth` circuit and submits it alongside the masked recovery command by calling `handleRecovery` of the `EmailAccountRecovery` contract. The recovery command in the email is structured as follows: `Recover account ETH_ADDRESS using recovery hash PUBKEY`.
5. Upon receiving sufficient votes from guardians, the recovery process concludes by calling `completeRecovery` of the `EmailRecoveryManager` contract.

For more details, we encourage readers to look into the [ZK Email blog](https://prove.email/blog/zkemail). Otherwise, let's dive straight into the juicy stuff without any delay.

## Parser discrepancies strike again

Knowing that parser discrepancies can lead to catastrophic consequences, as demonstrated in [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn), we were keen to apply similar techniques during our security research of ZK Email as the protocol relies on email parsing for its crucial steps. Failing to correctly parse an email can lead to a wide range of consequences, from authentication bypass to denial of service. However, what correct email parsing means is not an easy question to answer, as we will see.

One part where email parsing is involved is extracting the sender's email address from the `From` header of an email. To achieve this, the ZK Email project relies on regular expressions via the `FromAddrRegex` [circuit](https://github.com/zkemail/zk-regex/blob/531575345558ba938675d725bd54df45c866ef74/packages/circom/circuits/common/from_addr_regex.circom#L9). It supports two formats for the `From` header: a plain email address, handled in the `EmailAddrRegex` [circuit](https://github.com/zkemail/zk-regex/blob/531575345558ba938675d725bd54df45c866ef74/packages/circom/circuits/common/email_addr_regex.circom#L6), and an email address with a name, handled in the `EmailAddrWithNameRegex` [circuit](https://github.com/zkemail/zk-regex/blob/531575345558ba938675d725bd54df45c866ef74/packages/circom/circuits/common/email_addr_with_name_regex.circom#L6). Both circuits have two outputs: `out` and `reveal0`. The out output can be either `0` or `1`, indicating whether the `From` header contains a correct email address. The `reveal0` output contains the sender's email address.

Before diving into the issue, we would like to take a step back and discuss why ZK Email trusts the `From` header in the first place. The email protocols do not have authentication mechanisms by default. This is where DKIM comes into play. One of the guarantees a valid DKIM-signature gives is that the headers were validated by the sender’s email server (e.g., Outlook.com or Gmail.com). Since we trust the server and assume it was not compromised, we trust that the contents of the headers were set by the sender and sufficiently validated by the server.

In our case, all this means is trusting that the email address specified in the `From` header is indeed the sender. Thus, extraction of the sender from a DKIM-signed email is a crucial step, with the parser being a root of trust in ZK Email. If the attacker manages to persuade the verifier that the DKIM-signed email is from a different email address controlled by another user, it undermines the security of ZK Email.

We have identified that for at least two popular email services, `Outlook.com` and `Mail.ru`, it is possible to manipulate email addresses in the `From` header. This manipulation causes the `FromAddrRegex` circuit to output an email address that does not belong to the sender.

For example, through `Outlook.com` service, it's possible to send an email from attacker@outlook.com with the following `From` header:

```email
From: "Some name <victim@any-domain>" < attacker@outlook.com>
```

Note the space between `<` and the email address in `< attacker@outlook.com>`. While the actual sender is `attacker@outlook.com`, the `FromAddrRegex` circuit outputs `victim@any-domain`. The beauty of this bug is that `any-domain` can be literally any domain, not necessarily `outlook.com` that sent the message.
A fully functional malicious email can be crafted as follows:

```email
From: "John Doe <johndoe@gmail.com>" < attacker@outlook.com>
To: <relayer@gmail.com>
Subject: This is a test

hack?
```

It can be sent using the following command:

```shell
curl -vvv --ssl-reqd \
  --url 'smtp://smtp-mail.outlook.com:587' \
  --user 'attacker@outlook.com:{password}' \
  --mail-from 'attacker@outlook.com' \
  --mail-rcpt 'relayer@gmail.com' \
  --upload-file mail.txt
```

But how is it possible that `Outlook.com`, one of the leading email servers, lets this malicious email slip through its defenses? It turns out that the email is not inherently malicious. For example, both `Outlook.com` and `Gmail.com` servers parse this email as coming from the `attacker@outlook.com address`. So, as long as they agree on how to parse it, nothing bad happens. However, since the circuits parse the email as coming from `johndoe@gmail.com` the issue arises.

The ZK Email team mitigated the issue by changing how the email address is extracted. In particular, the circuit [reverses](https://github.com/zkemail/zk-regex/blob/7002a2179e076449b84e3e7e8ba94e88d0a2dc2f/packages/circom/circuits/common/email_addr_with_name_regex.circom#L13-L15) the `From` header, looks for the [first occurrence of angle brackets](https://github.com/zkemail/zk-regex/blob/7002a2179e076449b84e3e7e8ba94e88d0a2dc2f/packages/circom/circuits/common/reversed_bracket_regex.circom#L5), and extracts what is inside of them. Note, however, that the number of possible parser discrepancies is practically unlimited, especially given the variety of parsers and the fact that their code changes over time. Thus, it is crucial to have defense-in-depth strategies like timelocks for ZK Email actions.


## Enigmatic 255-decimal

The cornerstone part of the ZK Email system is the ZK regex compiler. It empowers a ZK circuit to support the processing of input signals with beloved and cherished regular expressions. The ZK regexes allow not only to constrain the input to satisfy the regex but additionally to produce a revealing array, exposing the part of the input matching specific sub-regexes.

Let’s look at the concrete example of a regex fed to the ZK regex compiler. This one comprises several sub-regexes and should match the whole `dkim-signature` header in an email but reveal only the timestamp value for the `;t=ts_value` tag in the header.

```json
{
  "parts": [
    {
      "is_public": false,
      "regex_def": "(\r\n|^)dkim-signature:"
    },
    {
      "is_public": false,
      "regex_def": "([a-z]+=[^;]+; )+t="
    },
    {
      "is_public": true,
      "regex_def": "[0-9]+"
    },
    {
      "is_public": false,
      "regex_def": ";"
    }
  ]
}
```

The ZK Email relies on regular expressions prefixed with `(\r\n|^)header_name:` for extracting various headers from an email, such as the `from`, `subject`, `dkim-signature` headers.

When we compile a regular expression with the compiler, it generates a Circom circuit that embodies a Deterministic Finite Automaton (DFA) satisfying the regular expression. Any regular expression can be converted into an equivalent DFA. An input string matches the regular expression if it transitions the DFA to the accept state.

Let’s have the `^a` regular expression as a toy example. When generating a circuit for [the regular expression](https://zkregex.com/min_dfa?regex=XmE=), the compiler makes a DFA with three states, with state `2` being the accepted state.

What’s more essential for understanding the vulnerability identified is that the compiler injects `255` decimal as the first value to the `in` array before the user’s input. This one is called an “invalid” decimal, as conceived by the ZK regex compiler’s code, and shouldn’t interfere with the user’s input, indicating the beginning of the string.

```circom
var num_bytes = msg_bytes+1;
signal in[num_bytes];
// -->
in[0]<==255;
// <--
for (var i = 0; i < msg_bytes; i++) {
	in[i+1] <== msg[i];
}
```

Further, in the main loop, the circuit handles the transition between states of the DFA based on the input `in[i]` and the current state. Initially, the DFA is in state `0` and transitions to state `1` when it receives the 255-decimal input, which denotes the beginning of the string or `^`.

```circom
for (var i = 0; i < num_bytes; i++) {
	state_changed[i] = MultiOR(2);
	eq[0][i] = IsEqual();
	// -->
	eq[0][i].in[0] <== in[i];
	eq[0][i].in[1] <== 255;
	// <--
	and[0][i] = AND();
	and[0][i].a <== states[i][0];
	and[0][i].b <== eq[0][i].out;
        // -->
	states[i+1][1] <== and[0][i].out;
        // <--
	state_changed[i].in[0] <== states[i+1][1];
	eq[1][i] = IsEqual();
	eq[1][i].in[0] <== in[i];
	eq[1][i].in[1] <== 97;
	and[1][i] = AND();
	and[1][i].a <== states[i][1];
	and[1][i].b <== eq[1][i].out;
	states[i+1][2] <== and[1][i].out;
	state_changed[i].in[1] <== states[i+1][2];
	states[i+1][0] <== 1 - state_changed[i].out;
}
```

If the subsequent input (the 1st character in the user’s input) isn’t a 97-decimal value (`a` character), it transitions back to state `0` from state `1`.

```circom
for (var i = 0; i < num_bytes; i++) {
	state_changed[i] = MultiOR(2);
	eq[0][i] = IsEqual();
	eq[0][i].in[0] <== in[i];
	eq[0][i].in[1] <== 255;
	and[0][i] = AND();
	and[0][i].a <== states[i][0];
	and[0][i].b <== eq[0][i].out;
	states[i+1][1] <== and[0][i].out;
	state_changed[i].in[0] <== states[i+1][1];
	eq[1][i] = IsEqual();
	// -->
	eq[1][i].in[0] <== in[i];
	eq[1][i].in[1] <== 97;
	// <--
	and[1][i] = AND();
	and[1][i].a <== states[i][1];
	and[1][i].b <== eq[1][i].out;
	states[i+1][2] <== and[1][i].out;
	state_changed[i].in[1] <== states[i+1][2];
	// -->
	states[i+1][0] <== 1 - state_changed[i].out;
 	// <--
}
```

Otherwise, having `a` character as an input, it transitions from state `1` to state `2`, acting as the accepted state.

This implies that one can bypass the regexp by feeding `[x, y, z, \xff, a]` as an input array. Initially, the DFA transitions from state `0` to state `1`  while processing the start of the string. Later, as the `x`, `y`, and `z` input characters are processed, the DFA remains in state `0` since the `x` character transitioned the DFA back to state `0` from state `1`. However, when it receives `\xff` character as the 4th character, the DFA transitions to state `1`, and the subsequent `a` character input entails the DFA’s transition to the accepted state.

For a further deep dive into the ZK regex compiler, we highly recommend the [ZK Regexp technical explainer](https://prove.email/blog/zkregex). Inquisitive readers can visit online [ZK Regex Tools](https://zkregex.com/) to build DFAs and state matrices or obtain Circom circuits for regexes of their choice.

Now, coming back to the vulnerability. We’ve discovered that most email providers blissfully send invalid UTF-8 characters in the subject header of an email, including the `\xff` character.

```email
subject: \xfffrom: victim@anydomain
```

With the following `curl` command line, we’ve managed to send a DKIM-signed email with the `\xff` character in the subject header through Gmail.

```shell
curl -vvv --ssl-reqd \
  --url 'smtp://smtp.gmail.com:587' \
  --user 'attacker@gmail.com:{password}' \
  --mail-from 'attacker@gmail.com' \
  --mail-rcpt 'relayer@domain'\
  --upload-file mail-255.txt
```

The `EmailAuth` circuit is in charge of verifying DKIM-signature of the email and extracting the sender’s email address by parsing the `from` header using the sub-circuits `FromAddrRegex`, `FromAllRegex`, and `EmailAddrRegex`. The `FromAllRegex` circuit matches the `from` header in the email by using the following regular expression:

```regexp
(\r\n|^)from:[^\r\n]+\r\n
```

Given that the attacker can inject `\xff` character followed by the victim’s email address, the `EmailAuth` circuit can be tricked into extracting `victim@anydomain` email address from the `subject` header, thinking it comes from the `from` header.

This ultimately results in an email spoofing attack, allowing the attacker to impersonate any email address by sending emails from `attacker@gmail.com` with the victim’s email address injected after the `\xff` character in the subject.

The ZK Email team mitigated the vulnerability by introducing a range check for the user’s input in this [commit](https://github.com/zkemail/zk-regex/commit/77541563c36075a0a5e817656d4613b5fb7ff548). Currently, all Circom circuits generated by the ZK regex compiler include the following constraints in the initialization part:

```circom
signal in_range_checks[msg_bytes];
in[0]<==255;
for (var i = 0; i < msg_bytes; i++) {
	in_range_checks[i] <== LessThan(8)([msg[i], 255]);
	in_range_checks[i] === 1;
	in[i+1] <== msg[i];
}
```

## Time-honored URL parameter injections

The ZK Email system takes advantage of an oracle deployed on the Internet Computer blockchain (ICP) to fetch DKIM public key from a TXT record through `dns.google/resolve` [service](https://dns.google/resolve) for an email provider’s domain.  Subsequently, it generates signed data that includes the DKIM public key and its Poseidon hash. Finally, anyone can submit the public key hash to the `UserOverrideableDKIMRegistry` contract on the EVM chain using signed data produced by the oracle.

The `UserOverrideableDKIMRegistry` contract maintains the mapping between a domain name and its DKIM public key hash.

On the ICP side, the `ic_dns_oracle_backend` canister (ICP smart contract) includes a publicly-exposed `sign_dkim_public_key` update method. Anyone can call the `sign_dkim_public_key`, which provides two input parameters: `selector` and `domain`. The `domain` parameter specifies the domain name for the email provider. Whereas the `selector` parameter signifies the prefix for the TXT record containing a DKIM public key for the domain. Ultimately, it combines `selector` and `domain` into one URL. For instance, if `domain=matterlabs.dev` and `selector=google`, the URL would be constructed as follows:

```
https://dns.google/resolve?name=google._domainkey.matterlabs.dev&type=TXT
```

Consequently, the ICP canister fetches the DKIM public key by sending an HTTP request to the URL, calculates a Poseidon hash of the public key, and then generates a response signed by the threshold signature.

The critical oversight lies in the code failing to restrict the value of the selector, exposing the possibility of injecting extra URL parameters through the `selector` input parameter.

Although it might look like a novel attack vector for the ZK Email system and web3 in general, injection vulnerabilities are the oldest trick in the book that has been haunting web2 systems for decades.

For instance, a malicious actor can use the following values when calling `sign_dkim_public_key`:
- `selector` is set to `google._domainkey.matterlabs.dev&name=xx`
- `domain` is set to `any.domain`

This results in the following URL:

```
https://dns.google/resolve?name=google._domainkey.matterlabs.dev&name=xx._domainkey.any.domain&type=TXT
```

The `dns.google` service uses the first parameter `name=google._domainkey.matterlabs.dev` but ignoring the second one. Ultimately, the `ic_dns_oracle_backend` canister is producing a signed response, falsely indicating that the domain `any.domain` has the DKIM public key managed by `matterlabs.dev`.

```
(variant {Ok=record {signature="0x292648253083ccaa095977b195e412d65ee68af949f9b44fed6e0e548403e6726f8ea7b85ad90b00abb3d41c03a409abec5b30db90534a89e7ab5bac9ae023f21c"; domain="any.domain"; public_key="0x8765da4200022daf7747d5fa4e0a62c58e54ad2ae8be4203d736424a4d2e26f7657feb4829b119a714bb56776f01b4e10fa54ba79e3d9d87f44a1db815c8ec1cabb0dde471afe363a1b9a06898284d23862eda51f799d6474a8a4b6d7a5c275eecddc94a1d9185371f8709deb48f52f319641e9728321222cfdd4216c53f0189bd8156a49e6dd44ec01a65be260fded98e8bff2726a407330d403961a80b6c572aeaa2c09a5463186549021bdcac3b9baed4aa7a364428cef63dc9519b404d2756e13152e6bcb1959d267e478d2212d7d6d30e0642307261b7d887065053164a8d7fcf36609be1208d175247a56480e0895c29cdacf2048f0e93f2fc7ee0f65b"; selector="google._domainkey.matterlabs.dev&name=xx"; public_key_hash="0x0fa8f9303b08e5751b274a16394c2b5908f8158e1d731935576438ae7a6f7e0f"}})
```

This attack portrays drastic outcomes as the attacker can spoof DKIM signatures for any email provider by placing malicious public key hashes into `UserOverrideableDKIMRegistry`, which undermines the ZK Email’s security.

The ZK Email team resolved the issue in this [commit](https://github.com/zkemail/ic-dns-oracle/commit/e40142a5526b49cfb8362a412964a0f77663ffb8) by strictly validating the `selector` and `domain` input parameters.

## Conclusion

This blog post covered three Critical severity issues identified during the security review. We encourage you to check out the full [report](https://github.com/matter-labs-audits/reports/blob/main/reports/zkemail/ZKEmail%20Security%20Review%20Report.pdf) for other High and Medium severity issues. In the report’s appendix, you may also find proof of concepts for the first and the second Critical severity issues.

One direction for further security research would be to apply techniques from the [Splitting the email atom: exploiting parsers to bypass access controls blog post](https://portswigger.net/research/splitting-the-email-atom) to the circuits produced by the ZK Email compiler.

To conclude, we thank the ZK Email team for their responsiveness and care about the codebase they demonstrated while resolving issues.
