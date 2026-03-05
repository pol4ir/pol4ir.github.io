---
title: "NTLM reflection"
date: 2026-02-21 10:00:00 +0000
categories: [CVEs]
tags: [lateral movement, rce, smb, winrm, ldap, esc8, cve, ntlm reflection, local ntlm authentication, ntlm relay,ntlmrelayx, UBR, remote registry, MIC, coercion, CVE-2025-33073, CVE-2025-58726, CVE-2025-54918, GhostSPN, NTLM MIC bypass ,NTLMSSP, signing, channel binding token CBT, EPA, DRSUAPI, DCSync, Impacket, privilege escalation, red team , penetration testing]
image: /assets/posts/2026-02-21-NTLM reflection recon/chart2.png

---

It has been roughly eight months since Synacktiv published their blog post on <a href="https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025">NTLM reflection</a>, yet this technique remains a consistent finding in my assessments. Since then, additional CVEs related to NTLM reflection have surfaced, and some confusion still exists around the conditions under which they are exploitable, particularly regarding signing, CBT, and similar mitigations. This makes it all the more important to understand how to correctly identify and classify each of them, especially from an attacker's perspective. Before diving into that, a solid foundation is necessary, starting with a clear explanation of what NTLM reflection is and what actually happens under the hood.

<h2 id="lntlmauth">Local NTLM authentication</h2>

Publicly available information on this mechanism, and on the Reserved field in particular, is scarce. At the time of writing, Microsoft has yet to officially document this field in the <code class="language-plaintext highlighter-rouge">MS-NLMP</code> specification, which makes understanding its behavior and purpose considerably more challenging.

<a href="/assets/posts/2026-02-21-NTLM reflection recon/reserved.png" class="popup img-link"><img src="/assets/posts/2026-02-21-NTLM reflection recon/reserved.png"  loading="lazy" alt="null"></a>
<em>Reserved field</em>

Local NTLM authentication is a mechanism designed specifically for scenarios where client and server reside on the same machine. For an in-depth analysis, Synacktiv's blog post covers it thoroughly; what follows here is a concise overview of how it works.

1) The client generates the  <code class="language-plaintext highlighter-rouge">NTLM_NEGOTIATE</code> message, providing the workstation name and domain name, and sets the flags  <code class="language-plaintext highlighter-rouge">NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED (0x00002000)</code> and  <code class="language-plaintext highlighter-rouge">NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED (0x00001000)</code>.
<a href="/assets/posts/2026-02-21-NTLM reflection recon/negotiate.png" class="popup img-link"><img src="/assets/posts/2026-02-21-NTLM reflection recon/negotiate.png" loading="lazy" alt="null"></a>
<em>NTLM_NEGOTIATE message</em>

2) When preparing the  <code class="language-plaintext highlighter-rouge">NTLM_CHALLENGE</code> message, the server checks whether the workstation and domain names supplied by the client match the local machine’s name and domain. If they do, the server sets the  <code class="language-plaintext highlighter-rouge">NTLMSSP_RESERVED_6 flag (0x00004000)</code>, creates a server context, and stores its ID in the  <code class="language-plaintext highlighter-rouge">Reserved</code> field.
<a href="/assets/posts/2026-02-21-NTLM reflection recon/challenge.png" class="popup img-link"><img src="/assets/posts/2026-02-21-NTLM reflection recon/challenge.png" loading="lazy" alt="null"></a>
<em>NTLM_CHALLENGE message</em>

3) The client receives the challenge and inserts its token into the server context referenced by the ID in the Reserved field. The client sends back an  <code class="language-plaintext highlighter-rouge">NTLM_AUTHENTICATE</code> message that is almost empty (including the challenge response), and the server uses the token stored in the context to perform further operations.
<a href="/assets/posts/2026-02-21-NTLM reflection recon/auth.png" class="popup img-link"><img src="/assets/posts/2026-02-21-NTLM reflection recon/auth.png" loading="lazy" alt="null"></a>
<em>NTLM_AUTHENTICATE message</em>

<h2 id="dtf">Dropping the flags</h2>
As the post mentioned earlier explains, <i>“NTLM reflection is a special case of NTLM authentication relay in which the original authentication is relayed back to the machine from which the authentication originated.”</i> <br><code class="language-plaintext highlighter-rouge">CVE‑2025‑33073</code> is already thoroughly covered in Synacktiv’s blog, which shows how an attacker can execute commands as SYSTEM (when the coerced service runs as SYSTEM) through an SMB to SMB NTLM relay when SMB signing is not enforced. In fact, the technique also works against several protocols that normally enforce channel binding, such as ESC8 (relay to ADCS https endpoint), MSSQL, and WINRMS as discussed <a href="https://github.com/Pennyw0rth/NetExec/issues/928">here</a>.

Later, another vulnerability was found: <code class="language-plaintext highlighter-rouge">CVE‑2025‑54918</code> (NTLM MIC bypass). This vulnerability still relies on NTLM reflection, but it enables cross‑protocol relay to LDAP when signing is not enforced, and to LDAPS even when CBT is enforced, something that, with the proper modern countermeasures, should no longer be possible.

In fact in a standard NTLM authentication flow, the payload inside the  <code class="language-plaintext highlighter-rouge">NTLM_AUTHENTICATE</code> message contains a structure known as  <code class="language-plaintext highlighter-rouge">AvPairs</code>, which is essentially a list of key–value pairs. The entire AvPairs structure is encrypted (MAC) together with the rest of the challenge blob (which also includes the client challenge). Two AvPairs values are particularly important:

-  <code class="language-plaintext highlighter-rouge">MsvAvFlags</code>: indicates whether the MIC is present.

-  <code class="language-plaintext highlighter-rouge">MsvAvTargetName</code>: specifies the service the client intends to authenticate to (for example, cifs).

<a href="/assets/posts/2026-02-21-NTLM reflection recon/avpairs.png" class="popup img-link"><img src="/assets/posts/2026-02-21-NTLM reflection recon/avpairs.png" loading="lazy" alt="null"></a>
<em>AvPairs structure and values</em>

Because of these fields, the client cannot modify flags such as  <code class="language-plaintext highlighter-rouge">SIGN/SEAL</code> without invalidating the  <code class="language-plaintext highlighter-rouge">MIC</code> (protected by MsvAvFlags), and cross‑protocol relay is normally impossible due to the presence of MsvAvTargetName, which binds the authentication to a specific service.

For protocols that operate over TLS, a form of TLS service binding is available. When a client needs to communicate using a protocol wrapped inside TLS (such as HTTPS or LDAPS) it first negotiates a TLS session with the server. During this handshake, the client derives the hash of the server’s certificate. This value, known as the <code class="language-plaintext highlighter-rouge">Channel Binding Token (CBT)</code>, is then embedded into the client’s NTLM authentication response.

At the end of the NTLM exchange, the legitimate server inspects the received NTLM message, extracts the included hash, and compares it with the actual hash of its own certificate. If the two values don’t match, the server can determine that it was not the original endpoint involved in the NTLM negotiation. This mechanism is particularly relevant for protocols that do not natively support signing, such as HTTPS.


However, NTLM reflection behaves differently, as it triggers local NTLM authentication. This occurs because the marshalled target (<code class="language-plaintext highlighter-rouge">&lt;hostname&gt;1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA</code> or <code class="language-plaintext highlighter-rouge">localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA</code>) supplied during coercion is stripped by the <code class="language-plaintext highlighter-rouge">lsasrv!LsapCheckMarshalledTargetInfo</code> function before the authentication proceeds. Once the target information is stripped, the target appears identical to the local machine, causing <code class="language-plaintext highlighter-rouge">msv1_0!SspIsTargetLocalhost</code> function to add the domain and workstation name to the <code class="language-plaintext highlighter-rouge">NTLM_NEGOTIATE</code> message.

So in this special case, as we previously saw, the <code class="language-plaintext highlighter-rouge">NTLM_AUTHENTICATE</code> message is essentially empty: there is no MIC, no NtProofStr validation, and none of the AvPairs values that would normally prevent tampering or cross‑protocol relay. As a result, performing reflection only requires removing the SIGN and SEAL flags when the client expects them.


The following example shows the attack removing the SIGN flag, note that the same can be done with the <a href="https://github.com/decoder-it/impacket-partial-mic/commit/2c40d11c97ff7118723ec746cbd19b883141d8f0">SEAL flag</a>, and both can be removed at the same time as well:<br>
<a href="/assets/posts/2026-02-21-NTLM reflection recon/ldap.png" class="popup img-link"><img src="/assets/posts/2026-02-21-NTLM reflection recon/ldap.png" loading="lazy" alt="null"></a>
<em>Removing the SIGN flag, as originally requested by the client</em>

Since the domain controller policy “LDAP server signing requirements” appears to apply only to plain LDAP, LDAPS remains exposed to the same issue:

<a href="/assets/posts/2026-02-21-NTLM reflection recon/ldaps.png" class="popup img-link"><img src="/assets/posts/2026-02-21-NTLM reflection recon/ldaps.png" loading="lazy" alt="null"></a>
<em>Removing the SIGN flag, as originally requested by the client (with signing and CBT enforced)</em>
<br>
<blockquote class="prompt-warning">
Note that NTLM reflection cannot be used to obtain DCSYNC, because the <a href="https://dirkjanm.io/a-different-way-of-abusing-zerologon/">DRSUAPI protocol requires both signing and sealing</a> (<code class="language-plaintext highlighter-rouge">RPC_C_AUTHN_LEVEL_PKT_INTEGRITY</code> and <code class="language-plaintext highlighter-rouge">RPC_C_AUTHN_LEVEL_PKT_PRIVACY</code>).
</blockquote>

It is also worth noting that a similar reflection primitive exists in Kerberos authentication (see GhostSPN), though that deserves a dedicated post of its own.

<h2 id="detection">Detection</h2>
I wanted to find a way to detect systems vulnerable to <code class="language-plaintext highlighter-rouge">CVE‑2025‑54918</code> without actually triggering coercion (I also reached out to @decoder_it to eventually work on this). Looking at the existing NetExec ntlm_reflection module, the first approach is to check the victim machine’s  <code class="language-plaintext highlighter-rouge">UBR</code>(Update Build Revision) via Remote Registry to determine whether the relevant security patches are installed.

I initially looked into retrieving it via LDAP for a more reliable approach, but as far as I know the UBR value is not stored in the Active Directory database, making the Remote Registry the only viable option.
Since the module didn’t include support for  <code class="language-plaintext highlighter-rouge">CVE‑2025‑54918</code>, I implemented it myself and submitted a <a href="https://github.com/Pennyw0rth/NetExec/pull/1086"> PR to the official repository</a>.

However, while writing the module I thought that relying on the Remote Registry is not ideal: it isn’t enabled by default on workstations, and even when it is, administrators can easily disable it. Because of this limitation, I wanted to simulate the same network traffic by crafting a fake local NTLM authentication and observing how the server responds. The idea was simple: analyze the server’s return message and see whether the response differs depending on whether the patch is installed.

I <a href="https://github.com/pol4ir/impacket">modified Impacket</a> and successfully reproduced the same network traffic (also for smb), but I didn’t observe any meaningful difference in the server’s responses across the various scenarios. The authentication phase completed without issues, but as soon as the client attempted to perform additional operations, an error occurred. I’m not entirely certain, but the most plausible explanation is that the server cannot find the token in the context it previously created for the client, the one referenced in the Reserved field. Without that token, the server is unable to impersonate the client and therefore cannot proceed with any further operations. If anyone has dug deeper into this behavior, feel free to reach out.


As I conduct further tests, I believe that relying on different error statuses may not be a viable approach. The network traffic is largely the same, except for the coercion traffic that occurs when the client is unpatched. This is because the patch <i>"prevents the exploitation of the vulnerability by removing the ability to coerce machines into authenticating via Kerberos by registering a DNS record with marshalled target information."</i> I also expect the same behavior for NTLM, since coercion does not occur on patched targets.

<h2 id="conclusion">Conclusion</h2>

NTLM reflection is a powerful technique that can be used to bypass modern mitigations and perform various attacks, including RCE. It’s crucial for both attackers and defenders to understand the underlying mechanisms of NTLM local authentication and how NTLM reflection operates to effectively identify and mitigate potential vulnerabilities. As new CVEs continue to emerge, staying informed about the latest developments in this area is essential for maintaining robust security postures. 

This class of vulnerability also serves as a clear reminder that patch management is not optional: even well-established mitigations can be circumvented in ways that are far from obvious. 

<blockquote class="prompt-info">
Security updates related to NTLM reflection:<br>
- <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073">CVE-2025-33073 (NTLM reflection)</a><br>
- <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-54918">CVE-2025-54918 (NTLM MIC bypass)</a><br>
- <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-58726">CVE-2025-58726 (GhostSPN)</a>
</blockquote>

<br>
As usual, the post concludes with a summary table covering everything discussed, designed to help you determine the conditions under which each NTLM reflection CVE is exploitable. 

<a href="/assets/posts/2026-02-21-NTLM reflection recon/chart2.png" class="popup img-link"><img src="/assets/posts/2026-02-21-NTLM reflection recon/chart2.png" loading="lazy" alt="null"></a>
<em>Summary chart</em>



<h2 id="references">References</h2>
-  <a href="https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025">Synacktiv - NTLM reflection is dead, long live NTLM reflection! – An in-depth analysis of CVE-2025-33073 </a>
-  <a href="https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/">Reflecting Your Authentication: When Windows Ends Up Talking to Itself </a>

