---
title: Windows Lateral Movement - What You Really Need
date: 2025-10-10 10:00:00 +0000
categories: [lateral movement]
tags: [lateral movement, rce, wmi, cim, winrm, minimal rights, dcom, task scheduling, scmanager, named pipes, rpc, uac, acl, Find-DCOMLocalAdminAccess.ps1, microsoft policy, sc.exe, OpenService, RACE, BloodHound, enumeration]
image: /assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/chart.png
---

Last year, I conducted a security assessment for a company and was able to perform lateral movement on a target machine without having local administrator rights, by leveraging remote service creation.

Throughout my experience as a red teamer, I often heard that local admin rights are required for certain lateral movement techniques, especially when using tools like those from Impacket. I knew this wasn’t entirely true, but until that moment, I hadn’t had the opportunity to test it myself. This led me to explore the topic in depth and discover what is actually needed to perform various lateral movement techniques.

<blockquote class="prompt-danger">
Please note that this post is not an exhaustive analysis of all lateral movement techniques or related tools. It is intended as an introduction to the most common methods.
<br>
As I always recommend, never take anything for granted, test everything yourself! What works today may not work tomorrow (a.k.a. some Windows updates annoy us).
</blockquote>


<h2 id="screation">Service creation</h2>
If you're already familiar with the underlying mechanics, feel free to skip ahead to <a href="#wyrllyneed">this section</a>.<br>
From a UNIX-like perspective, tools like smbexec and psexec are commonly used for lateral movement, both relying on remote service creation as their core technique. Authentication is typically handled via NTLM, especially in environments without Active Directory or when connecting directly to an IP address rather than a hostname.
<br>
The authentication process relies on the <code class="language-plaintext highlighter-rouge">[MS-NRPC]</code> (Netlogon Remote Protocol) interface. Like other RPC services, it can be accessed through multiple transport protocols, including SMB named pipes, plain TCP, and UDP. When SMB is used as the transport, RPC services can be accessed via named pipes through the special <code class="language-plaintext highlighter-rouge">IPC$</code> share, which is reserved for inter-process communication on Windows systems.


Once authentication is complete, the service is created using the <code class="language-plaintext highlighter-rouge">[MS-SCMR]</code> interface via the well-known named pipe <code class="language-plaintext highlighter-rouge">\pipe\svcctl</code>. The goal is to create a service on the target machine that executes a binary, running your command under the <code class="language-plaintext highlighter-rouge">NT AUTHORITY\SYSTEM</code> security context. After establishing a connection to the named pipe, the <code class="language-plaintext highlighter-rouge">OpenSCManager</code> function opens a handle to the Service Control Manager (SCM), followed by calls to <code class="language-plaintext highlighter-rouge">CreateService</code> and <code class="language-plaintext highlighter-rouge">StartService</code> to deploy and run the service.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/servicecreation0.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/servicecreation0.png"  loading="lazy"></a>


<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/servicecreation.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/servicecreation.png"  loading="lazy"></a>
<em>Service creation process from smbexec.py</em>

<blockquote class="prompt-info">
On the server side these functions are actually aliases that automatically select either the ANSI or Unicode version, depending on whether the UNICODE preprocessor constant is defined during compilation.
</blockquote>

<h3 id="psexec">Psexec.py</h3>

psexec.py emulates the behavior of the original PsExec utility from Sysinternals, enabling remote command execution via service creation. It uploads its payload to any writable network share, typically the <code class="language-plaintext highlighter-rouge">ADMIN$</code> share, which maps to <code class="language-plaintext highlighter-rouge">C:\Windows</code> and is generally writable only by members of the local Administrators group. Once the payload is in place, it creates a remote service to execute it.

To facilitate communication, PsExec sets up custom named pipes using:

1. <code class="language-plaintext highlighter-rouge">RemCom_stdin</code> for input
2. <code class="language-plaintext highlighter-rouge">RemCom_stdout</code> for standard output
3. <code class="language-plaintext highlighter-rouge">RemCom_stderr</code> for standard error

This setup provides an interactive shell between the client and the remote host. 
The system logs Event ID 7045 when a service is created and Event ID 7036 when the service starts, allowing visibility into both the payload and the service name via the ETW.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/evtvwr.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/evtvwr.png"  loading="lazy"></a>
<em>Event viewer log of psexec execution</em>

<blockquote class="prompt-warning">
Before starting these tests, I verified that the SeNetworkLogonRight privilege was assigned to the "Everyone" group, which is the default configuration on most Windows systems. This privilege is required to allow users to perform network logons such as accessing shared folders or executing remote commands.

You can confirm this setting by navigating to: Local Security Policy → Local Policies → User Rights Assignment → Access this computer from the network.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/netlogon.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/netlogon.png"  loading="lazy"></a>
<em>Access this computer from the network</em>

On a Domain Controller, this configuration can be managed through the Group Policy Management Editor.
</blockquote>

Of course, these aren’t the only artifacts generated, but a full analysis is beyond the scope of this post.

After execution, PsExec attempts to clean up by uninstalling the created service (using the <code class="language-plaintext highlighter-rouge">DeleteService</code> function) and, optionally, deleting the uploaded binary.

<h3 id="smbexec">Smbexec.py</h3>

SMBExec works like psexec.py, but avoids writing binaries to disk by creating a new service for each command, so it does not provide an interactive shell. Since it requires no payload upload, this eliminates the need for a writable share.
<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/smbexec.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/smbexec.png"  loading="lazy"></a>
<em>smbexec.py execution</em>

To retrieve command output, smbexec can use different techniques. The first is SERVER mode, which utilizes a share created on the attacker’s machine. In this mode, STDOUT and STDERR are redirected to a temporary file on that share. SERVER mode requires root privileges to bind on port 445, and the port cannot be changed unless you modify the code.
The second technique, known as SHARE mode (which is the default) involves using a readable SMB share on the victim machine to redirect STDOUT and STDERR to a file located on that share.

<h3 id="wyrllyneed">What you really need</h3>

As previously discussed, both smbexec and psexec use the same underlying technique for lateral movement. The key difference is that smbexec does not require a writable share, since it does not upload any payload to the target machine.
Based on what we've seen so far, the minimum requirements are:

- A user who is a member of the local administrators group
- Either a readable share (for smbexec SHARE mode) or root privileges (for smbexec SERVER mode)

However, the second requirement can be easily bypassed by changing the local port for smbserver or by creating a service that executes a reverse shell payload, which connects back to the attacker.

The first command smbexec executes is not your intended command, but rather <code class="language-plaintext highlighter-rouge">cd</code>. You can modify the command (<a href="https://github.com/fortra/impacket/blob/master/examples/smbexec.py#L251">at line 251</a>) to anything you want. For example, you could execute a reverse shell payload encoded in base64 that connects back to you:

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/encodedrevshell.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/encodedrevshell.png"  loading="lazy"></a>
<em>Encoded reverse shell payload</em>

Smbexec will display an error due to the absence of a readable share to retrieve the output (<a href="https://github.com/fortra/impacket/blob/master/examples/smbexec.py#L325">by default, it attempts to use the <code class="language-plaintext highlighter-rouge">C$</code> share</a> and obviously the <code class="language-plaintext highlighter-rouge">IPC$</code> share can't be used for this purpose), but the payload will still execute, resulting in a reverse shell:

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/revshellobtained.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/revshellobtained.png"  loading="lazy"></a>
<em>Reverse shell obtained</em>

Note that instead, psexec.py uses serviceinstall.py to create and start the service. If you want to use a reverse shell payload, you need to modify the serviceinstall.py script <a href="https://github.com/fortra/impacket/blob/master/impacket/examples/serviceinstall.py#L98">at line 98</a> and comment out the lines in psexec.py that search for writable shares.

<blockquote class="prompt-info">
If you manually start the created service, you will encounter the following error:
<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/fashion.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/fashion.png"  loading="lazy"></a>
<em>Service start error</em>

This is because the service’s main() function must call <code class="language-plaintext highlighter-rouge">StartServiceCtrlDispatcher()</code> to run the service control dispatcher, which establishes the connection between the SCM and the service process (either by extending the ServiceBase class in C# or manually).
</blockquote>
At first glance, it seems that being a member of the local administrators group is the final requirement. But is this truly necessary?

In my research, I found <a href="https://pentestlab.blog/2023/03/20/persistence-service-control-manager/">this article</a>, which demonstrates that service creation, startup, and management can be delegated to specific users by modifying the security descriptor of the SCM. You can retrieve the SDDL (DACL and SACL description) of the SCM using the following command:

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/sdshow.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/sdshow.png"  loading="lazy"></a>
<em>sc sdshow scmanager command</em>

Alternatively, you can convert the binary registry value from the registry key <code class="language-plaintext highlighter-rouge">HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security</code>

```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security"
$raw = Get-ItemProperty -Path $regPath -Name Security
$bytes = $raw.Security
$sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
$sddl = $sd.GetSddlForm("All")
$sddl
```

The Security Descriptor Definition Language (SDDL) format is structured as follows:

```
O:<owner_sid>G:<group_sid>D:<dacl_flags>(<ACE1>)(<ACE2>)...(ACEn)S:<sacl_flags>(<ACE1>)(<ACE2>)...(ACEn)
```

You can easily find an SDDL parser online to help decode the SDDL string. Once you understand the format, you can modify it to <code class="language-plaintext highlighter-rouge">(A;;KA;;;AU)</code> using the following command:

```
sc sdset scmanager D:(A;;KA;;;AU)
```

<blockquote class="prompt-warning">
Note that you must run this command with a high integrity level; otherwise, you will receive an access denied error.
</blockquote>

The ACE (Access Control Entry) <code class="language-plaintext highlighter-rouge">(A;;KA;;;AU)</code> grants Authenticated Users (AU) the GENERIC_ALL (KA) permission, effectively allowing full control.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/scsdet.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/scsdet.png"  loading="lazy"></a>
<em>sc sdset scmanager command</em>

I created a new domain user without adding it to any group and attempted to create a service using smbexec.py, but it failed with the following error:

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/accessdenied.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/accessdenied.png"  loading="lazy"></a>
<em>Access denied error</em>

I struggled a bit to understand why it wasn’t working, and I also found it difficult to locate helpful resources online. However, after some research, I discovered <a href="https://support.microsoft.com/en-us/topic/block-remote-callers-who-are-not-local-administrators-from-starting-stopping-services-c5f77f8e-09e6-57e6-72d1-2c4423627a24">this policy</a>. 
As Microsoft describes: 

<blockquote>
Beginning with Windows 10 version 1709 and Windows Server 2016 version 1709. Under the new policy, only users who are local administrators on a remote computer can start or stop services on that computer.

 A common security mistake is to configure services to use an overly permissive security descriptor (see Service Security and Access Rights), and thereby inadvertently grant access to more remote callers than intended.
</blockquote>

According to the article's metadata, it was first published in 2018, which makes it surprising that other articles i found discussing service creation as a non-admin user fail to mention it.

It also shows how to disable this policy through the following registry keys:
- <code class="language-plaintext highlighter-rouge">RemoteAccessCheckExemptionList</code> under the path <code class="language-plaintext highlighter-rouge">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\SCM</code>
- <code class="language-plaintext highlighter-rouge">RemoteAccessExemption</code> under the path <code class="language-plaintext highlighter-rouge">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control</code>

The first one is per-services and the second one is to disable the policy globally.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/regvalue.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/regvalue.png"  loading="lazy"></a>
<em>Registry key to disable the policy</em>

After rebooting the machine, I tried again and this time it worked. I was able to create a service using smbexec.py without being a member of the local administrators group, and without needing a writable/readable share or root privileges on the attacker's machine.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/utente2.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/utente2.png"  loading="lazy"></a>
<em>User that is not member of the local administrators group</em>

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/revshellutente2.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/revshellutente2.png"  loading="lazy"></a>
<em>Reverse shell obtained</em>


If you suddenly encounter the error <code class="language-plaintext highlighter-rouge">0xc0000022 - STATUS_ACCESS_DENIED</code>, it's likely that AV or EDR is blocking the execution of your payload.

<blockquote class="prompt-info">
Crackmapexec also displayed the "(Pwned!)" message when I changed the scmanager SDDL to <code class="language-plaintext highlighter-rouge">(A;;KA;;;WD)</code>. It appears to check whether the user has certain privileges over the scmanager (such as the ability to create or query services), but I have not investigated this further.
Keep in mind that this method cannot be reliably used to enumerate remote command execution as a non-admin, since its original purpose was to detect actual local administrator access. Because it doesn't account for the previously mentioned policy restriction, a more dependable alternative is to use a manually modified version of smbexec, as demonstrated.
<br><br>
Edit: While researching an sc.exe-related issue (<a href="#scexe">see below</a>), I found <a href="https://0xdf.gitlab.io/2020/06/01/resolute-more-beyond-root.html#why-pwn3d">this post</a> that confirmed my theory. The check is for <code class="language-plaintext highlighter-rouge">SC_MANAGER_ALL_ACCESS</code> permission on the SCM.
</blockquote>

To be certain about the registry key, I tested this on Windows Server 2012 and confirmed that simply changing the scmanager SDDL was sufficient. No registry modifications were required.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/server2012.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/server2012.png"  loading="lazy"></a>
<em>Windows Server 2012</em>


So if you're considering using this as a persistence method on Windows 10 version 1709 and later or Windows Server 2016 version 1709 and later,  in addition to configuring the SDDL for scmanager (as highlighted in <a href="https://x.com/0gtweet/status/1628720819537936386">Grzegorz Tworek's tweet</a>) it is also necessary to configure the relevant registry keys as we have seen!

<H3 id="wintoolservice">Windows Tools</H3>

Now that we've established it's possible to create a service remotely without being a member of the local administrators group, let's examine whether Windows tools can be used for this purpose.

<h4 id="sysinternals">PSExec from Sysinternals</h4>

There isn't much to note here. PSExec does not work in this scenario because it attempts to upload a payload to the <code class="language-plaintext highlighter-rouge">ADMIN$</code> share, which is not writable by our user.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/psexec0.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/psexec0.png"  loading="lazy"></a>
<em>PsExec error</em>

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/psexec.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/psexec.png"  loading="lazy"></a>
<em>PsExec error</em>

<h4 id="scexe">SC.exe</h4>

sc.exe is a native Windows tool for managing services, but surprisingly, it does not work as expected in this scenario. While I was able to create the service, attempting to start it resulted in an "access denied" error:

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/scerror.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/scerror.png"  loading="lazy"></a>
<em>sc.exe error</em>

After some research, I found <a href="https://0xdf.gitlab.io/2020/06/01/resolute-more-beyond-root.html#why-pwn3d">this article</a> describing the same error. In short, the sc start command uses the <code class="language-plaintext highlighter-rouge">OpenServiceW</code> function to obtain a handle to the service it wants to start. The DACL (Discretionary Access Control List) that is checked is the one assigned to the service itself, not the Service Control Manager. If you do not specify a DACL during service creation, the service inherits a default template that allows only local administrators to start, stop, or query the service, hence the access denied error.

However, calling <code class="language-plaintext highlighter-rouge">OpenServiceW</code> is not the only way to obtain a service handle. When you create a service using the <code class="language-plaintext highlighter-rouge">CreateServiceW</code> function and specify the access mask <code class="language-plaintext highlighter-rouge">"SERVICE_ALL_ACCESS"</code> it returns a handle to the newly created service with the requested permissions. This allows you to start, stop, or query the service without any issues. This is why tools like smbexec.py and psexec.py work reliably, they retrieve the service handle via <code class="language-plaintext highlighter-rouge">CreateServiceW</code> with the appropriate access mask, rather than calling <code class="language-plaintext highlighter-rouge">OpenServiceW</code>.

Alternatively, you can still use sc.exe to create a service with the start type set to "auto" and wait for the next reboot for your payload to be executed.

<h4 id="findlcladminaccess">Find-LocalAdminAccess</h4>

Find-LocalAdminAccess is a PowerView function that enumerates local administrator access on remote systems by calling Test-AdminAccess for each discovered computer.

According to the code for Test-AdminAccess (<a href="https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L15407">line 15407</a>):
<blockquote>
"This function will use the OpenSCManagerW Win32API call to establisha handle to the remote host. If this succeeds, the current user context has local administrator acess to the target."
</blockquote>

So in my case it should work out of the box and it does:
<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/powerview.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/powerview.png"  loading="lazy"></a>
<em>Find-LocalAdminAccess output</em>

<blockquote class="prompt-warning">
Similar to CrackMapExec, what’s being checked here is the presence of the <code class="language-plaintext highlighter-rouge">0xF003F access mask (SC_MANAGER_ALL_ACCESS)</code>. This allows interaction with the Service Control Manager without actually creating or starting a service, thereby bypassing newer policy restriction. However, since this method doesn't trigger the updated policy checks, it cannot be considered reliable for enumerating remote code execution as a non-admin user. This is totally fine because the method was originally designed to detect valid local administrator access.
</blockquote>
<h2 id="dcom">DCOM</h2>
 
The Component Object Model (COM) is a Microsoft technology designed for building interoperable binary software components. Distributed COM (DCOM) builds on this foundation, enabling these components to communicate and operate across networks via RPC (over port 135, with additional session data transmitted through dynamic ports in the range 19152–65535.), allowing for the remote creation, activation, and management of objects on other systems.

Many applications expose interfaces that allow remote command execution via DCOM, including MMC20, ShellBrowserWindow, ShellWindows, Excel, Internet Explorer, and others. These objects have well-known <code class="language-plaintext highlighter-rouge">CLSIDs</code> and <code class="language-plaintext highlighter-rouge">PROGIDs</code>, which can be used to instantiate them.

<blockquote class="prompt-info">
Note that many DCOM servers spawn under the process <code class="language-plaintext highlighter-rouge">C:\Windows\system32\svchost.exe -k DcomLaunch</code>.
</blockquote>

After authentication, the client calls the <code class="language-plaintext highlighter-rouge">ISystemActivator</code> COM interface to create remote COM objects. The <code class="language-plaintext highlighter-rouge">RemoteCreateInstance</code> method is invoked with the CLSID of the desired object. If successful, a reference to the remote COM object is returned, allowing the client to interact with it and execute its methods.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/dcomsystem.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/dcomsystem.png"  loading="lazy"></a>
<em>DCOM remote object creation process</em>
<h3 id="wyrllyneedcom">What you really need</h3>
Accessing DCOM objects requires specific permissions on the target application. While the default setup typically limits launch and activation rights to local administrators, it is not uncommon to encounter misconfigured systems in practice. For this reason, always verify the permission settings.
You can inspect and adjust these permissions using <code class="language-plaintext highlighter-rouge">dcomcnfg.exe</code>. At a minimum, your user account should have:

- <code class="language-plaintext highlighter-rouge">Remote Launch</code> permission in both "Edit Limits" and "Edit Default"
- <code class="language-plaintext highlighter-rouge">Remote Activation</code> permission in both "Edit Limits" and "Edit Default"
- <code class="language-plaintext highlighter-rouge">Remote Access</code> permission in Limits (usually granted to "Everyone" by default) and in Default (typically granted to "SELF" by default)

The "Default" settings specify the permissions that DCOM applications will use unless overridden for a specific application. "Limits" define the maximum permissions that can be enforced, even if individual application settings are more permissive.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/dcom.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/dcom.png"  loading="lazy"></a>
<em>DCOM configuration</em>


Additionally, ensure that "Enable Distributed COM on this computer" is selected in the "My Computer" properties (this is enabled by default).

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/dcom2.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/dcom2.png"  loading="lazy"></a>
<em>DCOM configuration</em>

You can also modify the Launch and Activation permissions for individual DCOM applications. This allows you to grant non-admin users access to specific applications, such as MMC20, while restricting others like ShellBrowserWindow.

To change permissions for a specific DCOM application, follow these steps (see <a href="https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/">enigma0x3's guide</a>):
1. Identify the application's <code class="language-plaintext highlighter-rouge">APPID</code> in dcomcnfg.exe: Component Services → Computers → My Computer → DCOM Config. Right-click the application, select Properties, and go to the "General" tab.
2. Open regedit and navigate to <code class="language-plaintext highlighter-rouge">"HKEY_CLASSES_ROOT\AppID"</code>. Right-click the relevant APPID, select Permissions, click "Advanced", change the owner to your user, and grant your user Full Control.
3. Return to dcomcnfg.exe, right-click the application, select Properties, and go to the "Security" tab. Under "Launch and Activation Permissions", select "Customize" and click "Edit". Add your user and grant "Local Launch", "Remote Launch", and "Remote Activation" permissions.

<blockquote class="prompt-info">
If the application does not appear in dcomcnfg.exe, you can locate it using the <code class="language-plaintext highlighter-rouge"><a href="https://github.com/tyranid/oleviewdotnet">OLE/COM Object Viewer</a></code>. <a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/shellwindows.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/shellwindows.png"  loading="lazy"></a>

</blockquote>


Note that some applications, such as ShellBrowserWindow and ShellWindows, require an interactive user session to be active on the target machine in order to function properly. This is because these COM objects interface directly with explorer.exe. As a result, any command executed through these interfaces will be spawned under the explorer.exe process, rather than mmc.exe.

In the OLE/COM Object Viewer, the RunAs section will display "Interactive User" for these applications, while others like MMC20 and Excel will show "N/A" (see the above screenshot).<br>

Additionally, you can change the security context under which a DCOM application runs. By default, it operates as "The launching user" or "Interactive user," but you can select "This user" in the "Identity" tab and specify any desired account.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/dcmolast.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/dcmolast.png"  loading="lazy"></a>
<em>DCOM identity configuration</em>

<blockquote class="prompt-info">
If no GUI session is available to set various permissions, you might want to check the <code class="language-plaintext highlighter-rouge">Set-DCOMPermissions</code> function from the <a href="https://github.com/samratashok/RACE/tree/master">RACE powershell module</a>.
</blockquote>

<h3 id="dcomexec.py">Dcomexec.py</h3>

From a UNIX-like perspective, you can use dcomexec.py from Impacket or netexec. Dcomexec.py supports MMC20, ShellBrowserWindow, and ShellWindows applications, providing a semi-interactive shell. As previously discussed, you can achieve a fully interactive shell by using a reverse shell payload without requiring access to any share by leveraging the <code class="language-plaintext highlighter-rouge">-nooutput</code> flag.

As far as i know, at the time of writing, netexec officially supports only the MMC20 application.
<H3 id="wintoolsdcom">Windows tools</H3>

From a Windows perspective, you can use Invoke-DCOM. It supports applications such as MMC20, ShellBrowserWindow, ShellWindows, and Excel.

To perform enumeration, you need to manually run Invoke-DCOM against each target machine using all supported methods. I couldn't find any tool that automates this task, so I wrote <a href="https://github.com/pol4ir/Find-DCOMLocalAdminAccess/tree/main">Find-DCOMLocalAdminAccess.ps1</a>.

The script attempts to enumerate DCOM access across all discovered computers using every available method.

<a href="https://raw.githubusercontent.com/pol4ir/Find-DCOMLocalAdminAccess/refs/heads/main/test.gif"><img src="https://raw.githubusercontent.com/pol4ir/Find-DCOMLocalAdminAccess/refs/heads/main/test.gif"  loading="lazy"></a>

These Windows tools, under the hood, simply attempt to instantiate the various DCOM applications. You can achieve the same behavior directly in PowerShell using the following code:

```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<TARGET_Machine>"))
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"<command>","7")
```

<blockquote class="prompt-info">
<a href="https://simondotsh.com/infosec/2021/12/29/dcom-without-admin.html">As noted in this article</a>, the <code class="language-plaintext highlighter-rouge">ExecuteDCOM</code> edge in BloodHound is displayed only if the user is a member of the <code class="language-plaintext highlighter-rouge">Distributed COM Users</code> group. However, as we discussed, this condition is not always accurate. In my tests, for example, the user "utente2" was able to successfully invoke a DCOM application despite not having the edge in BloodHound. Conversely, the user "dave" did have the edge, likely because he is a member of the Distributed COM Users group.
<p>
 <a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/executedcom.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/executedcom.png"  loading="lazy"></a>
<em>ExecuteDCOM edge from BloodHound</em></p>
</blockquote>

<blockquote class="prompt-info">
Troubleshooting some errors:<br>
- <code class="language-plaintext highlighter-rouge">0x80070005 - Access Denied</code>: insufficient DCOM permissions, requires interactive user or DCOM not enabled;
<br>- <code class="language-plaintext highlighter-rouge">0x800706ba - The RPC server is unavailable</code>: firewall blocking or RPC service not running; 
<br>- No error but command fails silently: likely blocked by AV or EDR.
</blockquote>

<h3 id="wmi">WMI</h3>
Windows Management Instrumentation (WMI) was introduced by Microsoft with Windows 2000 and Windows Server 2003 as part of its implementation of Web-Based Enterprise Management (WBEM), an industry-driven initiative to standardize technologies for accessing management data across enterprise environments.

WMI is built upon the Common Information Model (CIM) standard, which defines a unified structure for representing managed components within an IT infrastructure, including their properties and relationships.

Through its exposed interfaces, WMI enables administrators to perform remote and local management tasks across various Windows components.

While WMI does not offer a true remote shell, certain interfaces can be leveraged to simulate shell-like behavior. The host process typically used is <code class="language-plaintext highlighter-rouge">wmiprvse.exe</code>

One notable example is the <code class="language-plaintext highlighter-rouge">Win32_Process</code> class, which models system processes. By invoking its Create method, it’s possible to spawn new processes remotely. 

Once authenticated, the process calls the COM interface responsible for creating remote COM objects: ISystemActivator. This leads to the instantiation of the <code class="language-plaintext highlighter-rouge">IWbemLevel1Login</code> interface. Through this interface, it logs into the <code class="language-plaintext highlighter-rouge">root\cimv2</code> namespace, commonly used for system-level WMI tasks. With access granted, it loads the <code class="language-plaintext highlighter-rouge">Win32_Process</code> class and executes its Create method to run commands on the remote host.

<h4 id="wyrllyneedwmi">What you really need</h4>
So in addition to meeting DCOM requirements, the user must also have appropriate permissions on the WMI namespace. By default, members of the local Administrators group have full control over <code class="language-plaintext highlighter-rouge">root\cimv2</code>. However, these permissions can be modified to allow non-admin users to execute methods like Create on the <code class="language-plaintext highlighter-rouge">Win32_Process</code> class.

To configure this:
1. Open wmimgmt.msc
2. Right click on WMI Control (Local) and select properties
3. Go to the "Security" tab, select the <code class="language-plaintext highlighter-rouge">root\cimv2</code> namespace and click "Security"
4. Add the desired user and grant them the <code class="language-plaintext highlighter-rouge">Remote Enable</code> permission 

<blockquote class="prompt-info">
If no GUI session is available to set various permissions, you might want to check the <code class="language-plaintext highlighter-rouge">Set-RemoteWMI</code> function from the <a href="https://github.com/samratashok/RACE/tree/master">RACE powershell module</a>. 
</blockquote>

<h4 id="wmiexec.py">Wmiexec.py</h4>

After successful authentication, the tool establishes a smooth, semi-interactive shell on the remote host. Because WmiExec neither installs new services nor writes executables to disk, it maintains a low footprint, making it a stealthy and widely adopted method for remote command execution. To retrieve the output of executed commands, it redirects STDOUT and STDERR to a file on the <code class="language-plaintext highlighter-rouge">ADMIN$</code> share, then reads the output from that file. Fortunately, as demonstrated with dcomexec.py, using the <code class="language-plaintext highlighter-rouge">-nooutput</code> option allows you to bypass this behavior and execute commands without caring about the output.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/wmi.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/wmi.png"  loading="lazy"></a>
<em>WMI namespace security configuration</em>

The same can be achieved using netexec:

```
netexec wmi 192.168.56.30 -u <user> -p <pass> -x 'command'
```

For Windows-based approaches, you can use tools like Find-WMILocalAdminAccess.ps1 (enumeration only), CimSession, WMIC <a href="https://support.microsoft.com/en-us/topic/windows-management-instrumentation-command-line-wmic-removal-from-windows-e9e83c7f-4992-477f-ba1d-96f694b8665d">(deprecated)</a>, SharpWMI, and many others:

```powershell
Invoke-WMIMethod -Class win32_process -Name Create -Argumentlist '<command>' -Computername
```

<h2 id="winrm">Windows Remote Management</h2>

Windows Remote Management (WinRM) is Microsoft’s implementation of remote management protocols, designed to support both local and remote administration of Windows-based systems. It forms part of the broader Windows Hardware Management framework and enables administrators to interact with system components efficiently across the network.

WinRM is also the mechanism through which WMI (Windows Management Instrumentation) can be accessed over HTTP or HTTPS. Unlike standard web traffic that uses ports 80 and 443, WinRM communicates over port 5985 (HTTP) and 5986 (HTTPS). Although WinRM is pre-installed on all modern Windows systems, it requires configuration before use, particularly on client machines, where it is not enabled by default. On the other hand, Windows Server editions have WinRM enabled by default starting from Server 2008 R2, with full activation out-of-the-box from Server 2012 R2 onward.

To function properly, WinRM must have listeners configured on the client side. Even if the WinRM service is running, it won’t process incoming requests unless a listener is present and properly set up.

<blockquote class="prompt-info">
The process responsible for hosting WinRM plugins during remote operations is <code class="language-plaintext highlighter-rouge">wsmprovhost.exe</code>, which acts as the execution environment for commands and scripts triggered via WinRM.
</blockquote>

One of the key components of WinRM is Windows Remote Shell (WinRS), which allows remote command execution through cmd.exe and returns the output to the initiating system.

<h3 id="wyrllyneedwinrm">What you really need</h3>
By default, members of the Administrators group and, starting with Windows Server 2012, users in the <code class="language-plaintext highlighter-rouge">Remote Management Users</code> group are permitted to use PSRemoting for remote command execution. However, it's worth noting that group membership alone is not always required, what matters are the effective permissions on the remote PowerShell sessions (PSSessions). These permissions can be reviewed and adjusted to allow access without full administrative rights:

```powershell
winrm get winrm/config
```

It's possible to modify these permissions to allow non-admin users to execute remote commands:

```powershell
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```
<blockquote class="prompt-warning">
Note that you must run this command with a high integrity level; otherwise, you will receive an access denied error.
</blockquote>

In this dialog window, add a user or group and grant them <code class="language-plaintext highlighter-rouge">Execute (Invoke)</code> permissions:

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/winrm.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/winrm.png"  loading="lazy"></a>
<em>WinRM configuration</em>

If you want to modify it without having a GUI:

```powershell
$SDDL = “O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;<SID>)(A;;GA;;;RM)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)”
Set-PSSessionConfiguration -Name Microsoft.PowerShell -SecurityDescriptorSddl $SDDL
```

<blockquote class="prompt-info">
Otherwise, you might want to check the <code class="language-plaintext highlighter-rouge">Set-RemotePSRemoting</code> function from the <a href="https://github.com/samratashok/RACE/tree/master">RACE powershell module</a>.
</blockquote>

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/evilwinrm.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/evilwinrm.png"  loading="lazy"></a>
<em>Evil-WinRM execution</em>


To enumerate, you can use a straightforward PowerShell command:
```powershell
Invoke-Command -computername <victim> -ScriptBlock {whoami} 
```

Behind the scenes, this is essentially what Find-PSRemotingLocalAdminAccess <a href="https://github.com/RedTeamMagic/Powershell/blob/main/Find-PSRemotingLocalAdminAccess.ps1#L66">does</a> 

<h2 id="taskscheduling">Task scheduling</h2>

Microsoft Windows offers mechanisms for executing scheduled tasks remotely via the <code class="language-plaintext highlighter-rouge">[MS-TSCH]</code> Task Scheduler Service Remoting Protocol. Remote task creation can be performed through the named pipe <code class="language-plaintext highlighter-rouge">\pipe\atsvc</code> or the TCP-based interface <code class="language-plaintext highlighter-rouge">ITaskSchedulerService</code>. 
The Task Scheduler service is hosted by the following svchost process: <code class="language-plaintext highlighter-rouge">C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule</code>.
Starting with Windows 10 Version 1511, svchost.exe spawns taskhostw.exe, which then launches the executable defined by the scheduled task.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/taskhost.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/taskhost.png"  loading="lazy"></a>
<em>taskhostw.exe</em>

<blockquote class="prompt-info">

- Windows XP / Vista / Early versions Tasks were executed via taskeng.exe, the original task engine.
<br>
- Windows 7 The process name changed to taskhost.exe, which hosted task-related COM objects.
<br>
- Windows 8 Introduced an additional process called taskhostex.exe, later removed in future versions.

</blockquote>

Once connected, the client can invoke the <code class="language-plaintext highlighter-rouge">SchRpcRegisterTask</code> method to register a new scheduled task on the target system.

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/taskscheduler.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/taskscheduler.png"  loading="lazy"></a>
<em>Task Scheduler remote object creation process</em>

For every scheduled task created, an XML file named after the task is generated under <code class="language-plaintext highlighter-rouge">C:\Windows\System32\Tasks\</code>. This file contains the full description and configuration of the task.

In Windows, the at.exe command has been deprecated since Windows 8. To create scheduled tasks remotely, you can use schtasks.exe, which provides more flexibility and supports modern task scheduling features:

```
schtasks /Create /S <target_ip> /U <user> /P <pass> /TN <task_name> /TR <command> /SC ONCE /ST 00:00 /RL HIGHEST /F
```

<h3 id="atexec">atexec.py</h3>

Impacket atexec.py connects to the target system over RPC, using the Task Scheduler Service to create an immediate scheduled task with <code class="language-plaintext highlighter-rouge">SYSTEM-level</code> privileges. The task name is randomly generated (8 characters) and executes a single command wrapped in cmd.exe, allowing redirection of STDOUT and STDERR to a temporary file in the <code class="language-plaintext highlighter-rouge">ADMIN$</code> share. This file is retrieved via SMB, read, and deleted. After execution, the task itself is also removed.

I’ll probably need to take a proper deep dive into the minimum requirements for creating scheduled tasks, something to tackle when I have more time to dig in.

<h2 id="uac">Workgroup and UAC remote restrictions</h2>

If UAC remote restrictions are enabled (which they are by default), local accounts that belong to the local Administrators group will receive a filtered token when accessing a system remotely. This results in access denied errors during remote operations. These restrictions, however, do not apply to domain accounts, which retain full administrative tokens during remote logons.

Since UAC remote restrictions apply to network logons, using a local administrator account for lateral movement will fail due to insufficient permissions on the target machine. That said, considering we've already discussed enabling lateral movement for non-admin users, this limitation doesn't affect our current approach.

<blockquote class="prompt-info">
To determine whether UAC (User Account Control) is enabled, check the following registry keys :
<br>1. <code class="language-plaintext highlighter-rouge">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA</code>.
The default value is 1, which means UAC is active.
<br>2. If <code class="language-plaintext highlighter-rouge">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy</code> is set to 0, local accounts that are members of the local Administrators group will receive a filtered token when accessing the system remotely, resulting in limited privileges.
<br>3. The registry key <code class="language-plaintext highlighter-rouge">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken</code> instead is used to determine the behavior of the built-in Administrator account (RID 500) when UAC is enabled:
<br>If set to 0, the built-in Administrator account will run with a filtered token.
<br>If set to 1, the account runs with a full token.
<br>When connecting remotely, the built-in Administrator account operates with an unfiltered token by default, so UAC remote restrictions are not enforced.
</blockquote>
<h2 id="conclusion">Conclusion</h2>

<a href="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/chart.png" class="popup img-link"><img src="/assets/posts/2025-10-10-LateralMovement-WhatYouReallyNeed.md/img/chart.png" loading="lazy"></a>
<em>Summary chart</em>

Although the configuration we discussed isn’t the default, misconfigured systems are surprisingly common in real-world environments as I personally observed during a live engagement. This means that even if you have valid credentials for a user who isn’t part of the local Administrators group, or you lack access to readable/writable shares, you may still be able to perform lateral movement, provided the target system is misconfigured. It’s always worth checking for these conditions, as demonstrated.


Worth noting: such configurations can also be repurposed as a persistence mechanism, allowing long-term access if left untouched.

If you think I’ve missed anything, don’t hesitate to reach out!
<h2 id="references">References</h2>
- <a href="https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution">Synacktiv - traces of windows remote command execution</a>
- <a href="https://www.crowdstrike.com/en-us/blog/how-to-detect-and-prevent-impackets-wmiexec/">Crowdstrike - how to detect and prevent impackets wmiexec</a>
- <a href="https://www.deepinstinct.com/blog/forget-psexec-dcom-upload-execute-backdoor">Deepinstinct - forget psexec dcom upload execute backdoor</a>
- <a href="https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/">Enigma0x3 - lateral movement via dcom</a>


