# Lonsdaleite - a practical hardening guide

## TOC

[[TOC]]

## Introduction

This guide is a companion to the [lonsdaleite NixOS module](https://www.github.com/omega-800/lonsdaleite), aiming to be a learning experience for [myself](https://www.github.com/omega-800), a hub of knowlegde on the topic of security and a practical guide of deploying a GNU + Linux / NixOS instance with security in mind.
All of the resources this project is based on are referenced in the [Sources](#sources) section, if not explicitly stated in the rest of this document. Please give them some love, because without them this project wouldn't have been possible.

[Madaians insecurities](https://madaidans-insecurities.github.io/linux.html)
> Linux being secure is a common misconception in the security and privacy realm.  

## Core security concepts

[What are the six basic security concepts?](https://securitycourses.com/cybersecurity-basics/what-are-the-six-basic-security-concepts/)
> The six basic security concepts are confidentiality, integrity, availability, authentication, authorization, and non-repudiation. Confidentiality ensures that only authorized individuals can access sensitive information. Integrity ensures that data is not tampered with or altered in any way. Availability ensures that data is accessible to authorized individuals when needed. Authentication ensures that individuals are who they claim to be. Authorization ensures that individuals have the necessary permissions to access certain data or systems. Non-repudiation ensures that individuals cannot deny their actions or transactions.

[Core principles of system hardening](https://linux-audit.com/linux-server-hardening-most-important-steps-to-secure-systems/#core-principles-of-system-hardening)
> ## Principe of least privilege
> 
> The principle of least privileges means that you give users and processes the bare minimum of permission to do their job. It is similar to granting a visitor access to a building. You could give full access to the building, including all sensitive areas. The other option is to only allow your guest to access a single floor where they need to be. The choice is easy, right?
> 
> ## Segmentation
> 
> The next principle is that you split bigger areas into smaller ones. If we look at that building again, we have split it into multiple floors. Each floor can be further divided into different zones. Maybe you visitor is only allowed on floor 4, in the blue zone. If we translate this to Linux security, this principle would apply to memory usage. Each process can only access their own memory segments.
> 
> ## Reduction
> 
> This principle aims to remove something that is not strictly needed for the system to work. It looks like the principle of least privilege, yet focuses on preventing something in the first place. A process that does not have to run, should be stopped. Similar for unneeded user accounts or sensitive data that is no longer being used.

## Hardening

### Network

#### Firewall

##### iptables

##### nftables

##### OpenSnitch

#### Hosting

##### SSL

##### Reverse Proxy

##### WAF 

##### Fail2ban

##### Hashicorp Vault

#### Onion / TOR

#### Kerberos 

#### MAC

#### SSH

#### DNS

##### Stubby

#### Misc. security

### Hardware

#### File System

##### Separation

##### Encryption

##### Permissions

##### Keeping things clean (impermanence)

##### Backups

#### Kernel

##### Modules

##### Sysctl

#### Memory access

### Applications

### Automatic Updates

#### Containerization

##### Docker

##### LXC

#### Virtualization

##### qemu

##### kvm

#### Isolation

##### Firejail

##### Apparmor

##### Isolate

##### Wrappers

#### Auth

##### GPG

##### Pass

##### SOPS

#### GitLeaks

### Operating system

#### SELinux

#### Privileges

##### PAM

[Linux Audit](https://linux-audit.com/linux-security-guide-extended-version/#choose-security-during-installation#securing-authentication-on-linux)
> Linux systems usually have the PAM framework available. The abbreviation stands for Pluggable Authentication Module. It provides a stackable set of authentication modules. This stack then determines who can access the system and any specific conditions that might apply to the session. Not only does it filter out the authorized users, it can set shell specific settings and check for password strength.

##### Users

- Enforce secure passwords 
- Password expiration
- Principle of least privilege: groups and permissions
- 2FA

#### Antivirus

##### ClamAV

#### SystemD

#### Misc. security

##### TTY

##### Randomness

#### Updates

## Monitoring

### Network

#### Suricata

#### Snort

#### Suricata

#### Zeek

#### mitmproxy

#### sslsniff

#### nmap

### Hardware

### Applications

#### Grafana 

#### Prometheus

#### Elasticlog

### Operating system

#### Wazuh

#### Lynis

#### osquery

#### vuls / vulnix

#### OpenVAS

## Sources

1. [Nix mineral](https://github.com/cynicsketch/nix-mineral)
2. [Kicksecure](https://github.com/Kicksecure/security-misc)
3. [Madaians insecurities](https://madaidans-insecurities.github.io/guides/linux-hardening.html)
4. [Redhat](https://docs.redhat.com/en/documentation/Red_Hat_Enterprise_Linux/7/html/security_guide/index)
5. [theprivacyguide1](https://theprivacyguide1.github.io/linux_hardening_guide)
6. [Arch wiki](https://wiki.archlinux.org/title/Security)
7. [IBM archive](https://web.archive.org/web/20210712001756/https://developer.ibm.com/technologies/linux/articles/l-harden-desktop/)
8. [Crunchbang archive](https://web.archive.org/web/20140220055801/http://crunchbang.org:80/forums/viewtopic.php?id=24722)
9. [LKRG](https://lkrg.org/)
10. [Linux audit](https://linux-audit.com/linux-security-guide-extended-version)
11. [imthenachoman](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server)
12. [Top 100 Linux security tools](https://linuxsecurity.expert/security-tools/top-100/)
