# OpenId Jenkins Plugin

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th style="text-align: left;">Plugin Information</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="text-align: left;"><p>View openid <a
href="https://plugins.jenkins.io/openid">on the plugin site</a> for more
information.</p></td>
</tr>
</tbody>
</table>
The previous versions of this plugin may not be safe to use. Please review the following warnings before use:

-   [CSRF vulnerability and missing permission check allow
    SSRF](https://jenkins.io/security/advisory/2019-04-03/#SECURITY-1084)

This plugin lets your Jenkins users login to Jenkins through external OpenID providers, without using password.(Or in the OpenID terminology, this plugin makes Jenkins [a relying party](http://en.wikipedia.org/wiki/OpenID).

The plugin has two somewhat different mode of operations:

1.  ***On the side* mode**: Keep the existing security realm and just use OpenID as a way to login without typing a password. That is, Jenkins is still taking user/group information from some source (such as Active Directory, LDAP, etc.), and with this plugin useres can now login to their user accounts by associating OpenID with their accounts.
2.  **SSO mode**: You’ll designate one OpenID provider as the authoritative source of the user information in Jenkins. The user must login through this OpenID provider, and the user account will be automatically created and linked to it.

## Maintainers

- Michael Nazzareno Trimarchi
  - michael@amarulasolutions.com

## Build

Requires JDK 11, Maven 3.0 or higher.

```bash
mvn -U clean package
```

If the user needs to disable test just run
```bash
mvn -U -DskipTests=true clean package
```

## Table of content

As of 2.1 this mode is off by default for new installations. Upgrades should retain the configuration as on. In this mode, the user will first associate OpenIDs with their user accounts (by clicking their name on the top right of the page and then "Configure", after logging in normally):

<span
class=".confluence-embedded-file-wrapper .image-center-wrapper">![image](docs/images/associate.png)</span>

This will initiate a wizard that allows the user to associate OpenIDs to this account. Once this is setup, the user can login to his/her account
with this OpenID, without remembering the password:

<span
class=".confluence-embedded-file-wrapper .image-center-wrapper">![image](docs/images/login-with-openid.png)</span>

In this mod "on the side" mode, OpenID is just used as a means to bypass the use of password.

# SSO mode

This mode makes Jenkins completely rely on single external OpenID provider as the user realm. Use of OpenID in this mode is no longer just a convenience — you have to "belong" to the configured OpenID provider to be able to login to Jenkins.

First, the administrator will configure the system and designate the OpenID provider:

<span
class=".confluence-embedded-file-wrapper .image-center-wrapper">![image](docs/images/sso.png)</span>

Here you need to specify which OpenID provider you’ll be delegating authentication to. You do this either by specifing the "OpenID Provider
Endpoint URL" (as defined by [the spec](http://openid.net/specs/openid-authentication-2_0.html#terminology)), or by specifying one OpenID identifier and let Jenkins figure out where the OP Endpoint URL is. The latter is often easier as it can be sometimes rather complicated to find out what the actual OP Endpoint URL is.

Once Jenkins is configured this way, the user is automatically sent to this OpenID provider whenever Jenkins determines that the user needs to be authenticated. This includes accessing a protected page and clicking a login link, and it happens **without the user clicking a "login with
OpenID" button**.

Combined with the option in typical OpenID providers to bypass the confirmation dialog after the first login, this creates a single sign-on experience where the user never have to explicitly login to access Jenkins.

## Automatic Read Access

By default, users who authenticate via OpenID have no rights, not even the right to see the Jenkins GUI. To grant a right to all OpenID users,
add a user "authenticated" and grant them the desired right. Typically this will be Overall/Read.

## Team extension support

This implementation supports [the OpenID team extension](https://dev.launchpad.net/OpenIDTeams) to retrieve group membership information from OpenID providers. The protocol works, the group membership information is retrieved on a login. If you are added as a member of a new team, or if you modify ACLs in Jenkins and added a row for a new group, you’ll have to relogin for Jenkins to recognize your membership in this new group.

## SSO mode configuration ideas

-   If you deny the read access to the anonymous user on your Jenkins, people will automatically get authenticated va OpenID whenever they
    access Jenkins. This is very convenient to keep track of who’s making what changes in Jenkins, but without bothering the user.

-   You can take it one step further, and grant the read access to specific teams in the OpenID provider. This allows you to restrict
    the use of Jenkins to a subset of those who have identities on the OpenID provider (as opposed to everyone with an account.)

# Working with Google Apps

This plugin supports Google Apps as an OpenID provider. Select "Google Apps SSO (with OpenID)" in the UI and type in your domain name. In this
way, users must have a valid user account on your domain to be able to login.

Google is phasing out OpenID 2.0 support and will [turn off OpenID logins by April 20th, 2015](https://developers.google.com/+/api/auth-migration#timetable). You should migrate to the new [google-login](https://wiki.jenkins-ci.org/display/JENKINS/Google+Login+Plugin) plugin which also supports Google Apps domain restriction.

# Release History

-   [SECURITY-1084](https://issues.jenkins-ci.org/browse/SECURITY-1084) Fixed missing permission check and CSRF protection
    (<https://jenkins.io/security/advisory/2019-04-03/#SECURITY-1084>)

-   [JENKINS-55683](https://issues.jenkins-ci.org/browse/JENKINS-55683) Fixed infinite redirect loop on Jenkins 2.150.2/2.160

-   [JENKINS-36499](https://issues.jenkins-ci.org/browse/JENKINS-36499) - Updated to use the plugin parent pom

-   [JENKINS-28859](https://issues.jenkins-ci.org/browse/JENKINS-28859) - Drop Google App SSO code

-   Fixed findbugs errors, cleanup

-   Fixed the escape hatch system property to disable the OpenID Teams extension: -Dhudson.plugins.openid.impl.TeamsExtension.disable=true

-   Added some alternative email attributes

-   Fix proxy settings for discovery

-   Add a UI to allow easy access to disable/enable the federated login service.

-   Default the federated login service to disabled on new installations (upgrades should retain enabled until configured otherwise)

-   Upgrade openid4java to version 0.9.8 to pick up critical security fixes that the openid4java project recommend picking up.

-   Provide a system property to disable the federated login service.

-   JENKINS-9978

-   JENKINS-14843

-   JENKINS-9792

-   Improved the form validation ([JENKINS-16396](https://issues.jenkins-ci.org/browse/JENKINS-16396))

-   Improved error diagnostics ([JENKINS-11746](https://issues.jenkins-ci.org/browse/JENKINS-11746))

-   Added Google Apps support.

-   Fixed a security vulnerability.

-   Improved the error diagnosis when the authentication session starts under one host name and then the user is redirected back to another
    host name, of the same Jenkins.

-   Fixed a bug in persistence ([JENKINS-9163](https://issues.jenkins-ci.org/browse/JENKINS-9163))

-   Use AX in addition to SReg to retrieve user information ([JENKINS-8732](https://issues.jenkins-ci.org/browse/JENKINS-8732))

-   Fixed a bug in the reverse proxy setup ([JENKINS-8755](https://issues.jenkins-ci.org/browse/JENKINS-8755))

-   Initial release
