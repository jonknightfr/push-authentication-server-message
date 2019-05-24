<!--
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
-->
# Push Authentication Sender Message
An authentication node based on the standard ForgeRock push authentication sender node, but adds additional message and payload options.

This node can be configured either to send a static message, defined in the node configuration, or a message derived from a header value passed to the authentication tree. In both cases variable substitution can be used inject {{user}} and {{issuer}} values.

In addition, shared state values can be included in the message payload, defined in the node configuration. This can be used to convey additional context info, such as gelocation. The standard ForgeRock authenticator currently doesn't support additional payload data, so this option needs a custom app to benefit from the context data.

## Installation

Copy the .jar file from the ../target directory into the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed.  Restart the web container to pick up the new node.  The node will then appear in the authentication trees components palette.

## To Build

Edit the necessary ClientScriptNode.java as appropriate.  To rebuild, run "mvn clean install" in the directory containing the pom.xml

![ScreenShot](./configuration.png)

## Disclaimer
The sample code described herein is provided on an "as is" basis, without warranty of any kind, to the fullest extent permitted by law. ForgeRock does not warrant or guarantee the individual success developers may have in implementing the sample code on their development platforms or in production configurations.

ForgeRock does not warrant, guarantee or make any representations regarding the use, results of use, accuracy, timeliness or completeness of any data or information relating to the sample code. ForgeRock disclaims all warranties, expressed or implied, and in particular, disclaims all warranties of merchantability, and warranties related to the code, or any service or software related thereto.

ForgeRock shall not be liable for any direct, indirect or consequential damages or costs of any type arising out of any action taken by you or others related to the sample code.