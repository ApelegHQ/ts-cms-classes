/* Copyright © 2024 Apeleg Limited. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

import type { IAsn1Data, Asn1OctetString } from '@apeleghq/asn1-der';
import { Asn1ContextSpecific, Asn1Sequence } from '@apeleghq/asn1-der';
import CMSVersion from './CMSVersion.js';
import EncryptedContentInfo from './EncryptedContentInfo.js';
import OriginatorInfo from './OriginatorInfo.js';
import RecipientInfos from './RecipientInfos.js';
import UnprotectedAttributes from './UnprotectedAttributes.js';

/*
      AuthEnvelopedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        authEncryptedContentInfo EncryptedContentInfo,
        authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
        mac MessageAuthenticationCode,
        unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }*/

class AuthEnvelopedData extends Asn1Sequence {
	constructor(
		recipientInfos: RecipientInfos,
		authEncryptedContentInfo: EncryptedContentInfo,
		mac: Asn1OctetString,
		originatorInfo?: OriginatorInfo,
		authAttrs?: UnprotectedAttributes,
		unauthAttrs?: UnprotectedAttributes,
	) {
		const omit = {};
		const version = CMSVersion.v0;

		super(
			[
				version,
				originatorInfo
					? new Asn1ContextSpecific(0, originatorInfo, false)
					: omit,
				recipientInfos,
				authEncryptedContentInfo,
				authAttrs ? new Asn1ContextSpecific(1, authAttrs, false) : omit,
				mac,
				unauthAttrs
					? new Asn1ContextSpecific(2, unauthAttrs, false)
					: omit,
			].filter((x): x is IAsn1Data => x !== omit),
		);
	}
}

export default AuthEnvelopedData;
