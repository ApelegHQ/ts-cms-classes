/* Copyright © 2024 Exact Realty Limited. All rights reserved.
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

import type { IAsn1Data } from '@exact-realty/asn1-der';
import { Asn1ContextSpecific, Asn1Sequence } from '@exact-realty/asn1-der';
import CMSVersion from './CMSVersion.js';
import UnprotectedAttributes from './UnprotectedAttributes.js';
import EncryptedContentInfo from './EncryptedContentInfo.js';
import RecipientInfos from './RecipientInfos.js';
import OriginatorInfo from './OriginatorInfo.js';
import PasswordRecipientInfo from './PasswordRecipientInfo.js';

/*
   EnvelopedData ::= SEQUENCE {
     version CMSVersion,
     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
     recipientInfos RecipientInfos,
     encryptedContentInfo EncryptedContentInfo,
     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/

/*
         IF ((originatorInfo is present) AND
             (any version 2 attribute certificates are present)) OR
            (any RecipientInfo structures include pwri) OR
            (any RecipientInfo structures include ori)
         THEN version is 3
         ELSE
            IF (originatorInfo is present) OR
               (unprotectedAttrs is present) OR
               (any RecipientInfo structures are a version other than 0)
            THEN version is 2
            ELSE version is 0
*/

class EnvelopedData extends Asn1Sequence {
	constructor(
		recipientInfos: RecipientInfos,
		encryptedContentInfo: EncryptedContentInfo,
		originatorInfo?: OriginatorInfo,
		unprotectedAttrs?: UnprotectedAttributes,
	) {
		const omit = {};
		const version =
			// TODO: (any version 2 attribute certificates are present)
			// AttributeCertificates are not currently implemented
			(originatorInfo && false) ||
			// TODO: OR .kinds.has(ori)
			// ORI is not implemented
			recipientInfos.kinds.has(PasswordRecipientInfo)
				? CMSVersion.v3
				: originatorInfo ||
					  unprotectedAttrs ||
					  Array.from(recipientInfos.versions).some(
							(v) => v.version !== 0,
					  )
					? CMSVersion.v2
					: CMSVersion.v0;

		super(
			[
				version,
				originatorInfo
					? new Asn1ContextSpecific(0, originatorInfo, false)
					: omit,
				recipientInfos,
				encryptedContentInfo,
				unprotectedAttrs
					? new Asn1ContextSpecific(1, unprotectedAttrs, false)
					: omit,
			].filter((x): x is IAsn1Data => x !== omit),
		);
	}
}

export default EnvelopedData;
