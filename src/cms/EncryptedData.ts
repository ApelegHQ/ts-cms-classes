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

import { Asn1ContextSpecific, Asn1Sequence } from '@exact-realty/asn1-der';
import CMSVersion from './CMSVersion.js';
import UnprotectedAttributes from './UnprotectedAttributes.js';
import EncryptedContentInfo from './EncryptedContentInfo.js';

/*
      EncryptedData ::= SEQUENCE {
        version CMSVersion,
        encryptedContentInfo EncryptedContentInfo,
        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }*/

class EncryptedData extends Asn1Sequence {
	constructor(
		encryptedContentInfo: EncryptedContentInfo,
		unprotectedAttrs?: UnprotectedAttributes,
	) {
		const version = unprotectedAttrs ? CMSVersion.v2 : CMSVersion.v0;

		super(
			unprotectedAttrs
				? [
						version,
						encryptedContentInfo,
						new Asn1ContextSpecific(1, unprotectedAttrs, false),
					]
				: [version, encryptedContentInfo],
		);
	}
}

export default EncryptedData;
