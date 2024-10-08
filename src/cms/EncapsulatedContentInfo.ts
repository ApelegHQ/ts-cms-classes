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

import type { Asn1OctetString } from '@apeleghq/asn1-der';
import { Asn1ContextSpecific, Asn1Sequence } from '@apeleghq/asn1-der';
import type ContentType from './ContentType.js';

/*
   EncapsulatedContentInfo ::= SEQUENCE {
     eContentType ContentType,
     eContent [0] EXPLICIT OCTET STRING OPTIONAL }
*/
class EncapsulatedContentInfo extends Asn1Sequence {
	eContentType_: ContentType;

	constructor(eContentType: ContentType, eContent?: Asn1OctetString) {
		super(
			eContent
				? [eContentType, new Asn1ContextSpecific(0, eContent, true)]
				: [eContentType],
		);
		this.eContentType_ = eContentType;
	}

	get eContentType(): Readonly<typeof this.eContentType_> {
		return this.eContentType_;
	}
}

export default EncapsulatedContentInfo;
