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

import { Asn1ContextSpecific, Asn1Sequence } from '@apeleghq/asn1-der';
import type ContentType from './ContentType.js';
import EncryptedContent from './EncryptedContent.js';
import ContentEncryptionAlgorithmIdentifier from './ContentEncryptionAlgorithmIdentifier.js';

/*
      EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
*/
class EncryptedContentInfo extends Asn1Sequence {
	contentType_: ContentType;

	constructor(
		contentType: ContentType,
		contentEncryptionAlgorithm: ContentEncryptionAlgorithmIdentifier,
		encryptedContent?: EncryptedContent,
	) {
		super(
			encryptedContent
				? [
						contentType,
						contentEncryptionAlgorithm,
						new Asn1ContextSpecific(0, encryptedContent, false),
					]
				: [contentType, contentEncryptionAlgorithm],
		);
		this.contentType_ = contentType;
	}

	get contentType(): Readonly<typeof this.contentType_> {
		return this.contentType_;
	}
}

export default EncryptedContentInfo;
