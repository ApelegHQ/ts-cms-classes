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
import Name from '../x501/Name.js';
import type Attributes from './Attributes.js';
import SubjectPublicKeyInfo from './SubjectPublicKeyInfo.js';
import Version from './Version.js';

/*
CertificationRequestInfo ::= SEQUENCE {
    version       INTEGER { v1(0) } (v1,...),
    subject       Name,
    subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
    attributes    [0] Attributes{{ CRIAttributes }}
}
*/

class CertificationRequestInfo extends Asn1Sequence {
	constructor(
		subject: Name,
		subjectPKInfo: SubjectPublicKeyInfo,
		attributes?: Attributes,
	) {
		const omit = {};
		super(
			[
				Version.v1,
				subject,
				subjectPKInfo,
				attributes
					? new Asn1ContextSpecific(0, attributes, false)
					: omit,
			].filter((x: unknown): x is IAsn1Data => x !== omit),
		);
	}
}

export default CertificationRequestInfo;
