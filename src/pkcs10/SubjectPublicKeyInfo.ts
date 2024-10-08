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

import type { Asn1BitString } from '@apeleghq/asn1-der';
import { Asn1AnyRaw, Asn1Sequence } from '@apeleghq/asn1-der';
import type AlgorithmIdentifier from '../cms/AlgorithmIdentifier.js';

/*
     SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }
*/
class SubjectPublicKeyInfo extends Asn1Sequence {
	static get importDer() {
		return (data: AllowSharedBufferSource) => {
			const imported = new Asn1AnyRaw(data);
			return imported as unknown as SubjectPublicKeyInfo;
		};
	}

	constructor(
		algorithm: AlgorithmIdentifier,
		subjectPublicKey: Asn1BitString,
	) {
		super([algorithm, subjectPublicKey]);
	}
}

export default SubjectPublicKeyInfo;
