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

import type { Asn1BitString } from '@exact-realty/asn1-der';
import { Asn1Sequence } from '@exact-realty/asn1-der';
import type SignatureAlgorithmIdentifier from '../cms/SignatureAlgorithmIdentifier.js';
import type CertificationRequestInfo from './CertificationRequestInfo.js';

/*
   CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }
*/
class CertificationRequest extends Asn1Sequence {
	constructor(
		certificationRequestInfo: CertificationRequestInfo,
		signatureAlgorithm: SignatureAlgorithmIdentifier,
		signature: Asn1BitString,
	) {
		super([certificationRequestInfo, signatureAlgorithm, signature]);
	}
}

export default CertificationRequest;
