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

import { Asn1Object } from '@exact-realty/asn1-der';
import { OID_NISTALGO_SHA_SHA256 } from '@exact-realty/crypto-oids';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';

let sha256: DigestAlgorithmIdentifier;

class DigestAlgorithmIdentifier extends AlgorithmIdentifier {
	static get sha256(): Readonly<DigestAlgorithmIdentifier> {
		if (!sha256) {
			// No NULL parameter,
			// see <https://datatracker.ietf.org/doc/html/rfc4055#section-2.1>
			sha256 = new this(new Asn1Object(OID_NISTALGO_SHA_SHA256));
		}
		return sha256;
	}
}

export default DigestAlgorithmIdentifier;
