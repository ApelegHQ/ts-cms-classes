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

import {
	Asn1Integer,
	Asn1Null,
	Asn1Object,
	Asn1OctetString,
	Asn1Sequence,
} from '@exact-realty/asn1-der';
import {
	OID_DIGESTALGO_HMACWITHSHA256,
	OID_PKCS5_PBKDF2,
} from '@exact-realty/crypto-oids';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';

// OID_PKCS5_PBKDF2
// Params: hmacWithSHA256 (OID_DIGESTALGO_HMACWITHSHA256)
/*
PBKDF2-params ::= SEQUENCE {
  salt OCTET STRING,
  iterationCount INTEGER (1..MAX),
  keyLength INTEGER (1..MAX) OPTIONAL,
  prf AlgorithmIdentifier
            DEFAULT { algorithm id-hmacWithSHA1, parameters NULL } }
*/
class KeyDerivationAlgorithmIdentifier extends AlgorithmIdentifier {
	static get pbkdf2sha256(): (
		salt: AllowSharedBufferSource,
		iterationCount: number,
	) => Readonly<KeyDerivationAlgorithmIdentifier> {
		return (salt: AllowSharedBufferSource, iterationCount: number) => {
			return new this(
				new Asn1Object(OID_PKCS5_PBKDF2),
				new Asn1Sequence([
					new Asn1OctetString(salt),
					new Asn1Integer(iterationCount),
					new AlgorithmIdentifier(
						new Asn1Object(OID_DIGESTALGO_HMACWITHSHA256),
						new Asn1Null(),
					),
				]),
			);
		};
	}
}

export default KeyDerivationAlgorithmIdentifier;
