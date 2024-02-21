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
	Asn1ContextSpecific,
	Asn1Integer,
	Asn1Null,
	Asn1Object,
	Asn1Sequence,
} from '@exact-realty/asn1-der';
import {
	OID_ANSIX962_SIGNATURES_ECDSAWITHSHA256,
	OID_PKCS1_IDMGF1,
	OID_PKCS1_RSASSAPSS,
	OID_PKCS1_SHA256WITHRSAENCRYPTION,
} from '@exact-realty/crypto-oids';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import DigestAlgorithmIdentifier from './DigestAlgorithmIdentifier.js';

let ecdsaWithSha256: SignatureAlgorithmIdentifier;
let rsaPssWithSha256Mgf1Sha256Salt32: SignatureAlgorithmIdentifier;
let sha256WithRsaEncryption: SignatureAlgorithmIdentifier;

class SignatureAlgorithmIdentifier extends AlgorithmIdentifier {
	static get ecdsaWithSha256(): Readonly<SignatureAlgorithmIdentifier> {
		if (!ecdsaWithSha256) {
			ecdsaWithSha256 = new this(
				new Asn1Object(OID_ANSIX962_SIGNATURES_ECDSAWITHSHA256),
			);
		}
		return ecdsaWithSha256;
	}
	static get rsaPssWithSha256Mgf1Sha256Salt32(): Readonly<SignatureAlgorithmIdentifier> {
		if (!rsaPssWithSha256Mgf1Sha256Salt32) {
			rsaPssWithSha256Mgf1Sha256Salt32 = new this(
				new Asn1Object(OID_PKCS1_RSASSAPSS),
				new Asn1Sequence([
					new Asn1ContextSpecific(
						0,
						DigestAlgorithmIdentifier.sha256,
						true,
					),
					new Asn1ContextSpecific(
						1,
						new Asn1Sequence([
							new Asn1Object(OID_PKCS1_IDMGF1),
							DigestAlgorithmIdentifier.sha256,
						]),
						true,
					),
					new Asn1ContextSpecific(
						2,
						// RSA PSS salt length (32)
						new Asn1Integer(new Uint8Array([0x20])),
						true,
					),
				]),
			);
		}
		return rsaPssWithSha256Mgf1Sha256Salt32;
	}
	static get sha256WithRsaEncryption(): Readonly<SignatureAlgorithmIdentifier> {
		if (!sha256WithRsaEncryption) {
			sha256WithRsaEncryption = new this(
				new Asn1Object(OID_PKCS1_SHA256WITHRSAENCRYPTION),
				// Parameters MUST be NULL
				// See <https://datatracker.ietf.org/doc/html/rfc4055#section-5>
				new Asn1Null(),
			);
		}
		return sha256WithRsaEncryption;
	}
}

export default SignatureAlgorithmIdentifier;
