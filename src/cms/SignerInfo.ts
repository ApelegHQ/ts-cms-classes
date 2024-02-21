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
import type CMSVersion from './CMSVersion.js';
import type DigestAlgorithmIdentifier from './DigestAlgorithmIdentifier.js';
import type SignatureAlgorithmIdentifier from './SignatureAlgorithmIdentifier.js';
import type SignatureValue from './SignatureValue.js';
import type SignedAttributes from './SignedAttributes.js';
import type SignerIdentifier from './SignerIdentifier.js';
import type UnsignedAttributes from './UnsignedAttributes.js';

class SignerInfo extends Asn1Sequence {
	digestAlgorithmId_: DigestAlgorithmIdentifier;
	version_: CMSVersion;

	constructor(
		sid: SignerIdentifier,
		digestAlgorithmId: DigestAlgorithmIdentifier,
		signatureAlgorithmId: SignatureAlgorithmIdentifier,
		signatureValue: SignatureValue,
		signedAttributesSet?: SignedAttributes,
		unsignedAttributesSet?: UnsignedAttributes,
	) {
		const omit = {};
		super(
			[
				// version
				sid.signerInfoVersion,
				// sid
				sid,
				// digestAlgorithm
				digestAlgorithmId,
				// signedAttributes
				signedAttributesSet
					? new Asn1ContextSpecific(0, signedAttributesSet, false)
					: omit,
				signatureAlgorithmId,
				// signatureValue
				signatureValue,
				// unsignedAttributes
				unsignedAttributesSet
					? new Asn1ContextSpecific(1, unsignedAttributesSet, false)
					: omit,
			].filter((x: unknown): x is IAsn1Data => x !== omit),
		);
		this.digestAlgorithmId_ = digestAlgorithmId;
		this.version_ = sid.signerInfoVersion;
	}

	get digestAlgorithm(): Readonly<typeof this.digestAlgorithmId_> {
		return this.digestAlgorithmId_;
	}

	get version(): Readonly<typeof this.version_> {
		return this.version_;
	}
}

export default SignerInfo;
