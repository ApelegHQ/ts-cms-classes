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

import { ASN1_CLASS_CONTEXT_SPECIFIC_, Asn1Base } from '@apeleghq/asn1-der';
import CMSVersion from './CMSVersion.js';
import IssuerAndSerialNumber from './IssuerAndSerialNumber.js';
import SubjectKeyIdentifier from './SubjectKeyIdentifier.js';

class SignerIdentifier extends Asn1Base {
	data_: IssuerAndSerialNumber | SubjectKeyIdentifier;
	signerInfoVersion_: CMSVersion;

	constructor(signer: IssuerAndSerialNumber | SubjectKeyIdentifier) {
		if (signer instanceof IssuerAndSerialNumber) {
			super(signer.class_, signer.primitive_, signer.tag_);
			this.signerInfoVersion_ = CMSVersion.v1;
		} else if (signer instanceof SubjectKeyIdentifier) {
			super(ASN1_CLASS_CONTEXT_SPECIFIC_, signer.primitive_, 0);
			this.signerInfoVersion_ = CMSVersion.v3;
		} else {
			throw new Error('Invalid signer type');
		}

		this.data_ = signer;
	}

	get signerInfoVersion() {
		return this.signerInfoVersion_;
	}

	rawContents_(): AllowSharedBufferSource | null | undefined {
		return this.data_.rawContents_();
	}
}

export default SignerIdentifier;
