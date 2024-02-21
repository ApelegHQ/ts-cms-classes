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

import { Asn1Set } from '@exact-realty/asn1-der';
import type CMSVersion from './CMSVersion.js';
import type DigestAlgorithmIdentifier from './DigestAlgorithmIdentifier.js';
import DigestAlgorithmIdentifiers from './DigestAlgorithmIdentifiers.js';
import type SignerInfo from './SignerInfo.js';

class SignerInfos extends Asn1Set {
	digestAlgorithms_: DigestAlgorithmIdentifiers;
	versions_: Set<CMSVersion>;

	constructor(signerInfos: SignerInfo[]) {
		super(signerInfos);
		const digestAlgorithms: DigestAlgorithmIdentifier[] = [];
		const versionSet = new Set<CMSVersion>();

		signerInfos.forEach((signerInfo) => {
			const digestAlgorithm = signerInfo.digestAlgorithm;
			if (!digestAlgorithms.includes(digestAlgorithm)) {
				digestAlgorithms.push(digestAlgorithm);
			}

			versionSet.add(signerInfo.version);
		});
		this.digestAlgorithms_ = new DigestAlgorithmIdentifiers(
			digestAlgorithms,
		);
		this.versions_ = versionSet;
	}

	get digestAlgorithms(): Readonly<typeof this.digestAlgorithms_> {
		return this.digestAlgorithms_;
	}

	get versions(): Readonly<typeof this.versions_> {
		return this.versions_;
	}
}

export default SignerInfos;
