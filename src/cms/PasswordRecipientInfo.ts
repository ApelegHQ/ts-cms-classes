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
import CMSVersion from './CMSVersion.js';
import EncryptedKey from './EncryptedKey.js';
import KeyDerivationAlgorithmIdentifier from './KeyDerivationAlgorithmIdentifier.js';
import KeyEncryptionAlgorithmIdentifier from './KeyEncryptionAlgorithmIdentifier.js';

/*
   PasswordRecipientInfo ::= SEQUENCE {
     version CMSVersion,   -- always set to 0
     keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                                OPTIONAL,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     encryptedKey EncryptedKey }
*/

class PasswordRecipientInfo extends Asn1Sequence {
	version_: CMSVersion;

	constructor(
		keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier,
		encryptedKey: EncryptedKey,
		keyDerivationAlgorithm?: KeyDerivationAlgorithmIdentifier,
	) {
		const version = CMSVersion.v0;
		super(
			keyDerivationAlgorithm
				? [
						version,
						new Asn1ContextSpecific(
							0,
							keyDerivationAlgorithm,
							false,
						),
						keyEncryptionAlgorithm,
						encryptedKey,
					]
				: [version, keyEncryptionAlgorithm, encryptedKey],
		);

		this.version_ = version;
	}

	get version(): Readonly<typeof this.version_> {
		return this.version_;
	}
}

export default PasswordRecipientInfo;
