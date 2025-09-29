/* Copyright © 2025 Apeleg Limited. All rights reserved.
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

import { Asn1Sequence } from '@apeleghq/asn1-der';
import CMSVersion from './CMSVersion.js';
import EncryptedKey from './EncryptedKey.js';
import type KeyEncryptionAlgorithmIdentifier from './KeyEncryptionAlgorithmIdentifier.js';
import type KEKIdentifier from './KEKIdentifier.js';

/*
      KEKRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 4
        kekid KEKIdentifier,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }
*/

class KEKRecipientInfo extends Asn1Sequence {
	version_: CMSVersion;

	constructor(
		kekid: KEKIdentifier,
		keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier,
		encryptedKey: EncryptedKey,
	) {
		const version = CMSVersion.v4;
		super([version, kekid, keyEncryptionAlgorithm, encryptedKey]);

		this.version_ = version;
	}

	get version(): Readonly<typeof this.version_> {
		return this.version_;
	}
}

export default KEKRecipientInfo;
