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

import { Asn1Object } from '@apeleghq/asn1-der';
import {
	OID_NISTALGO_AES_AES256WRAP,
	OID_PKCS9_SMIME_PWRIKEK,
} from '@apeleghq/crypto-oids';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import ContentEncryptionAlgorithmIdentifier from './ContentEncryptionAlgorithmIdentifier.js';

let aes256wrap: KeyEncryptionAlgorithmIdentifier;

class KeyEncryptionAlgorithmIdentifier extends AlgorithmIdentifier {
	static get pwriAes256cbc(): (
		aesIv: AllowSharedBufferSource,
	) => Readonly<KeyEncryptionAlgorithmIdentifier> {
		return (aesIv: AllowSharedBufferSource) =>
			new this(
				new Asn1Object(OID_PKCS9_SMIME_PWRIKEK),
				ContentEncryptionAlgorithmIdentifier.aes256cbc(aesIv),
			);
	}
	static get aes256wrap(): Readonly<KeyEncryptionAlgorithmIdentifier> {
		if (!aes256wrap) {
			aes256wrap = new this(new Asn1Object(OID_NISTALGO_AES_AES256WRAP));
		}
		return aes256wrap;
	}
}

export default KeyEncryptionAlgorithmIdentifier;
