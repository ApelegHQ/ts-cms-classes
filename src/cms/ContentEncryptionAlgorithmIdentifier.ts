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
	Asn1Object,
	Asn1OctetString,
	Asn1Sequence,
} from '@exact-realty/asn1-der';
import { OID_NISTALGO_AES_AES256GCM } from '@exact-realty/crypto-oids';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';

class ContentEncryptionAlgorithmIdentifier extends AlgorithmIdentifier {
	static get aes256gcm16(): (
		nonce: AllowSharedBufferSource,
	) => Readonly<ContentEncryptionAlgorithmIdentifier> {
		return (nonce: AllowSharedBufferSource) =>
			new this(
				new Asn1Object(OID_NISTALGO_AES_AES256GCM),
				new Asn1Sequence([
					// aes-nonce
					new Asn1OctetString(nonce),
					// AES-GCM-ICVlen
					new Asn1Integer(0x10),
				]),
			);
	}
}

export default ContentEncryptionAlgorithmIdentifier;
