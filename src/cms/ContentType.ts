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
	OID_PKCS7_DATA,
	OID_PKCS7_ENCRYPTEDDATA,
	OID_PKCS7_ENVELOPEDDATA,
	OID_PKCS7_SIGNEDDATA,
} from '@apeleghq/crypto-oids';

let idData: ContentType;
let idEncryptedData: ContentType;
let idEnvelopedData: ContentType;
let idSignedData: ContentType;

class ContentType extends Asn1Object {
	static get idData(): Readonly<Asn1Object> {
		if (!idData) {
			idData = new ContentType(OID_PKCS7_DATA);
		}
		return idData;
	}
	static get idEncryptedData(): Readonly<Asn1Object> {
		if (!idEncryptedData) {
			idEncryptedData = new ContentType(OID_PKCS7_ENCRYPTEDDATA);
		}
		return idEncryptedData;
	}
	static get idEnvelopedData(): Readonly<Asn1Object> {
		if (!idEnvelopedData) {
			idEnvelopedData = new ContentType(OID_PKCS7_ENVELOPEDDATA);
		}
		return idEnvelopedData;
	}
	static get idSignedData(): Readonly<Asn1Object> {
		if (!idSignedData) {
			idSignedData = new ContentType(OID_PKCS7_SIGNEDDATA);
		}
		return idSignedData;
	}
}

export default ContentType;
