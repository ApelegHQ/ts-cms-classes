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

import {
	Asn1ContextSpecific,
	Asn1Integer,
	Asn1Object,
	Asn1OctetString,
	Asn1Sequence,
} from '@apeleghq/asn1-der';
import {
	OID_NISTALGO_AES_AES128GCM,
	OID_NISTALGO_AES_AES192GCM,
	OID_NISTALGO_AES_AES256GCM,
	OID_PKCS1_IDMGF1,
	OID_PKCS1_IDRSAESOAEP,
} from '@apeleghq/crypto-oids';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import DigestAlgorithmIdentifier from './DigestAlgorithmIdentifier.js';

let rsaOaepWithRfc8017DefaultParams: ContentEncryptionAlgorithmIdentifier;
let rsaOaepWithSha256Mgf1Sha256Empty: ContentEncryptionAlgorithmIdentifier;
let rsaOaepWithSha384Mgf1Sha384Empty: ContentEncryptionAlgorithmIdentifier;
let rsaOaepWithSha512Mgf1Sha512Empty: ContentEncryptionAlgorithmIdentifier;

class ContentEncryptionAlgorithmIdentifier extends AlgorithmIdentifier {
	static get aes128gcm16(): (
		nonce: AllowSharedBufferSource,
	) => Readonly<ContentEncryptionAlgorithmIdentifier> {
		return (nonce: AllowSharedBufferSource) =>
			new this(
				new Asn1Object(OID_NISTALGO_AES_AES128GCM),
				new Asn1Sequence([
					// aes-nonce
					new Asn1OctetString(nonce),
					// AES-GCM-ICVlen
					new Asn1Integer(0x10),
				]),
			);
	}
	static get aes192gcm16(): (
		nonce: AllowSharedBufferSource,
	) => Readonly<ContentEncryptionAlgorithmIdentifier> {
		return (nonce: AllowSharedBufferSource) =>
			new this(
				new Asn1Object(OID_NISTALGO_AES_AES192GCM),
				new Asn1Sequence([
					// aes-nonce
					new Asn1OctetString(nonce),
					// AES-GCM-ICVlen
					new Asn1Integer(0x10),
				]),
			);
	}
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
	static get rsaOaepWithRfc8017DefaultParams() {
		if (!rsaOaepWithRfc8017DefaultParams) {
			rsaOaepWithRfc8017DefaultParams = new this(
				new Asn1Object(OID_PKCS1_IDRSAESOAEP),
				new Asn1Sequence([]),
			);
		}
		return rsaOaepWithRfc8017DefaultParams;
	}
	static get rsaOaepWithSha256Mgf1Sha256Empty(): Readonly<ContentEncryptionAlgorithmIdentifier> {
		if (!rsaOaepWithSha256Mgf1Sha256Empty) {
			rsaOaepWithSha256Mgf1Sha256Empty = new this(
				new Asn1Object(OID_PKCS1_IDRSAESOAEP),
				new Asn1Sequence([
					// hashAlgorithm
					new Asn1ContextSpecific(
						0,
						DigestAlgorithmIdentifier.sha256,
						true,
					),
					// maskGenAlgorithm
					new Asn1ContextSpecific(
						1,
						new Asn1Sequence([
							new Asn1Object(OID_PKCS1_IDMGF1),
							DigestAlgorithmIdentifier.sha256,
						]),
						true,
					),
					// pSourceAlgorithm DEFAULT pSpecifiedEmpty
				]),
			);
		}
		return rsaOaepWithSha256Mgf1Sha256Empty;
	}
	static get rsaOaepWithSha384Mgf1Sha384Empty(): Readonly<ContentEncryptionAlgorithmIdentifier> {
		if (!rsaOaepWithSha384Mgf1Sha384Empty) {
			rsaOaepWithSha384Mgf1Sha384Empty = new this(
				new Asn1Object(OID_PKCS1_IDRSAESOAEP),
				new Asn1Sequence([
					// hashAlgorithm
					new Asn1ContextSpecific(
						0,
						DigestAlgorithmIdentifier.sha384,
						true,
					),
					// maskGenAlgorithm
					new Asn1ContextSpecific(
						1,
						new Asn1Sequence([
							new Asn1Object(OID_PKCS1_IDMGF1),
							DigestAlgorithmIdentifier.sha384,
						]),
						true,
					),
					// pSourceAlgorithm DEFAULT pSpecifiedEmpty
				]),
			);
		}
		return rsaOaepWithSha384Mgf1Sha384Empty;
	}
	static get rsaOaepWithSha512Mgf1Sha512Empty(): Readonly<ContentEncryptionAlgorithmIdentifier> {
		if (!rsaOaepWithSha512Mgf1Sha512Empty) {
			rsaOaepWithSha512Mgf1Sha512Empty = new this(
				new Asn1Object(OID_PKCS1_IDRSAESOAEP),
				new Asn1Sequence([
					// hashAlgorithm
					new Asn1ContextSpecific(
						0,
						DigestAlgorithmIdentifier.sha512,
						true,
					),
					// maskGenAlgorithm
					new Asn1ContextSpecific(
						1,
						new Asn1Sequence([
							new Asn1Object(OID_PKCS1_IDMGF1),
							DigestAlgorithmIdentifier.sha512,
						]),
						true,
					),
					// pSourceAlgorithm DEFAULT pSpecifiedEmpty
				]),
			);
		}
		return rsaOaepWithSha512Mgf1Sha512Empty;
	}
}

export default ContentEncryptionAlgorithmIdentifier;
