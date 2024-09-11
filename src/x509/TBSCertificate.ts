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

import type { IAsn1Data } from '@apeleghq/asn1-der';
import { Asn1ContextSpecific, Asn1Sequence } from '@apeleghq/asn1-der';
import type AlgorithmIdentifier from '../cms/AlgorithmIdentifier.js';
import SubjectPublicKeyInfo from '../pkcs10/SubjectPublicKeyInfo.js';
import type Name from '../x501/Name.js';
import type CertificateSerialNumber from './CertificateSerialNumber.js';
import Version from './Version.js';
import UniqueIdentifier from './UniqueIdentifier.js';
import Extensions from './Extensions.js';
import Validity from './Validity.js';

/*
   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }
*/

class TBSCertificate extends Asn1Sequence {
	constructor(
		serialNumber: CertificateSerialNumber,
		signature: AlgorithmIdentifier,
		issuer: Name,
		validity: Validity,
		subject: Name,
		subjectPublicKeyInfo: SubjectPublicKeyInfo,
		issuerUniqueID?: UniqueIdentifier,
		subjectUniqueID?: UniqueIdentifier,
		extensions?: Extensions,
	) {
		const version = extensions
			? Version.v3
			: issuerUniqueID || subjectUniqueID
				? Version.v2
				: Version.v1;
		const omit = {};
		super(
			[
				new Asn1ContextSpecific(0, version, false),
				serialNumber,
				signature,
				issuer,
				validity,
				subject,
				subjectPublicKeyInfo,
				issuerUniqueID
					? new Asn1ContextSpecific(1, issuerUniqueID, true)
					: omit,
				subjectUniqueID
					? new Asn1ContextSpecific(2, subjectUniqueID, true)
					: omit,
				extensions
					? new Asn1ContextSpecific(3, extensions, true)
					: omit,
			].filter((x: unknown): x is IAsn1Data => x !== omit),
		);
	}
}

export default TBSCertificate;
