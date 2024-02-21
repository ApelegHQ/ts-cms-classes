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

import { Asn1Sequence } from '@exact-realty/asn1-der';
import CMSVersion from './CMSVersion.js';
import ContentType from './ContentType.js';
import type EncapsulatedContentInfo from './EncapsulatedContentInfo.js';
import type SignerInfos from './SignerInfos.js';

/*
   SignedData ::= SEQUENCE {
     version CMSVersion,
     digestAlgorithms DigestAlgorithmIdentifiers,
     encapContentInfo EncapsulatedContentInfo,
     certificates [0] IMPLICIT CertificateSet OPTIONAL,
     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
     signerInfos SignerInfos }
*/

/*
         IF ((certificates is present) AND
            (any certificates with a type of other are present)) OR
            ((crls is present) AND
            (any crls with a type of other are present))
         THEN version MUST be 5
         ELSE
            IF (certificates is present) AND
               (any version 2 attribute certificates are present)
            THEN version MUST be 4
            ELSE
               IF ((certificates is present) AND
                  (any version 1 attribute certificates are present)) OR
                  (any SignerInfo structures are version 3) OR
                  (encapContentInfo eContentType is other than id-data)
               THEN version MUST be 3
               ELSE version MUST be 1
*/

class SignedData extends Asn1Sequence {
	constructor(
		encapContentInfo: EncapsulatedContentInfo,
		signerInfos: SignerInfos,
	) {
		// Since certificates and CRLs are not implemented yet, the possible
		// values for version are only v3 or v1
		const version =
			Array.from(signerInfos.versions).some((v) => v.version === 3) ||
			encapContentInfo.eContentType !== ContentType.idData
				? CMSVersion.v3
				: CMSVersion.v1;

		super([
			version,
			signerInfos.digestAlgorithms,
			encapContentInfo,
			// certificates [0] IMPLICIT CertificateSet OPTIONAL,
			// crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
			signerInfos,
		]);
	}
}

export default SignedData;
