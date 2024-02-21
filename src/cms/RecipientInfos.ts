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
import RecipientInfo from './RecipientInfo.js';

class RecipientInfos extends Asn1Set {
	kinds_: Set<RecipientInfo['kind']>;
	versions_: Set<RecipientInfo['version']>;

	constructor(recipientInfos: RecipientInfo[]) {
		super(recipientInfos);
		const kindsSet = new Set<RecipientInfo['kind']>();
		const versionsSet = new Set<RecipientInfo['version']>();

		recipientInfos.forEach((recipientInfo) => {
			kindsSet.add(recipientInfo.kind);
			versionsSet.add(recipientInfo.version);
		});
		this.kinds_ = kindsSet;
		this.versions_ = versionsSet;
	}

	get kinds(): Readonly<typeof this.kinds_> {
		return this.kinds_;
	}

	get versions(): Readonly<typeof this.versions_> {
		return this.versions_;
	}
}

export default RecipientInfos;
