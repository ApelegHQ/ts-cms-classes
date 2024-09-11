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

import { Asn1Integer } from '@apeleghq/asn1-der';

let v1: Version;
let v2: Version;
let v3: Version;

class Version extends Asn1Integer {
	static get v1(): Readonly<Version> {
		if (!v1) {
			v1 = new this(0);
		}
		return v1;
	}
	static get v2(): Readonly<Version> {
		if (!v1) {
			v2 = new this(1);
		}
		return v2;
	}
	static get v3(): Readonly<Version> {
		if (!v1) {
			v3 = new this(2);
		}
		return v3;
	}
	private constructor(v: number) {
		super(v);
	}
}

export default Version;
