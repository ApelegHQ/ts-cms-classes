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

let v0: CMSVersion;
let v1: CMSVersion;
let v2: CMSVersion;
let v3: CMSVersion;
let v4: CMSVersion;
let v5: CMSVersion;

class CMSVersion extends Asn1Integer {
	version_: number;

	static get v0(): Readonly<CMSVersion> {
		if (!v0) {
			v0 = new this(0);
		}
		return v0;
	}
	static get v1(): Readonly<CMSVersion> {
		if (!v1) {
			v1 = new this(1);
		}
		return v1;
	}
	static get v2(): Readonly<CMSVersion> {
		if (!v2) {
			v2 = new this(2);
		}
		return v2;
	}
	static get v3(): Readonly<CMSVersion> {
		if (!v3) {
			v3 = new this(3);
		}
		return v3;
	}
	static get v4(): Readonly<CMSVersion> {
		if (!v4) {
			v4 = new this(4);
		}
		return v4;
	}
	static get v5(): Readonly<CMSVersion> {
		if (!v5) {
			v5 = new this(5);
		}
		return v5;
	}

	get version() {
		return this.version_;
	}

	private constructor(v: number) {
		super(v);
		this.version_ = v;
	}
}

export default CMSVersion;
