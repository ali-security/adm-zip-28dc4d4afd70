"use strict";

const zlib = require("zlib");
const { expect } = require("chai");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of payload. `crc` defaults to a deliberately
// wrong value, because the allocation used to happen before the crc check.
function craftBomb(declaredSize, method, content, crc) {
    const name = Buffer.from("a");
    crc = crc || 0;
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    // Deterministic counterparts of the two RSS probes above: the entry carries a
    // valid payload with a matching crc, so decompression succeeds and the size of
    // the buffer handed back is directly observable. It must be the size of the
    // real data, never the declared one.
    it("sizes the STORED output from the real data, not the declared size", () => {
        const payload = Buffer.from("bounded");
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, payload, Utils.crc32(payload)));
        const data = zip.getEntries()[0].getData();

        expect(data.length).to.equal(payload.length);
        expect(data.equals(payload)).to.equal(true);
    });

    it("sizes the DEFLATED output from the inflated data, not the declared size", () => {
        const payload = Buffer.from("bounded");
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(payload), Utils.crc32(payload)));
        // readFile() is one of the public entry points named by the advisory
        const data = zip.readFile("a");

        expect(data.length).to.equal(payload.length);
        expect(data.equals(payload)).to.equal(true);
    });

    // The async read path (readFileAsync / extractAllToAsync / getDataAsync) shared
    // the very same eager allocation, so it needs its own regression guard.
    it("sizes the output from the real data on the async read path", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        let received = null;

        // invalid crc -> still throws, but the buffer it produced is bounded
        expect(() => zip.getEntries()[0].getDataAsync((data) => (received = data))).to.throw(/CRC32/);

        expect(received).to.not.equal(null);
        expect(received.length).to.equal(1);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});
