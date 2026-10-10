"""Raw sector-level access to a disk image (or block device).

Works on `dd`-style images, e.g. created with:
    adb shell "su -c 'dd if=/dev/block/mmcblk0'" | dd of=phone.img
or pulled from a rooted device. Sector size is usually 512 or 4096.
"""
import os


class SectorReader:
    def __init__(self, path, sector_size=512):
        self.path = path
        self.sector_size = sector_size
        self._f = open(path, "rb")
        self._f.seek(0, os.SEEK_END)
        self.size = self._f.tell()
        self.sector_count = self.size // sector_size

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read_sector(self, n):
        """Return sector n as bytes (raises IndexError past the end)."""
        if n < 0 or n >= self.sector_count:
            raise IndexError("sector %d out of range (0..%d)" % (n, self.sector_count - 1))
        self._f.seek(n * self.sector_size)
        return self._f.read(self.sector_size)

    def read_range(self, offset, length):
        """Read an arbitrary byte range."""
        if offset < 0 or offset + length > self.size:
            raise IndexError("range out of bounds")
        self._f.seek(offset)
        return self._f.read(length)

    def iter_chunks(self, chunk_size=1024 * 1024, overlap=64 * 1024):
        """Yield (offset, bytes) windows; overlap keeps signatures split across
        chunk borders detectable."""
        step = chunk_size - overlap
        offset = 0
        while offset < self.size:
            yield offset, self.read_range(offset, min(chunk_size, self.size - offset))
            if offset + chunk_size >= self.size:
                break
            offset += step
