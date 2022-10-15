#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <time.h>
#include <inttypes.h> // for uint64_t

#include "zipcrypto.h"

#define WRITEBUFFERSIZE (16384)
#define MAXFILENAME (256)

#define Z_BUFSIZE (64 * 1024)
#define VersionMadeBy (45)
#define VersionNeeded (45)

#define ZIP_OK                          (0)
#define ZIP_EOF                         (0)
#define ZIP_ERRNO                       (Z_ERRNO)
#define ZIP_PARAMERROR                  (-102)
#define ZIP_BADZIPFILE                  (-103)
#define ZIP_INTERNALERROR               (-104)

#define LOCALHEADERMAGIC    (0x04034b50)
#define CENTRALHEADERMAGIC  (0x02014b50)
#define ENDHEADERMAGIC      (0x06054b50)
#define ZIP64ENDHEADERMAGIC      (0x06064b50)
#define ZIP64ENDLOCHEADERMAGIC   (0x07064b50)
#define ZIP64DATADESCHEADERMAGIC   (0x08074b50)

typedef unsigned int uInt;
typedef unsigned long uLong;

#define RAND_HEAD_LEN 12

typedef struct {
	char filename[256];
	unsigned long crc32;
	unsigned long flag;
	int method;
	int encrypt;
	int zip64;
	uint64_t pos_zip64extrainfo;
	uint64_t totalCompressedData;
	uint64_t totalUncompressedData;
	uint64_t LocHdrSize;
	uint64_t loc_offset; // Relative offset of local file header for CEN
	uint64_t cen_offset; // Offset of start of central directory, relative to start of archive for EOCD
	union {
		uint16_t mod_time;
		struct {
			unsigned tm_sec:5;
			unsigned tm_min:6;
			unsigned tm_hour:5;
		};
	};
	union {
		uint16_t mod_date;
		struct {
			unsigned tm_mday:5;
			unsigned tm_mon:4;
			unsigned tm_year:7;
		};
	};
	uint16_t verifier;

	uint32_t crcForCrypting;
	uint32_t keys[3];	 /* keys defining the pseudo-random sequence */
	unsigned crypt_header_size;
} zip_entry_info;

typedef struct {
	z_stream stream;
	uInt number_entry;
	int cur_entry;
	zip_entry_info entry[128];
	char out_zip[256];
	uLong cur_offset;
	uLong size_centraldir;
	unsigned char buffered_data[Z_BUFSIZE];
	uInt pos_in_buffered_data;
	uLong Zip64EOCDRecord_offset;

	// output zip file function pointer
	size_t (*write)(char *buf, uLong size, void *zi);
} zip64_info;

uint16_t get_verifier(zip64_info *zi)
{
	zip_entry_info *zei = &zi->entry[zi->cur_entry];
	uint32_t crc = zei->crcForCrypting;
	uint32_t dos_date = zei->mod_date << 16 | zei->mod_time;

	/* Info-ZIP: ZipCrypto format: if bit 3 of flag is set, we use
	 * high byte of 16-bit File time_t
	 */
	if (zei->flag & (1 << 3)) {
		printf("flag3 is set\n");
		return ((dos_date >> 16) & 0xff) << 8 | ((dos_date >> 8) & 0xff);
	}
	return ((crc >> 16) & 0xff) << 8 | ((crc >> 24) & 0xff);
}

void get_file_time(zip64_info *zi, char *filenameinzip)
{
	struct stat attr;
	/* time_t st_mtime; */
	struct tm *p;
	zip_entry_info *zei = NULL;

	stat(filenameinzip, &attr);
	/* st_mtime = attr.st_mtime; */
	p = localtime(&attr.st_mtime);

	zei = &zi->entry[zi->cur_entry];

	zei->tm_sec = (p->tm_sec / 2); // zip use 2 second precision
	zei->tm_min = p->tm_min;
	zei->tm_hour = p->tm_hour;
	zei->tm_mday = p->tm_mday;
	zei->tm_mon = p->tm_mon + 1; // st_mtime month range[0-11]
	zei->tm_year = p->tm_year + 1900 - 1980; // st_mtime year start at 1900, zip start at 1980

	printf("ppsec: %d\n", p->tm_sec);
	printf("ppmin: %d\n", p->tm_min);
	printf("pphour: %d\n", p->tm_hour);
	printf("ppmday: %d\n", p->tm_mday);
	printf("ppmon: %d\n", p->tm_mon);
	printf("ppyear: %d\n", p->tm_year);

	printf("sec: %u\n", zei->tm_sec);
	printf("min: %u\n", zei->tm_min);
	printf("hour: %u\n", zei->tm_hour);
	printf("mday: %u\n", zei->tm_mday);
	printf("mon: %u\n", zei->tm_mon);
	printf("year: %u\n", zei->tm_year);
}

size_t out_zip_write(char *buf, uLong size, void *zi)
{
	FILE *fout;
	size_t ret;
	zip64_info *zi_local = (zip64_info *)zi;

	fout = fopen(zi_local->out_zip, "ab+");
	if (fout == NULL) {
		printf("Cannot open %s\n", zi_local->out_zip);
		exit(0);
	}

	ret = fwrite(buf, 1, size, fout);
	fclose(fout);

	zi_local->cur_offset += size;

	return ret;
}

int zip64local_putValue(char *outbuf, uint64_t x, int nbByte)
{
	unsigned char buf[8];
	int n;
	for (n = 0; n < nbByte; n++) {
		buf[n] = (unsigned char) (x & 0xff);
		x >>= 8;
	}
	if (x != 0) {
		for (n = 0; n < nbByte; n++) {
			buf[n] = 0xff;
		}
	}
	memcpy(outbuf, buf, nbByte);
	return 0;
}


int Write_EncryptHeader(zip64_info *zi, char *password)
{

	int err = Z_OK;
	zip_entry_info *zei = &zi->entry[zi->cur_entry];

	zei->crypt_header_size = 0;
	if ((err == Z_OK) && (password != NULL)) {
		uint8_t header[RAND_HEAD_LEN];
		unsigned int HdrSize;

		HdrSize = encrypt_init(header, zei->keys, password, zei->verifier);
		zei->crypt_header_size = HdrSize;

		size_t ret = zi->write(header, HdrSize, zi);
		if (ret != HdrSize) {
			printf("encrypt header write fail, ret: %d, HdrSize: %d\n", ret, HdrSize);
			exit(0);
		}
	}
	return ZIP_OK;
}

int Write_LocalFileHeader(zip64_info *zi, char *filenameinzip, int level, char *password)
{
	int err;
	char *LocalFileHdr = NULL;
	char *cur;
	uInt size_extrafield = 2 + 2 + 16; // hdr + size + uncompress_size + compress_size for zip64
	uLong flag = 0;

	if (password)
		flag |= 1;

	if (level == Z_BEST_SPEED)
		flag |= 6;
	flag |= 8; // set bit 3, because we don't know the size and crc when we write local hdr

	LocalFileHdr = malloc(128);
	cur = LocalFileHdr;

	uInt size_filename = (uInt)strlen(filenameinzip);

	err = zip64local_putValue(cur, LOCALHEADERMAGIC, 4); // LocalFileHdr magic number
	cur += 4;

	err = zip64local_putValue(cur, 45, 2); // version 4.5 support zip64
	cur += 2;

	err = zip64local_putValue(cur, flag, 2);
	cur += 2;

	err = zip64local_putValue(cur, Z_DEFLATED, 2);
	cur += 2;

	err = zip64local_putValue(cur, zi->entry[zi->cur_entry].mod_time, 2); // Mod:time
	cur += 2;

	err = zip64local_putValue(cur, zi->entry[zi->cur_entry].mod_date, 2); // Mod:date
	cur += 2;

	// CRC / Compressed size / Uncompressed size will be filled in later and rewritten later
	err = zip64local_putValue(cur, (uLong)0, 4); /* crc 32, unknown */
	cur += 4;

	err = zip64local_putValue(cur, (uLong)0xFFFFFFFF, 4); /* compressed size, unknown */
	cur += 4;

	err = zip64local_putValue(cur, (uLong)0xFFFFFFFF, 4); /* uncompressed size, unknown */
	cur += 4;

	err = zip64local_putValue(cur, size_filename, 2);
	cur += 2;

	err = zip64local_putValue(cur, (uLong)size_extrafield, 2);
	cur += 2;

	if (size_filename > 0) {
		memcpy(cur, filenameinzip, size_filename);
		cur += size_filename;
	}

	// Add Extra Information Header for 'ZIP64 information'
	// zip64 extende information extra field
	short HeaderID = 1;
	short DataSize = 16;
	uint64_t CompressedSize = 0;
	uint64_t UncompressedSize = 0;
	zip64local_putValue(cur, HeaderID, 2); // HeaderID
	cur += 2;

	zip64local_putValue(cur, DataSize, 2); // DataSize
	cur += 2;

	zip64local_putValue(cur, UncompressedSize, 8);
	cur += 8;

	zip64local_putValue(cur, CompressedSize, 8);
	cur += 8;

	strncpy(zi->entry[zi->cur_entry].filename, filenameinzip, size_filename);
	zi->entry[zi->cur_entry].flag = flag;
	zi->entry[zi->cur_entry].method = Z_DEFLATED;
	zi->entry[zi->cur_entry].zip64 = 1;

	if (flag & 0x1)
		zi->entry[zi->cur_entry].encrypt = 1;
	else
		zi->entry[zi->cur_entry].encrypt = 0;

	zi->entry[zi->cur_entry].loc_offset = zi->cur_offset;
	zi->entry[zi->cur_entry].LocHdrSize = cur - LocalFileHdr;
	/* zi->cur_offset += zi->entry[zi->cur_entry].LocHdrSize; */
	/* zi->entry[zi->cur_entry].=; */
	/* zi->entry[zi->cur_entry].=; */

	size_t ret = zi->write(LocalFileHdr, zi->entry[zi->cur_entry].LocHdrSize, zi);
	free(LocalFileHdr);
	/* zi->zi->cur_entry++; */
	/* zi->number_entry++; */

	return ZIP_OK;
}

int Write_DataDescriptor(zip64_info *zi)
{
	char *buf = malloc(128);

	char *cur = buf;

	zip64local_putValue(cur, ZIP64DATADESCHEADERMAGIC, 4);
	cur += 4;

	zip64local_putValue(cur, zi->entry[zi->cur_entry].crc32, 4);
	cur += 4;

	zip64local_putValue(cur, zi->entry[zi->cur_entry].totalCompressedData, 8);
	cur += 4;

	zip64local_putValue(cur, zi->entry[zi->cur_entry].totalUncompressedData, 8);
	cur += 4;

	size_t ret = zi->write(buf, cur - buf, zi);
	if (ret != cur - buf) {
		printf("data descript fail, ret: %d, size: %d\n", ret, cur - buf);
		exit(0);
	}
	return ret;
}
int Write_CentralFileHeader(zip64_info *zi)
{
	int i;
	char *cur = NULL;
	char *CentralDirFileHdr = NULL;
	uLong invalidValue = 0xffffffff;

	CentralDirFileHdr = malloc(128);

	for (i = 0; i < zi->number_entry; i++) {
		cur = CentralDirFileHdr;

		zip64local_putValue(cur, CENTRALHEADERMAGIC, 4);
		cur += 4;

		zip64local_putValue(cur, VersionMadeBy, 2);
		cur += 2;

		zip64local_putValue(cur, VersionNeeded, 2);
		cur += 2;

		zip64local_putValue(cur, zi->entry[i].flag, 2);
		cur += 2;

		zip64local_putValue(cur, zi->entry[i].method, 2);
		cur += 2;

		zip64local_putValue(cur, zi->entry[i].mod_time, 2); // Mod:time
		cur += 2;

		zip64local_putValue(cur, zi->entry[i].mod_date, 2); // Mod:date
		cur += 2;

		zip64local_putValue(cur, zi->entry[i].crc32, 4);
		cur += 4;

		// Compressed size
		// set 0xffffffff for zip64, real compressed size is set in CentralDirFileHdr extra field
		zip64local_putValue(cur, invalidValue, 4);
		cur += 4;

		// Uncompressed size
		// set 0xffffffff for zip64, real Uncompressed size is set in CentralDirFileHdr extra field
		zip64local_putValue(cur, invalidValue, 4);
		cur += 4;

		// File name length
		zip64local_putValue(cur, strlen(zi->entry[i].filename), 2);
		cur += 2;

		// Extra field length
		zip64local_putValue(cur, 2 + 2 + 8 + 8 + 8, 2); // HdrID + SizeOfExtraFieldTrunk + UncompressedDataSize + CompressedSize + OffsetOfLocalHdrRecord
		cur += 2;

		// File comment length
		zip64local_putValue(cur, 0, 2);
		cur += 2;

		// Disk nyumber where file starts
		zip64local_putValue(cur, 0, 2); // 0xffff for zip64, but if we set 0xffff, we need to add disk number in extra field
		cur += 2;

		// Internal file attribute
		zip64local_putValue(cur, 0, 2);
		cur += 2;

		// External file attributes
		zip64local_putValue(cur, 0, 4);
		cur += 4;

		// Relative offset of local file hader
		zip64local_putValue(cur, invalidValue, 4);
		cur += 4;

		// File name
		memcpy(cur, zi->entry[i].filename, strlen(zi->entry[i].filename));
		cur += strlen(zi->entry[i].filename);

		// Extra field
		// Add Extra Information Header for 'ZIP64 information'
		// zip64 extende information extra field
		zip64local_putValue(cur, 0x0001, 2);
		cur += 2;

		zip64local_putValue(cur, 8 + 8 + 8, 2); // UncompressedDataSize + CompressedSize + OffsetOfLocalHdrRecord
		cur += 2;

		zip64local_putValue(cur, zi->entry[i].totalUncompressedData, 8);
		cur += 8;

		zip64local_putValue(cur, zi->entry[i].totalCompressedData, 8);
		cur += 8;

		zip64local_putValue(cur, zi->entry[i].loc_offset, 8);
		cur += 8;

		if (i == 0)
			zi->entry[i].cen_offset = zi->cur_offset; // save Offset of start of central directory

		size_t ret = zi->write(CentralDirFileHdr, cur - CentralDirFileHdr, zi);
		if (ret != cur - CentralDirFileHdr) {
			printf("not match size, ret: %d, central size: %d\n", ret, cur-CentralDirFileHdr);
			exit(0);
		}
		zi->size_centraldir += (cur - CentralDirFileHdr);
		memset(CentralDirFileHdr, 0, sizeof(CentralDirFileHdr));
	}
	free(CentralDirFileHdr);

	return ZIP_OK;
}

int Write_Zip64EOCDRecord(zip64_info *zi)
{
	int err = ZIP_OK;
	uLong Zip64DataSize = 44;
	char *cur = NULL;
	char *Zip64EOCDRecord= NULL;

	Zip64EOCDRecord = malloc(128);
	if (Zip64EOCDRecord == NULL) {
		printf("Zip64EOCDRecord fail\n");
		exit(0);
	}
	cur = Zip64EOCDRecord;

	err = zip64local_putValue(cur, (uLong)ZIP64ENDHEADERMAGIC, 4); // Zip64 EOCD record magic number
	cur += 4;

	err = zip64local_putValue(cur, Zip64DataSize, 8); // size of the EOCD64 minus 12
	cur += 8;

	err = zip64local_putValue(cur, VersionMadeBy, 2);
	cur += 2;

	err = zip64local_putValue(cur, VersionNeeded, 2);
	cur += 2;

	// Number of this disk
	err = zip64local_putValue(cur, 0, 4);
	cur += 4;

	/* number of the disk with the start of the central directory */
	err = zip64local_putValue(cur, 0, 4);
	cur += 4;

	/* total number of entries in the central dir on this disk */
	err = zip64local_putValue(cur, zi->number_entry, 8);
	cur += 8;

	/* total number of entries in the central dir */
	err = zip64local_putValue(cur, zi->number_entry, 8);
	cur += 8;

	/* size of the central directory */
	err = zip64local_putValue(cur, zi->size_centraldir, 8);
	cur += 8;

	/* offset of start of central directory with respect to the starting disk number */
	err = zip64local_putValue(cur, zi->entry[0].cen_offset, 8);
	cur += 8;

	zi->Zip64EOCDRecord_offset = zi->cur_offset;
	zi->write(Zip64EOCDRecord, cur - Zip64EOCDRecord, zi);

	free(Zip64EOCDRecord);
	return err;
}

int Write_Zip64EOCDLocator(zip64_info *zi)
{
	int err = ZIP_OK;
	char *cur = NULL;
	char *Zip64EOCDLocator = NULL;

	Zip64EOCDLocator = malloc(128);
	if (Zip64EOCDLocator == NULL) {
		printf("Zip64EOCDLocator fail\n");
		exit(0);
	}
	cur = Zip64EOCDLocator;

	// Zip64 EOCD Locator magic number
	err = zip64local_putValue(cur, (uLong)ZIP64ENDLOCHEADERMAGIC, 4);
	cur += 4;

	// num of disks with the start of zip64 EOCD
	err = zip64local_putValue(cur, (uLong)0, 4);
	cur += 4;

	// Relative offset to the Zip64EndOfCentralDirectory
	err = zip64local_putValue(cur, (uLong)zi->Zip64EOCDRecord_offset, 8);
	cur += 8;

	// total number of disks
	err = zip64local_putValue(cur, (uLong)1, 4);
	cur += 4;

	size_t ret = zi->write(Zip64EOCDLocator, cur - Zip64EOCDLocator, zi);
	if (ret != (cur - Zip64EOCDLocator)) {
		printf("Locator write fail\n");
		exit(0);
	}

	free(Zip64EOCDLocator);

	return err;
}

int Write_EOCDRecord(zip64_info *zi)
{
	int err = ZIP_OK;
	char *cur = NULL;
	char *EOCDRecord = NULL;

	EOCDRecord = malloc(128);
	if (EOCDRecord == NULL) {
		printf("EOCDRecord fail\n");
		exit(0);
	}
	cur = EOCDRecord;

	// EOCD record magic number
	err = zip64local_putValue(cur, (uLong)ENDHEADERMAGIC, 4);
	cur += 4;

	// num of this disk
	err = zip64local_putValue(cur, 0, 2); // can fill with 0xffff or 0
	cur += 2;

	/* number of the disk with the start of the central directory */
	err = zip64local_putValue(cur, 0, 2); // can fill with 0xffff or 0
	cur += 2;

	/* number of entries in the central dir on this disk */
	err = zip64local_putValue(cur, zi->number_entry, 2); // can fill with 0xffff
	cur += 2;

	/* total number of entries in the central dir */
	err = zip64local_putValue(cur, zi->number_entry, 2); // can fill with 0xffff
	cur += 2;

	/* size of the central directory */
	err = zip64local_putValue(cur, zi->size_centraldir, 4); // can fill with 0xffffffff
	cur += 4;

	/* offset of start of central directory with respect to the starting disk number */
	err = zip64local_putValue(cur, zi->entry[0].cen_offset, 4); // can fill with 0xffffffff
	cur += 4;

	// comment length
	err = zip64local_putValue(cur, 0, 2); // can fill with 0xffff
	cur += 2;

	zi->write(EOCDRecord, cur - EOCDRecord, zi);

	free(EOCDRecord);
	return err;
}
void InitZipStruct(zip64_info *zi, char *out_zip_filename, bool init)
{
	if (init) {
		memset(zi, 0, sizeof(*zi));
		zi->write = out_zip_write;
		strcpy(zi->out_zip, out_zip_filename);
	}

	memset(&zi->stream, 0, sizeof(zi->stream));
	zi->stream.avail_in = (uInt)0;
	zi->stream.avail_out = (uInt)Z_BUFSIZE;
	zi->stream.next_out = zi->buffered_data;
	zi->stream.total_in = 0;
	zi->stream.total_out = 0;
	zi->stream.data_type = Z_BINARY;

	// We now only support Z_DEFLATED compression method
	if (true || Z_DEFLATED) {
		int windowBits = 15;
		/* int GZIP_ENCODING = 16; */

		zi->stream.zalloc = (alloc_func)0;
		zi->stream.zfree = (free_func)0;
		zi->stream.opaque = (voidpf)0;

		/* if (deflateInit2(&zi->stream, Z_BEST_SPEED, Z_DEFLATED, */
		/* 			windowBits | GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY) != Z_OK) { */
		if (deflateInit2(&zi->stream, Z_BEST_SPEED, Z_DEFLATED,
					-windowBits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
			printf("deflatinit2 fail\n");
			exit(0);
		}
	}

	return zi;
}

static int getFileCrc(char *filenameinzip, void *buf, unsigned long size_buf, unsigned long *result_crc)
{
	unsigned long calculate_crc = 0;
	int err = ZIP_OK;
	FILE *fin = fopen(filenameinzip, "rb");

	unsigned long size_read = 0;
	unsigned long total_read = 0;

	if (fin == NULL) {
		printf("fopen fail\n");
		exit(0);
	}
	do {
		size_read = fread(buf, 1, size_buf, fin);
		if (size_read < size_buf)
			if (feof(fin) == 0) {
				printf("error read %s\n", filenameinzip);
				exit(0);
			}
		if (size_read > 0)
			calculate_crc = crc32_z(calculate_crc, buf, size_read);
		total_read += size_read;
	} while (size_read > 0);

	if (fin)
		fclose(fin);

	*result_crc = calculate_crc;
	printf("file %s crc %lx\n", filenameinzip, calculate_crc);
	return ZIP_OK;
}

int zip64FlushWriteBuffer(zip64_info *zi)
{
	int err = ZIP_OK;

	if (zi->entry[zi->cur_entry].encrypt != 0) {
		printf("%s:%d\n", __func__, __LINE__);
		printf("pos_in_buffered_data: %d\n", zi->pos_in_buffered_data);
		uInt i;
		int t;
		for (i=0;i<zi->pos_in_buffered_data;i++) {
			/* printf("i:%d\n", i); */
			zi->buffered_data[i] = crypt_encode(zi->entry[zi->cur_entry].keys, zi->buffered_data[i], t);
		}
		printf("%s:%d\n", __func__, __LINE__);
	}
	size_t ret = zi->write(zi->buffered_data, zi->pos_in_buffered_data, zi);
	if (ret != zi->pos_in_buffered_data) {
		printf("write not match: ret: %ld, pos_in_buffered_data:%d\n", ret, zi->pos_in_buffered_data);
		exit(0);
	}
	printf("write match: ret: %ld, pos_in_buffered_data:%d\n", ret, zi->pos_in_buffered_data);
	zi->entry[zi->cur_entry].totalCompressedData += zi->pos_in_buffered_data;
	/* zi->cur_offset += zi->pos_in_buffered_data; */

	zi->entry[zi->cur_entry].totalUncompressedData += zi->stream.total_in;
	printf("totalUncompressedData: %lu\n", zi->entry[zi->cur_entry].totalUncompressedData);
	zi->stream.total_in = 0;

	zi->pos_in_buffered_data = 0;

	return err;
}

int zipWriteInFileInZip(zip64_info *zi, void *buf, unsigned int len)
{
	int err = ZIP_OK;

	zi->entry[zi->cur_entry].crc32 = crc32(zi->entry[zi->cur_entry].crc32, buf, (uInt)len); // crc for uncompress data
	zi->stream.next_in = (unsigned char *)buf;
	zi->stream.avail_in = len;

	while (zi->stream.avail_in > 0) {
		printf("avail_in: %d\n", zi->stream.avail_in);
		if (zi->stream.avail_out == 0) {
			printf("11111\n");
			if (zip64FlushWriteBuffer(zi) == ZIP_ERRNO)
				err = ZIP_ERRNO;
			zi->stream.avail_out = (uInt)Z_BUFSIZE;
			zi->stream.next_out = zi->buffered_data;
		}
		if (err != ZIP_OK)
			break;

		if (zi->entry[zi->cur_entry].method == Z_DEFLATED) {
			printf("22222");
			uLong uTotalOutBefore = zi->stream.total_out;
			err = deflate(&zi->stream, Z_NO_FLUSH);
			printf("err: %d\n", err);
			printf("avail out: %d\n", zi->stream.avail_out);
			printf("avail in: %d\n", zi->stream.avail_in);
			printf("total out: %d\n", zi->stream.total_out);
			if (uTotalOutBefore > zi->stream.total_out) {
				int bBreak = 0;
				bBreak++;
			}
			zi->pos_in_buffered_data += (uInt)(zi->stream.total_out - uTotalOutBefore);
		}
	}
	/* zip64FlushWriteBuffer(zi); */
	return err;
}

int zipCloseFileInZip(zip64_info *zi)
{
	int err = ZIP_OK;

	zi->stream.avail_in = 0;
	if (true || zi->entry[zi->cur_entry].method == Z_DEFLATED) {
		while (err == ZIP_OK) {
			printf("33333\n");
			uLong uTotalOutBefore;
			if (zi->stream.avail_out == 0) {
				if (zip64FlushWriteBuffer(zi) == ZIP_ERRNO)
					err = ZIP_ERRNO;
				zi->stream.avail_out = (uInt)Z_BUFSIZE;
				zi->stream.next_out = zi->buffered_data;
			}
			uTotalOutBefore = zi->stream.total_out;
			err = deflate(&zi->stream, Z_FINISH);
			printf("z_finish : %d\n", err);
			zi->pos_in_buffered_data += (uInt)zi->stream.total_out - uTotalOutBefore;
		}
	}
	printf("%s:%d\n", __func__, __LINE__);
	if (err == Z_STREAM_END)
		err = ZIP_OK; // This is normal
	else {
		printf("%s zip finish fail\n", zi->entry[zi->cur_entry].filename);
		exit(0);
	}
	printf("%s:%d\n", __func__, __LINE__);

	// Write Z_FINISH metadata and the last part of data
	if (zi->pos_in_buffered_data > 0 && err == ZIP_OK) {
		printf("%s:%d\n", __func__, __LINE__);
		if (zip64FlushWriteBuffer(zi) == ZIP_ERRNO) {
			printf("after finish still has data %s\n", zi->entry[zi->cur_entry].filename);
			exit(0);
		}
		printf("%s:%d\n", __func__, __LINE__);
	}
	if (zi->entry[zi->cur_entry].method == Z_DEFLATED) {
		int tmp_err = deflateEnd(&zi->stream);
		if (err == ZIP_OK)
			err = tmp_err;
	}

	printf("%s:%d\n", __func__, __LINE__);
	zi->entry[zi->cur_entry].totalCompressedData += zi->entry[zi->cur_entry].crypt_header_size;

	printf("%s: ret: %d\n", __func__, err);
	return err;
}

int main(int argc, char *argv[])
{
	size_t size_buf = 0;
	void *buf = NULL;
	int zipfilenamearg = 0;
	int i;
	zip64_info *zi;
	char filename_try[256] = {0};
	int err = 0;
	char *password = "1234";
	// password = NULL;

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			if (zipfilenamearg == 0) {
				zipfilenamearg = i;
				strcpy(filename_try, argv[zipfilenamearg]);
			}
		}
	} else {
		printf("argc need to be > 1\n");
		return -1;
	}

	zi = malloc(sizeof(*zi));
	InitZipStruct(zi, filename_try, true);
	for (i = zipfilenamearg+1; i < argc && err == ZIP_OK; i++) {
		FILE *fin;
		size_t size_read;
		char *filenameinzip = argv[i];
		char *savefilenameinzip;
		unsigned long crcFile = 0;

		InitZipStruct(zi, filename_try, false);
		size_buf = WRITEBUFFERSIZE;
		buf = (void *)malloc(size_buf);
		if (buf == NULL) {
			printf("Error allocating memory\n");
			return -1;
		}

		get_file_time(zi, filenameinzip);

		/* err = getFileCrc(filenameinzip, buf, size_buf, &zi->entry[zi->cur_entry].crcForCrypting); */

		Write_LocalFileHeader(zi, filenameinzip, Z_BEST_SPEED, password); // Add local header for this entry

		zi->entry[zi->cur_entry].verifier = get_verifier(zi);

		Write_EncryptHeader(zi, password);
		/* zi->entry[zi->cur_entry-1].crc32 = crcFile; */
		/* struct stat st; */
		/* stat(filenameinzip, &st); */
		/* zi->entry[zi->cur_entry-1].UncompressedDataSize = st.size; */


		fin = fopen(filenameinzip, "rb");
		if (fin == NULL) {
			printf("error in opening %s\n", filenameinzip);
			return -1;
		}
		do {
			err = ZIP_OK;
			size_read = fread(buf, 1, size_buf, fin);
			if (size_read < size_buf)
				if (feof(fin) == 0) {
					printf("error read %s\n", filenameinzip);
					return -1;
				}
			if (size_read > 0) {
				printf("size_read: %d,buf: %s\n", size_read, buf);
				err = zipWriteInFileInZip(zi, buf, (unsigned)size_read);
				printf("zipWrite: err: %d\n", err);
				if (err < 0) {
					printf("error in writing %s\n", filenameinzip);
					return -1;
				}
			}
		} while ((err == ZIP_OK) && size_read > 0);

		if (fin)
			fclose(fin);

		if (err < 0) {
			printf("something wrong\n");
			exit(0);
		}

		err = zipCloseFileInZip(zi);
		if (err != ZIP_OK) {
			printf("error in closing %s file\n", filenameinzip);
			exit(0);
		}
		Write_DataDescriptor(zi);

		zi->number_entry++;
		zi->cur_entry++;
	}


	// Add CentralDirFileHdr
	printf("write central header\n");
	err = Write_CentralFileHeader(zi);

	// Add ZIP64 EOCD record
	err = Write_Zip64EOCDRecord(zi);

	// Add Zip64 EOCD Locator
	err = Write_Zip64EOCDLocator(zi);

	// Add EOCD record
	err = Write_EOCDRecord(zi);

	printf("zip finish\n");

	return 0;
}
