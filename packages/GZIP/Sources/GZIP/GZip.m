#import "GZip.h"


#import <limits.h>
#import <zlib.h>

bool TGIsGzippedData(NSData *data) {
    const UInt8 *bytes = (const UInt8 *)data.bytes;
    return (data.length >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b);
}

NSData *TGGZipData(NSData *data, float level) {
    if (data.length == 0 || TGIsGzippedData(data)) {
        return data;
    }
    
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = (uint)data.length;
    stream.next_in = (Bytef *)(void *)data.bytes;
    stream.total_out = 0;
    stream.avail_out = 0;
    
    static const NSUInteger ChunkSize = 16384;
    
    NSMutableData *output = nil;
    int compression = (level < 0.0f) ? Z_DEFAULT_COMPRESSION : (int)(roundf(level * 9));
    if (deflateInit2(&stream, compression, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
        output = [NSMutableData dataWithLength:ChunkSize];
        while (stream.avail_out == 0) {
            if (stream.total_out >= output.length) {
                output.length += ChunkSize;
            }
            stream.next_out = (uint8_t *)output.mutableBytes + stream.total_out;
            stream.avail_out = (uInt)(output.length - stream.total_out);
            deflate(&stream, Z_FINISH);
        }
        deflateEnd(&stream);
        output.length = stream.total_out;
    }
    
    return output;
}

NSData * _Nullable TGGUnzipData(NSData *data, uint sizeLimit)
{
    if (data.length == 0 || data.length > UINT_MAX || !TGIsGzippedData(data)) {
        return nil;
    }
    
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = (uInt)data.length;
    stream.next_in = (Bytef *)data.bytes;
    stream.total_out = 0;
    stream.avail_out = 0;
    
    NSMutableData *output = nil;
    if (inflateInit2(&stream, 47) == Z_OK) {
        static const NSUInteger ChunkSize = 16384;
        Bytef overflowByte = 0;
        int status = Z_OK;
        BOOL exceededLimit = NO;
        output = [NSMutableData data];
        while (status == Z_OK) {
            if (sizeLimit > 0 && stream.total_out >= sizeLimit) {
                stream.next_out = &overflowByte;
                stream.avail_out = 1;
            } else {
                NSUInteger chunkSize = ChunkSize;
                if (sizeLimit > 0) {
                    uLong remaining = (uLong)sizeLimit - stream.total_out;
                    chunkSize = (NSUInteger)MIN((uLong)chunkSize, remaining);
                }
                if (stream.total_out > NSUIntegerMax - chunkSize) {
                    status = Z_MEM_ERROR;
                    break;
                }
                output.length = (NSUInteger)stream.total_out + chunkSize;
                stream.next_out = (Bytef *)output.mutableBytes + stream.total_out;
                stream.avail_out = (uInt)chunkSize;
            }
            status = inflate(&stream, Z_SYNC_FLUSH);
            if (sizeLimit > 0 && stream.total_out > sizeLimit) {
                exceededLimit = YES;
                break;
            }
        }
        int endStatus = inflateEnd(&stream);
        if (!exceededLimit && status == Z_STREAM_END && endStatus == Z_OK) {
            output.length = (NSUInteger)stream.total_out;
        } else {
            output = nil;
        }
    }
    
    return output;
}

