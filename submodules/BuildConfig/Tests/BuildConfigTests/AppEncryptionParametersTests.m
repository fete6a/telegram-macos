#import <XCTest/XCTest.h>

#import <BuildConfig/BuildConfig.h>
#import <CryptoUtils/Crypto.h>
#import <MurMurHash32/MurMurHash32.h>
#import <string.h>

@interface DeviceSpecificEncryptionParameters (BuildConfigTests)

- (instancetype)initWithKey:(NSData *)key salt:(NSData *)salt;

@end

@interface AppEncryptionParameters (BuildConfigTests)

- (BOOL)writeEnvelopeData:(NSData *)data;

@end

@interface FailingMigrationEncryptionParameters : AppEncryptionParameters

@property (nonatomic) BOOL failWrites;

@end


@implementation FailingMigrationEncryptionParameters

- (BOOL)writeEnvelopeData:(NSData *)data {
    if (self.failWrites) {
        return NO;
    }
    return [super writeEnvelopeData:data];
}

@end


@interface AppEncryptionParametersTests : XCTestCase

@property (nonatomic, strong) NSMutableArray<NSString *> *rootPaths;

@end


@implementation AppEncryptionParametersTests

- (void)setUp {
    [super setUp];
    self.rootPaths = [[NSMutableArray alloc] init];
}

- (void)tearDown {
    for (NSString *path in self.rootPaths) {
        [NSFileManager.defaultManager removeItemAtPath:path error:nil];
    }
    [super tearDown];
}

- (NSString *)makeRootPath {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    NSError *error = nil;
    XCTAssertTrue([NSFileManager.defaultManager createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&error], @"%@", error);
    [self.rootPaths addObject:path];
    return path;
}

- (NSString *)envelopePathForRootPath:(NSString *)rootPath {
    return [rootPath stringByAppendingPathComponent:@".tempkeyEncrypted"];
}

- (DeviceSpecificEncryptionParameters *)fixtureParameters {
    NSMutableData *key = [[NSMutableData alloc] initWithLength:32];
    NSMutableData *salt = [[NSMutableData alloc] initWithLength:16];
    memset(key.mutableBytes, 0x42, key.length);
    memset(salt.mutableBytes, 0x24, salt.length);
    return [[DeviceSpecificEncryptionParameters alloc] initWithKey:key salt:salt];
}

- (NSData *)legacyEnvelopeForPasscode:(NSString *)passcode parameters:(DeviceSpecificEncryptionParameters *)parameters {
    NSMutableData *payload = [[NSMutableData alloc] init];
    [payload appendData:parameters.key];
    [payload appendData:parameters.salt];
    int hash = murMurHash32Data(payload);
    [payload appendBytes:&hash length:sizeof(hash)];
    [payload setLength:64];
    NSData *passcodeData = [passcode dataUsingEncoding:NSUTF8StringEncoding];
    NSData *sha512 = CryptoSHA512(passcodeData.bytes, passcodeData.length);
    NSData *key = [sha512 subdataWithRange:NSMakeRange(0, 32)];
    NSData *iv = [sha512 subdataWithRange:NSMakeRange(sha512.length - 16, 16)];
    return CryptoAES(YES, key, iv, payload);
}

- (void)assertVersionedEnvelope:(NSData *)data {
    XCTAssertEqual(data.length, 144);
    NSData *magic = [@"TGKEYENC" dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(0, magic.length)], magic);
    uint32_t version = 0;
    uint32_t iterations = 0;
    [data getBytes:&version range:NSMakeRange(8, sizeof(version))];
    [data getBytes:&iterations range:NSMakeRange(12, sizeof(iterations))];
    XCTAssertEqual(CFSwapInt32BigToHost(version), 2);
    XCTAssertGreaterThanOrEqual(CFSwapInt32BigToHost(iterations), 600000);
    XCTAssertLessThanOrEqual(CFSwapInt32BigToHost(iterations), 10000000);
}

- (void)testNewEnvelopeAcceptsCorrectPasscodeAndRejectsWrongPin {
    NSString *rootPath = [self makeRootPath];
    AppEncryptionParameters *encryption = [[AppEncryptionParameters alloc] initWithPath:rootPath];
    DeviceSpecificEncryptionParameters *expected = [encryption decrypt];
    XCTAssertNotNil(expected);
    [encryption change:@"1234"];
    NSString *envelopePath = [self envelopePathForRootPath:rootPath];
    NSData *protectedEnvelope = [NSData dataWithContentsOfFile:envelopePath];
    [self assertVersionedEnvelope:protectedEnvelope];

    AppEncryptionParameters *locked = [[AppEncryptionParameters alloc] initWithPath:rootPath];
    XCTAssertNil([locked decrypt]);
    [locked applyPasscode:@"0000"];
    XCTAssertNil([locked decrypt]);
    XCTAssertEqualObjects([NSData dataWithContentsOfFile:envelopePath], protectedEnvelope);
    [locked applyPasscode:@"1234"];
    DeviceSpecificEncryptionParameters *unlocked = [locked decrypt];
    XCTAssertEqualObjects(unlocked.key, expected.key);
    XCTAssertEqualObjects(unlocked.salt, expected.salt);
}

- (void)testReencryptionUsesUniqueSaltAndPreservesParameters {
    NSString *rootPath = [self makeRootPath];
    AppEncryptionParameters *encryption = [[AppEncryptionParameters alloc] initWithPath:rootPath];
    DeviceSpecificEncryptionParameters *expected = [encryption decrypt];
    [encryption change:@"1234"];
    NSString *envelopePath = [self envelopePathForRootPath:rootPath];
    NSData *firstEnvelope = [NSData dataWithContentsOfFile:envelopePath];
    [encryption change:@"1234"];
    NSData *secondEnvelope = [NSData dataWithContentsOfFile:envelopePath];
    XCTAssertNotEqualObjects([firstEnvelope subdataWithRange:NSMakeRange(16, 16)], [secondEnvelope subdataWithRange:NSMakeRange(16, 16)]);
    XCTAssertNotEqualObjects([firstEnvelope subdataWithRange:NSMakeRange(32, 16)], [secondEnvelope subdataWithRange:NSMakeRange(32, 16)]);
    DeviceSpecificEncryptionParameters *recovered = [encryption decrypt];
    XCTAssertEqualObjects(recovered.key, expected.key);
    XCTAssertEqualObjects(recovered.salt, expected.salt);
}

- (void)testVersionedEnvelopeRejectsAuthenticatedFieldChanges {
    NSString *rootPath = [self makeRootPath];
    AppEncryptionParameters *encryption = [[AppEncryptionParameters alloc] initWithPath:rootPath];
    [encryption change:@"1234"];
    NSString *envelopePath = [self envelopePathForRootPath:rootPath];
    NSData *envelope = [NSData dataWithContentsOfFile:envelopePath];
    for (NSNumber *offset in @[@16, @48, @112]) {
        NSMutableData *modifiedEnvelope = [envelope mutableCopy];
        ((uint8_t *)modifiedEnvelope.mutableBytes)[offset.unsignedIntegerValue] ^= 1;
        XCTAssertTrue([modifiedEnvelope writeToFile:envelopePath atomically:YES]);
        AppEncryptionParameters *modified = [[AppEncryptionParameters alloc] initWithPath:rootPath];
        [modified applyPasscode:@"1234"];
        XCTAssertNil([modified decrypt]);
    }
    XCTAssertTrue([envelope writeToFile:envelopePath atomically:YES]);
    AppEncryptionParameters *restored = [[AppEncryptionParameters alloc] initWithPath:rootPath];
    [restored applyPasscode:@"1234"];
    XCTAssertNotNil([restored decrypt]);
}

- (void)testLegacyEnvelopeMigratesOnlyAfterCorrectPasscode {
    NSString *rootPath = [self makeRootPath];
    NSString *envelopePath = [self envelopePathForRootPath:rootPath];
    DeviceSpecificEncryptionParameters *expected = [self fixtureParameters];
    NSData *legacyEnvelope = [self legacyEnvelopeForPasscode:@"123456" parameters:expected];
    XCTAssertTrue([legacyEnvelope writeToFile:envelopePath atomically:YES]);

    AppEncryptionParameters *encryption = [[AppEncryptionParameters alloc] initWithPath:rootPath];
    [encryption applyPasscode:@"654321"];
    XCTAssertNil([encryption decrypt]);
    XCTAssertEqualObjects([NSData dataWithContentsOfFile:envelopePath], legacyEnvelope);
    [encryption applyPasscode:@"123456"];
    DeviceSpecificEncryptionParameters *migrated = [encryption decrypt];
    XCTAssertEqualObjects(migrated.key, expected.key);
    XCTAssertEqualObjects(migrated.salt, expected.salt);
    NSData *versionedEnvelope = [NSData dataWithContentsOfFile:envelopePath];
    [self assertVersionedEnvelope:versionedEnvelope];

    AppEncryptionParameters *reopened = [[AppEncryptionParameters alloc] initWithPath:rootPath];
    [reopened applyPasscode:@"123456"];
    DeviceSpecificEncryptionParameters *recovered = [reopened decrypt];
    XCTAssertEqualObjects(recovered.key, expected.key);
    XCTAssertEqualObjects(recovered.salt, expected.salt);
}

- (void)testFailedMigrationPreservesLegacyEnvelopeAndUnlocks {
    NSString *rootPath = [self makeRootPath];
    NSString *envelopePath = [self envelopePathForRootPath:rootPath];
    DeviceSpecificEncryptionParameters *expected = [self fixtureParameters];
    NSData *legacyEnvelope = [self legacyEnvelopeForPasscode:@"1234" parameters:expected];
    XCTAssertTrue([legacyEnvelope writeToFile:envelopePath atomically:YES]);

    FailingMigrationEncryptionParameters *encryption = [[FailingMigrationEncryptionParameters alloc] initWithPath:rootPath];
    encryption.failWrites = YES;
    [encryption applyPasscode:@"1234"];
    DeviceSpecificEncryptionParameters *unlocked = [encryption decrypt];
    XCTAssertEqualObjects(unlocked.key, expected.key);
    XCTAssertEqualObjects(unlocked.salt, expected.salt);
    XCTAssertEqualObjects([NSData dataWithContentsOfFile:envelopePath], legacyEnvelope);

    AppEncryptionParameters *retry = [[AppEncryptionParameters alloc] initWithPath:rootPath];
    [retry applyPasscode:@"1234"];
    DeviceSpecificEncryptionParameters *recovered = [retry decrypt];
    XCTAssertEqualObjects(recovered.key, expected.key);
    XCTAssertEqualObjects(recovered.salt, expected.salt);
    [self assertVersionedEnvelope:[NSData dataWithContentsOfFile:envelopePath]];
}

@end

