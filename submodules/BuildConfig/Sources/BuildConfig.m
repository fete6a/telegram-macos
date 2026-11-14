#import <BuildConfig/BuildConfig.h>

#import <Security/Security.h>
#import <AppKit/AppKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <string.h>

#import <MurMurHash32/MurMurHash32.h>
#import <CryptoUtils/Crypto.h>

static NSString *telegramApplicationSecretKey = @"telegramApplicationSecretKey_v7";


@implementation LocalPrivateKey
    
- (instancetype _Nonnull)initWithPrivateKey:(SecKeyRef)privateKey publicKey:(SecKeyRef)publicKey {
    self = [super init];
    if (self != nil) {
        _privateKey = (SecKeyRef)CFRetain(privateKey);
        _publicKey = (SecKeyRef)CFRetain(publicKey);
    }
    return self;
}
    
- (void)dealloc {
    CFRelease(_privateKey);
    CFRelease(_publicKey);
}
    
- (NSData * _Nullable)getPublicKey {
    NSData *result = CFBridgingRelease(SecKeyCopyExternalRepresentation(_publicKey, nil));
    return result;
}
    
- (NSData * _Nullable)encrypt:(NSData * _Nonnull)data {
    if (data.length % 16 != 0) {
        return nil;
    }
    
    CFErrorRef error = NULL;
    NSData *cipherText = (NSData *)CFBridgingRelease(SecKeyCreateEncryptedData(_publicKey, kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM, (__bridge CFDataRef)data, &error));
    
    if (!cipherText) {
        __unused NSError *err = CFBridgingRelease(error);
        return nil;
    }
    
    return cipherText;
}
    
- (NSData * _Nullable)decrypt:(NSData * _Nonnull)data cancelled:(bool *)cancelled {
    CFErrorRef error = NULL;
    NSData *plainText = (NSData *)CFBridgingRelease(SecKeyCreateDecryptedData(_privateKey, kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM, (__bridge CFDataRef)data, &error));
    
    if (!plainText) {
        __unused NSError *err = CFBridgingRelease(error);
        if (err.code == -2) {
            if (cancelled) {
                *cancelled = true;
            }
        }
        return nil;
    }
    
    return plainText;
}
    
@end


@interface BuildConfig () {
    NSData * _Nullable _bundleData;
    int32_t _apiId;
    NSString * _Nonnull _apiHash;
    NSString * _Nullable _hockeyAppId;
}

@end

@implementation DeviceSpecificEncryptionParameters

- (instancetype)initWithKey:(NSData * _Nonnull)key salt:(NSData * _Nonnull)salt {
    self = [super init];
    if (self != nil) {
        _key = key;
        _salt = salt;
    }
    return self;
}

@end


static const uint8_t AppEncryptionEnvelopeMagic[] = {'T', 'G', 'K', 'E', 'Y', 'E', 'N', 'C'};
static const uint32_t AppEncryptionEnvelopeVersion = 2;
static const uint32_t AppEncryptionMinimumIterations = 600000;
static const uint32_t AppEncryptionMaximumIterations = 10000000;
static const uint32_t AppEncryptionCalibrationMilliseconds = 500;
enum {
    AppEncryptionKdfSaltLength = 16,
    AppEncryptionIvLength = 16,
    AppEncryptionKeyLength = 32,
    AppEncryptionMacLength = 32,
    AppEncryptionPayloadLength = 64,
    AppEncryptionHeaderLength = sizeof(AppEncryptionEnvelopeMagic) + sizeof(uint32_t) + sizeof(uint32_t) + AppEncryptionKdfSaltLength + AppEncryptionIvLength,
    AppEncryptionEnvelopeLength = AppEncryptionHeaderLength + AppEncryptionPayloadLength + AppEncryptionMacLength
};

static NSData *AppEncryptionRandomData(NSUInteger length) {
    NSMutableData *data = [[NSMutableData alloc] initWithLength:length];
    if (SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes) != errSecSuccess) {
        arc4random_buf(data.mutableBytes, length);
    }
    return data;
}

static NSData * _Nullable AppEncryptionDerivedKey(NSString *passcode, NSData *salt, uint32_t iterations) {
    NSData *passwordData = [passcode dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *derivedKey = [[NSMutableData alloc] initWithLength:AppEncryptionKeyLength + AppEncryptionMacLength];
    int status = CCKeyDerivationPBKDF(kCCPBKDF2, passwordData.bytes, passwordData.length, salt.bytes, salt.length, kCCPRFHmacAlgSHA256, iterations, derivedKey.mutableBytes, derivedKey.length);
    if (status != 0) {
        return nil;
    }
    return derivedKey;
}

static NSData *AppEncryptionAuthenticationCode(NSData *data, NSData *key) {
    uint8_t result[AppEncryptionMacLength];
    CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length, result);
    return [[NSData alloc] initWithBytes:result length:sizeof(result)];
}

static BOOL AppEncryptionConstantTimeEqual(NSData *lhs, NSData *rhs) {
    if (lhs.length != rhs.length) {
        return NO;
    }
    const uint8_t *lhsBytes = lhs.bytes;
    const uint8_t *rhsBytes = rhs.bytes;
    uint8_t difference = 0;
    for (NSUInteger index = 0; index < lhs.length; index++) {
        difference |= lhsBytes[index] ^ rhsBytes[index];
    }
    return difference == 0;
}

static void AppEncryptionAppendUInt32(NSMutableData *data, uint32_t value) {
    uint32_t bigEndianValue = CFSwapInt32HostToBig(value);
    [data appendBytes:&bigEndianValue length:sizeof(bigEndianValue)];
}

static uint32_t AppEncryptionReadUInt32(NSData *data, NSUInteger offset) {
    uint32_t value = 0;
    [data getBytes:&value range:NSMakeRange(offset, sizeof(value))];
    return CFSwapInt32BigToHost(value);
}

static BOOL AppEncryptionHasVersionedMagic(NSData *data) {
    if (data.length < sizeof(AppEncryptionEnvelopeMagic)) {
        return NO;
    }
    return memcmp(data.bytes, AppEncryptionEnvelopeMagic, sizeof(AppEncryptionEnvelopeMagic)) == 0;
}

@interface AppEncryptionParameters () {
    NSString * _Nonnull _rootPath;
    NSString * _Nonnull _passcode;
    NSData * _Nonnull key;
    NSData * _Nonnull iv;
}

@end

@implementation AppEncryptionParameters

-(id _Nonnull)initWithPath:(NSString * _Nonnull)path {
    self = [super init];
    if (self != nil) {
        self->_rootPath = path;
        if (![NSFileManager.defaultManager fileExistsAtPath:path]) {
            [NSFileManager.defaultManager createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
        }
        [self applyPasscode:AppEncryptionParameters.defaultKey];
        [self upgradeLegacyIfNeeded];
        [self initializeIfNeeded];
    }
    return self;
}

+(NSString * _Nonnull)defaultKey {
    return @"no-matter-key";
}

-(void)applyPasscode:(NSString * _Nonnull)passcode {
    self->_passcode = [passcode copy];
    NSData *keyData = [passcode dataUsingEncoding:NSUTF8StringEncoding];
    NSData *sha512 = CryptoSHA512(keyData.bytes, keyData.length);
    self->key = [sha512 subdataWithRange:NSMakeRange(0, 32)];
    self->iv = [sha512 subdataWithRange:NSMakeRange(sha512.length - 16, 16)];
}

-(void)initializeIfNeeded {
    if ([NSFileManager.defaultManager fileExistsAtPath:self.path] || [NSFileManager.defaultManager fileExistsAtPath:self.legacyPath]) {
        return;
    }
    NSData *parametersData = AppEncryptionRandomData(32 + 16);
    NSData *keyData = [parametersData subdataWithRange:NSMakeRange(0, 32)];
    NSData *saltData = [parametersData subdataWithRange:NSMakeRange(32, 16)];
    DeviceSpecificEncryptionParameters *parameters = [[DeviceSpecificEncryptionParameters alloc] initWithKey:keyData salt:saltData];
    [self writeVersionedParameters:parameters passcode:self->_passcode];
}

-(NSString *)path {
    return [self->_rootPath stringByAppendingPathComponent:@".tempkeyEncrypted"];
}

-(NSString *)legacyPath {
    return [self->_rootPath stringByAppendingPathComponent:@".tempkey"];
}

-(void)change:(NSString * _Nonnull)passcode {
    DeviceSpecificEncryptionParameters *parameters = [self decrypt];
    if (parameters != nil && [self writeVersionedParameters:parameters passcode:passcode]) {
        [self applyPasscode:passcode];
    }
}
-(void)remove {
    DeviceSpecificEncryptionParameters *parameters = [self decrypt];
    NSString *passcode = [AppEncryptionParameters defaultKey];
    if (parameters != nil && [self writeVersionedParameters:parameters passcode:passcode]) {
        [self applyPasscode:passcode];
    }
}

-(NSData * _Nullable)encryptData:(NSData * _Nonnull)data {
    return CryptoAES(YES, self->key, self->iv, data);
}
-(NSData * _Nullable)decryptData:(NSData * _Nonnull)data {
    return CryptoAES(NO, self->key, self->iv, data);
}

-(void)upgradeLegacyIfNeeded {
    if ([NSFileManager.defaultManager fileExistsAtPath:self.path]) {
        return;
    }
    NSData *currentData = [NSData dataWithContentsOfFile:self.legacyPath];
    if (currentData == nil || currentData.length != 32 + 16) {
        return;
    }
    NSData *keyData = [currentData subdataWithRange:NSMakeRange(0, 32)];
    NSData *saltData = [currentData subdataWithRange:NSMakeRange(32, 16)];
    DeviceSpecificEncryptionParameters *parameters = [[DeviceSpecificEncryptionParameters alloc] initWithKey:keyData salt:saltData];
    if ([self writeVersionedParameters:parameters passcode:self->_passcode]) {
        [[NSFileManager defaultManager] removeItemAtPath:self.legacyPath error:nil];
    }
}

-(NSData * _Nullable)payloadForParameters:(DeviceSpecificEncryptionParameters *)parameters {
    if (parameters.key.length != 32 || parameters.salt.length != 16) {
        return nil;
    }
    NSMutableData *payload = [[NSMutableData alloc] init];
    [payload appendData:parameters.key];
    [payload appendData:parameters.salt];
    int hash = murMurHash32Data(payload);
    [payload appendBytes:&hash length:sizeof(hash)];
    [payload setLength:AppEncryptionPayloadLength];
    return payload;
}

-(DeviceSpecificEncryptionParameters * _Nullable)parametersFromPayload:(NSData *)payload {
    if (payload.length != AppEncryptionPayloadLength) {
        return nil;
    }
    NSData *keyData = [payload subdataWithRange:NSMakeRange(0, 32)];
    NSData *saltData = [payload subdataWithRange:NSMakeRange(32, 16)];
    int storedHash = 0;
    [payload getBytes:&storedHash range:NSMakeRange(32 + 16, sizeof(storedHash))];
    int computedHash = murMurHash32Data([payload subdataWithRange:NSMakeRange(0, 32 + 16)]);
    if (storedHash != computedHash) {
        return nil;
    }
    return [[DeviceSpecificEncryptionParameters alloc] initWithKey:keyData salt:saltData];
}

-(uint32_t)iterationsForPasscode:(NSString *)passcode {
    NSData *passwordData = [passcode dataUsingEncoding:NSUTF8StringEncoding];
    uint32_t calibratedIterations = CCCalibratePBKDF(kCCPBKDF2, passwordData.length, AppEncryptionKdfSaltLength, kCCPRFHmacAlgSHA256, AppEncryptionKeyLength + AppEncryptionMacLength, AppEncryptionCalibrationMilliseconds);
    return MIN(MAX(calibratedIterations, AppEncryptionMinimumIterations), AppEncryptionMaximumIterations);
}

-(NSData * _Nullable)versionedEnvelopeForParameters:(DeviceSpecificEncryptionParameters *)parameters passcode:(NSString *)passcode {
    NSData *payload = [self payloadForParameters:parameters];
    if (payload == nil) {
        return nil;
    }
    NSData *kdfSalt = AppEncryptionRandomData(AppEncryptionKdfSaltLength);
    NSData *encryptionIv = AppEncryptionRandomData(AppEncryptionIvLength);
    uint32_t iterations = [self iterationsForPasscode:passcode];
    NSData *derivedKey = AppEncryptionDerivedKey(passcode, kdfSalt, iterations);
    if (derivedKey == nil) {
        return nil;
    }
    NSData *encryptionKey = [derivedKey subdataWithRange:NSMakeRange(0, AppEncryptionKeyLength)];
    NSData *authenticationKey = [derivedKey subdataWithRange:NSMakeRange(AppEncryptionKeyLength, AppEncryptionMacLength)];
    NSData *encryptedPayload = CryptoAES(YES, encryptionKey, encryptionIv, payload);
    if (encryptedPayload == nil || encryptedPayload.length != AppEncryptionPayloadLength) {
        return nil;
    }
    NSMutableData *envelope = [[NSMutableData alloc] init];
    [envelope appendBytes:AppEncryptionEnvelopeMagic length:sizeof(AppEncryptionEnvelopeMagic)];
    AppEncryptionAppendUInt32(envelope, AppEncryptionEnvelopeVersion);
    AppEncryptionAppendUInt32(envelope, iterations);
    [envelope appendData:kdfSalt];
    [envelope appendData:encryptionIv];
    [envelope appendData:encryptedPayload];
    [envelope appendData:AppEncryptionAuthenticationCode(envelope, authenticationKey)];
    return envelope;
}

-(BOOL)writeEnvelopeData:(NSData *)data {
    return [data writeToFile:self.path options:NSDataWritingAtomic error:nil];
}

-(BOOL)writeVersionedParameters:(DeviceSpecificEncryptionParameters *)parameters passcode:(NSString *)passcode {
    NSData *envelope = [self versionedEnvelopeForParameters:parameters passcode:passcode];
    if (envelope == nil) {
        return NO;
    }
    return [self writeEnvelopeData:envelope];
}

-(DeviceSpecificEncryptionParameters * _Nullable)decryptVersionedEnvelope:(NSData *)envelope {
    if (envelope.length != AppEncryptionEnvelopeLength) {
        return nil;
    }
    NSUInteger versionOffset = sizeof(AppEncryptionEnvelopeMagic);
    uint32_t version = AppEncryptionReadUInt32(envelope, versionOffset);
    uint32_t iterations = AppEncryptionReadUInt32(envelope, versionOffset + sizeof(uint32_t));
    if (version != AppEncryptionEnvelopeVersion || iterations < AppEncryptionMinimumIterations || iterations > AppEncryptionMaximumIterations) {
        return nil;
    }
    NSUInteger saltOffset = versionOffset + sizeof(uint32_t) + sizeof(uint32_t);
    NSData *kdfSalt = [envelope subdataWithRange:NSMakeRange(saltOffset, AppEncryptionKdfSaltLength)];
    NSData *encryptionIv = [envelope subdataWithRange:NSMakeRange(saltOffset + AppEncryptionKdfSaltLength, AppEncryptionIvLength)];
    NSData *derivedKey = AppEncryptionDerivedKey(self->_passcode, kdfSalt, iterations);
    if (derivedKey == nil) {
        return nil;
    }
    NSData *encryptionKey = [derivedKey subdataWithRange:NSMakeRange(0, AppEncryptionKeyLength)];
    NSData *authenticationKey = [derivedKey subdataWithRange:NSMakeRange(AppEncryptionKeyLength, AppEncryptionMacLength)];
    NSData *authenticatedData = [envelope subdataWithRange:NSMakeRange(0, AppEncryptionEnvelopeLength - AppEncryptionMacLength)];
    NSData *storedAuthenticationCode = [envelope subdataWithRange:NSMakeRange(AppEncryptionEnvelopeLength - AppEncryptionMacLength, AppEncryptionMacLength)];
    NSData *computedAuthenticationCode = AppEncryptionAuthenticationCode(authenticatedData, authenticationKey);
    if (!AppEncryptionConstantTimeEqual(storedAuthenticationCode, computedAuthenticationCode)) {
        return nil;
    }
    NSData *encryptedPayload = [envelope subdataWithRange:NSMakeRange(AppEncryptionHeaderLength, AppEncryptionPayloadLength)];
    NSData *payload = CryptoAES(NO, encryptionKey, encryptionIv, encryptedPayload);
    return [self parametersFromPayload:payload];
}

-(BOOL)hasPasscode {
    AppEncryptionParameters *params = [[AppEncryptionParameters alloc] initWithPath:self->_rootPath];
    return [params decrypt] == nil;
}

-(DeviceSpecificEncryptionParameters * _Nullable)decrypt {
    NSData *currentData = [NSData dataWithContentsOfFile:self.path];
    if (currentData == nil) {
        return nil;
    }
    if (AppEncryptionHasVersionedMagic(currentData)) {
        return [self decryptVersionedEnvelope:currentData];
    }
    if (currentData.length != AppEncryptionPayloadLength) {
        return nil;
    }
    NSData *decrypted = CryptoAES(NO, self->key, self->iv, currentData);
    DeviceSpecificEncryptionParameters *parameters = [self parametersFromPayload:decrypted];
    if (parameters != nil) {
        [self writeVersionedParameters:parameters passcode:self->_passcode];
    }
    return parameters;
}

@end


@implementation BuildConfig
+ (NSString *)bundleId {
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
        (__bridge NSString *)kSecClassGenericPassword, (__bridge NSString *)kSecClass,
        @"bundleSeedID", kSecAttrAccount,
        @"", kSecAttrService,
        (id)kCFBooleanTrue, kSecReturnAttributes,
    nil];
    CFDictionaryRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status == errSecItemNotFound) {
        status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    }
    if (status != errSecSuccess) {
        return nil;
    }
    NSString *accessGroup = [(__bridge NSDictionary *)result objectForKey:(__bridge NSString *)kSecAttrAccessGroup];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    NSString *bundleSeedID = [[components objectEnumerator] nextObject];
    CFRelease(result);
    return @"6N38VWS5BX";
}



+ (NSString * _Nullable)bundleSeedId {
    return @"6N38VWS5BX";
}

+ (NSData * _Nonnull)applicationSecretTag:(bool)isCheckKey {
    if (isCheckKey) {
        return [[telegramApplicationSecretKey stringByAppendingString:@"_check"] dataUsingEncoding:NSUTF8StringEncoding];
    } else {
        return [telegramApplicationSecretKey dataUsingEncoding:NSUTF8StringEncoding];
    }
}
    
+ (LocalPrivateKey * _Nullable)getApplicationSecretKey:(NSString * _Nonnull)baseAppBundleId isCheckKey:(bool)isCheckKey  {
    NSString *bundleSeedId = [self bundleSeedId];
    if (bundleSeedId == nil) {
        return nil;
    }
    
    NSData *applicationTag = [self applicationSecretTag:isCheckKey];
    NSString *accessGroup = bundleSeedId;//[bundleSeedId stringByAppendingFormat:@".%@", baseAppBundleId];
    
    NSDictionary *query = @{
                            (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: applicationTag,
                            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
                           // (id)kSecAttrAccessGroup: (id)accessGroup,
                            (id)kSecReturnRef: @YES
                            };
    SecKeyRef privateKey = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);
    if (status != errSecSuccess) {
        return nil;
    }
    
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        if (privateKey) {
            CFRelease(privateKey);
        }
        return nil;
    }
    
    LocalPrivateKey *result = [[LocalPrivateKey alloc] initWithPrivateKey:privateKey publicKey:publicKey];
    
    if (publicKey) {
        CFRelease(publicKey);
    }
    if (privateKey) {
        CFRelease(privateKey);
    }
    
    return result;
}
    
+ (bool)removeApplicationSecretKey:(NSString * _Nonnull)baseAppBundleId isCheckKey:(bool)isCheckKey  {
    NSString *bundleSeedId = [self bundleSeedId];
    if (bundleSeedId == nil) {
        return nil;
    }
    
    NSData *applicationTag = [self applicationSecretTag:isCheckKey];
    NSString *accessGroup = [bundleSeedId stringByAppendingFormat:@".%@", baseAppBundleId];
    
    NSDictionary *query = @{
                            (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: applicationTag,
                            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
                          //  (id)kSecAttrAccessGroup: (id)accessGroup
                            };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess) {
        return false;
    }
    return true;
}
    
+ (LocalPrivateKey * _Nullable)createApplicationSecretKey  {
    
    NSDictionary *attributes = @{
                                 (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
                                 (id)kSecAttrKeySizeInBits: @256,
                                 (id)kSecPrivateKeyAttrs: @{
                                         (id)kSecAttrIsPermanent: @YES,
                                         },
                                 };
    
    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);
    if (!privateKey) {
        
        __unused NSError *err = CFBridgingRelease(error);
        return nil;
    }
    
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        if (privateKey) {
            CFRelease(privateKey);
        }
        
        __unused NSError *err = CFBridgingRelease(error);
        return nil;
    }
    LocalPrivateKey *result = [[LocalPrivateKey alloc] initWithPrivateKey:privateKey publicKey:publicKey];
    
    if (publicKey) {
        CFRelease(publicKey);
    }
    if (privateKey) {
        CFRelease(privateKey);
    }
    return result;
}
    
+ (DeviceSpecificEncryptionParameters * _Nonnull)deviceSpecificEncryptionParameters:(NSString * _Nonnull)rootPath baseAppBundleId:(NSString * _Nonnull)baseAppBundleId {
    CFAbsoluteTime startTime = CFAbsoluteTimeGetCurrent();
    
    NSString *filePath = [rootPath stringByAppendingPathComponent:@".tempkey"];
    
    NSData *currentData = [NSData dataWithContentsOfFile:filePath];
    NSData *resultData = nil;
    if (currentData != nil && currentData.length == 32 + 16) {
        resultData = currentData;
    }
    if (resultData == nil) {
        NSMutableData *randomData = [[NSMutableData alloc] initWithLength:32 + 16];
        if (SecRandomCopyBytes(kSecRandomDefault, randomData.length, randomData.mutableBytes) != errSecSuccess) {
            arc4random_buf(randomData.mutableBytes, randomData.length);
        }
        if (currentData != nil && currentData.length == 32) { // upgrade key with salt
            [currentData getBytes:randomData.mutableBytes length:32];
        }
        resultData = randomData;
        [resultData writeToFile:filePath atomically:false];
    }
    
    
    CFAbsoluteTime endTime = CFAbsoluteTimeGetCurrent();
    NSLog(@"deviceSpecificEncryptionParameters took %f ms", (endTime - startTime) * 1000.0);
    
    NSData *key = [resultData subdataWithRange:NSMakeRange(0, 32)];
    NSData *salt = [resultData subdataWithRange:NSMakeRange(32, 16)];
    return [[DeviceSpecificEncryptionParameters alloc] initWithKey:key salt:salt];
}


    
+ (dispatch_queue_t)encryptionQueue {
    static dispatch_queue_t instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = dispatch_queue_create("encryptionQueue", 0);
    });
    return instance;
}
//    
//    
//+ (void)encryptApplicationSecret:(NSData * _Nonnull)secret baseAppBundleId:(NSString * _Nonnull)baseAppBundleId completion:(void (^)(NSData * _Nullable, NSData * _Nullable))completion {
//    dispatch_async([self encryptionQueue], ^{
//        LocalPrivateKey *privateKey = [self getApplicationSecretKey:baseAppBundleId isCheckKey:false];
//        if (privateKey == nil) {
//            [self removeApplicationSecretKey:baseAppBundleId isCheckKey:false];
//            [self removeApplicationSecretKey:baseAppBundleId isCheckKey:true];
//            privateKey = [self addApplicationSecretKey:baseAppBundleId isCheckKey:false];
//            privateKey = [self addApplicationSecretKey:baseAppBundleId isCheckKey:true];
//        }
//        if (privateKey == nil) {
//            completion(nil, nil);
//            return;
//        }
//        NSData *result = [privateKey encrypt:secret];
//        completion(result, [privateKey getPublicKey]);
//    });
//}
//    
//+ (void)decryptApplicationSecret:(NSData * _Nonnull)secret publicKey:(NSData * _Nonnull)publicKey baseAppBundleId:(NSString * _Nonnull)baseAppBundleId completion:(void (^)(NSData * _Nullable))completion {
//    dispatch_async([self encryptionQueue], ^{
//        LocalPrivateKey *privateKey = [self getApplicationSecretKey:baseAppBundleId isCheckKey:false];
//        if (privateKey == nil) {
//            completion(nil);
//            return;
//        }
//        if (privateKey == nil) {
//            completion(nil);
//            return;
//        }
//        NSData *currentPublicKey = [privateKey getPublicKey];
//        if (currentPublicKey == nil) {
//            completion(nil);
//            return;
//        }
//        if (![publicKey isEqualToData:currentPublicKey]) {
//            completion(nil);
//            return;
//        }
//        NSData *result = [privateKey decrypt:secret cancelled:nil];
//        completion(result);
//    });
//}
//    
//


@end
