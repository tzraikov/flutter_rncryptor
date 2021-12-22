## Flutter RNCryptor package

A high-level AES encryption/decryption library compatible with Rob Napier's [RNCryptor](https://github.com/RNCryptor/RNCryptor) for iOS. This implementation is based on [JSCryptor](https://github.com/chesstrian/JSCryptor) and uses [pointycastle](https://pub.dev/packages/pointycastle) under the hood.

RNCryptor specification can be found [here](https://github.com/RNCryptor/RNCryptor-Spec).

## Usage

First import it in your Dart code:

```dart
import 'package:rncryptor/rncryptor.dart';
```

Using RNCryptor is simple, just call the *encrypt* method to encrypt your text by using the specified *password*:

```dart
var encrypted = RNCryptor.encrypt('my password', 'some plain text');
```

Call *decrypt* method to decrypt the encrypted text:

```dart
var encrypted = RNCryptor.decrypt('my password', 'an encrypted message');
```

Converting a password into a key is intentionally slow. In case your app encrypts/decrypts many short messages, using password would have a significant performance impact. In that case using keys would be preferred.

Use the *generateKey* method to generate a new key from a password and a salt:

```dart
var salt = RNCryptor.generateSalt();
var encryptKey = RNCryptor.generateKey('my password', salt);
```

RNCryptor uses two 256-bit (32 byte) length keys for encryption and authentication. The *encryptWithKey* method encrypts the message with the specified keys:

```dart
RNCryptor.encryptWithKey(encryptKey, hmacKey, 'some plain text');
```

Call the *decryptWithKey* method to decrypt a message encrypted with a known key:

```dart
RNCryptor.decryptWithKey(encryptKey, hmacKey, 'an encrypted message');
```
