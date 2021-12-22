import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import "package:pointycastle/export.dart";

import 'rncryptor_settings.dart';
import 'rncryptor_components.dart';

/// A high-level AES encryptor/decryptor engine compatible with RNCryptor
class RNCryptor {
  /// Encrypts plain text by using the specified password.
  static String encrypt(String password, String plainText) {
    final encryptionSalt = generateSalt();
    final hmacSalt = generateSalt();
    final iv = _generateIv(RNCryptorSettings.ivLength);

    final encryptionKey = generateKey(password, encryptionSalt);
    final hmacKey = generateKey(password, hmacSalt);
    final cipherText = _encryptCore(encryptionKey, iv, plainText)!;

    var data = BytesBuilder();
    data.add([RNCryptorSettings.version]);
    data.add([1]);
    data.add(encryptionSalt);
    data.add(hmacSalt);
    data.add(iv);
    data.add(cipherText);

    final hmac = _generateHmac(data.toBytes(), hmacKey);
    data.add(hmac);

    return base64.encode(data.toBytes());
  }

  /// Encrypts the input text by using a 32 byte length key and 16 byte length initialization vector.
  static String encryptWithKey(
      Uint8List encryptionKey, Uint8List hmacKey, String plainText) {
    final iv = _generateIv(RNCryptorSettings.ivLength);
    final cipherText = _encryptCore(encryptionKey, iv, plainText)!;

    var data = BytesBuilder();
    data.add([RNCryptorSettings.version]);
    data.add([0]);
    data.add(iv);
    data.add(cipherText);

    final hmac = _generateHmac(data.toBytes(), hmacKey);
    data.add(hmac);

    return base64.encode(data.toBytes());
  }

  static Uint8List? _encryptCore(
      Uint8List encryptionKey, Uint8List iv, String plainText) {
    final paddedPlainText = _addPkcs7Padding(plainText, iv.length);
    final cipher = CBCBlockCipher(AESEngine());
    final params = ParametersWithIV(KeyParameter(encryptionKey), iv);
    cipher.init(true, params);
    final textBytes = Uint8List.fromList(paddedPlainText.codeUnits);
    final cipherText = _processBlocks(cipher, textBytes);
    return cipherText;
  }

  /// Encrypts the input text by using the specified password.
  static String? decrypt(String password, String b64str,
      {bool checkHmac = true}) {
    final data = base64.decode(b64str);
    final components = RNCryptorComponents.fromBuffer(data);
    if (components == null || components.header.options != 1) {
      return null;
    }
    if (checkHmac) {
      var hmacKey = generateKey(password, components.header.hmacSalt!);
      var hmacData =
          data.sublist(0, data.length - RNCryptorSettings.hmacLength);
      var hmac = _generateHmac(hmacData, hmacKey);
      if (!ListEquality().equals(components.hmac, hmac)) {
        return null;
      }
    }
    try {
      final key = generateKey(password, components.header.encryptionSalt!);
      return _decryptCore(key, components.header.iv, components.cipherText);
    } catch (e) {
      return null;
    }
  }

  /// Decrypts the input text by using a 32 byte length key and 16 byte length initialization vector.
  static String? decryptWithKey(
      Uint8List encryptionKey, Uint8List hmacKey, String b64str,
      {bool checkHmac = true}) {
    final data = base64.decode(b64str);
    final components = RNCryptorComponents.fromBuffer(data);
    if (components == null || components.header.options != 0) {
      return null;
    }
    if (checkHmac) {
      var hmacData =
          data.sublist(0, data.length - RNCryptorSettings.hmacLength);
      var hmac = _generateHmac(hmacData, hmacKey);
      if (!ListEquality().equals(components.hmac, hmac)) {
        return null;
      }
    }
    try {
      return _decryptCore(
          encryptionKey, components.header.iv, components.cipherText);
    } catch (e) {
      return null;
    }
  }

  static String? _decryptCore(
      Uint8List key, Uint8List iv, Uint8List encrypted) {
    try {
      final cipher = CBCBlockCipher(AESEngine());
      cipher.init(false, ParametersWithIV(KeyParameter(key), iv));
      final decrypted = _processBlocks(cipher, encrypted);
      return _stripPkcs7Padding(decrypted);
    } catch (e) {
      return null;
    }
  }

  /// Generates a 32 byte length key by using the specified password and a password salt.
  static Uint8List generateKey(String password, Uint8List salt) {
    var passwordBytes = Uint8List.fromList(password.codeUnits);
    var params = Pbkdf2Parameters(
        salt, RNCryptorSettings.pbkdf2Iterations, RNCryptorSettings.keyLength);
    var keyDerivator = PBKDF2KeyDerivator(HMac(SHA1Digest(), 64));
    keyDerivator.init(params);
    return keyDerivator.process(passwordBytes);
  }

  /// Generates a random password salt with 8 bytes length.
  static Uint8List generateSalt() {
    return _generateIv(RNCryptorSettings.saltLength);
  }

  static Uint8List _generateIv(int blockSize) {
    var rng = Random();
    var list = Uint8List(blockSize);
    for (int i = 0; i < blockSize; i++) {
      list[i] = rng.nextInt(256);
    }
    return list;
  }

  static Uint8List _generateHmac(Uint8List data, Uint8List hmacKey) {
    var hmac = HMac(SHA256Digest(), 64);
    hmac.init(KeyParameter(hmacKey));
    return hmac.process(data);
  }

  static Uint8List _processBlocks(BlockCipher cipher, Uint8List inp) {
    var out = Uint8List(inp.lengthInBytes);
    for (var offset = 0; offset < inp.lengthInBytes;) {
      var len = cipher.processBlock(inp, offset, out, offset);
      offset += len;
    }
    return out;
  }

  static String _stripPkcs7Padding(Uint8List plainText) {
    var padLength = plainText[plainText.length - 1];
    return utf8.decode(plainText.sublist(0, plainText.length - padLength));
  }

  static String _addPkcs7Padding(String plainText, int blockSize) {
    var padSize = blockSize - (plainText.length % blockSize);
    return plainText + ''.padRight(padSize - 1) + String.fromCharCode(padSize);
  }
}
