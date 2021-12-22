import 'dart:typed_data';

import 'rncryptor_settings.dart';

class RNCryptorHeader {
  int version;
  int options;
  Uint8List? encryptionSalt;
  Uint8List? hmacSalt;
  Uint8List iv;
  int length;

  RNCryptorHeader(
      {required this.version,
      required this.options,
      required this.encryptionSalt,
      required this.hmacSalt,
      required this.iv,
      required this.length});

  static RNCryptorHeader? fromBuffer(Uint8List bufferData) {
    var offset = 0;

    final int version = bufferData[offset++];
    if (version != 3) {
      return null;
    }

    final int options = bufferData[offset++];

    Uint8List? encryptionSalt;
    Uint8List? hmacSalt;
    if (options == 1) {
      encryptionSalt =
          bufferData.sublist(offset, offset + RNCryptorSettings.saltLength);
      offset += encryptionSalt.length;
      hmacSalt =
          bufferData.sublist(offset, offset + RNCryptorSettings.saltLength);
      offset += hmacSalt.length;
    }
    final iv = bufferData.sublist(offset, offset + RNCryptorSettings.ivLength);
    offset += iv.length;

    return RNCryptorHeader(
        version: version,
        options: options,
        encryptionSalt: encryptionSalt,
        hmacSalt: hmacSalt,
        iv: iv,
        length: offset);
  }
}
