import 'dart:typed_data';

import 'rncryptor_settings.dart';
import 'rncryptor_header.dart';

class RNCryptorComponents {
  RNCryptorHeader header;
  Uint8List hmac;
  Uint8List cipherText;

  RNCryptorComponents(
      {required this.header, required this.hmac, required this.cipherText});

  static RNCryptorComponents? fromBuffer(Uint8List data) {
    final header = RNCryptorHeader.fromBuffer(data);
    if (header == null) {
      return null;
    }

    final hmac = data.sublist(data.length - RNCryptorSettings.hmacLength);
    final headerLength = header.length;
    final cipherTextLength = data.length - headerLength - hmac.length;
    final cipherText =
        data.sublist(headerLength, headerLength + cipherTextLength);
    return RNCryptorComponents(
        header: header, hmac: hmac, cipherText: cipherText);
  }
}
