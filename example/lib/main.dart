import 'package:flutter/material.dart';
import 'package:rncryptor/rncryptor.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
        title: 'RNCryptor Demo',
        theme: ThemeData(
          primarySwatch: Colors.blue,
        ),
        home: HomePage());
  }
}

class HomePage extends StatelessWidget {
  final conteoller = TextEditingController();
  final encryptionKey =
      RNCryptor.generateKey('some_strong_password', RNCryptor.generateSalt());
  final hmacKey =
      RNCryptor.generateKey('some_strong_password', RNCryptor.generateSalt());

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
        title: 'RNCryptor Demo',
        theme: ThemeData(
          primarySwatch: Colors.blue,
        ),
        home: Scaffold(
            body: SafeArea(
                child: Padding(
                    padding: EdgeInsets.fromLTRB(20, 20, 20, 20),
                    child: Column(children: [
                      TextField(
                          controller: conteoller,
                          decoration:
                              InputDecoration(hintText: 'Text to encrypt')),
                      SizedBox(height: 12),
                      ElevatedButton(
                          onPressed: () {
                            onEncrypt(context);
                          },
                          child: Text('Encrypt with password')),
                      ElevatedButton(
                          onPressed: () {
                            onEncrypt2(context);
                          },
                          child: Text('Encrypt with key')),
                    ])))));
  }

  onEncrypt(BuildContext context) {
    var password = 'some_strong_password';
    var encrypted = RNCryptor.encrypt(password, conteoller.text);
    var decrypted = RNCryptor.decrypt(password, encrypted);
    showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
              title: Text("Encrypted text"),
              content: Column(children: [
                Text(encrypted),
                SizedBox(height: 12),
                Text('Decrypted: $decrypted')
              ]),
              actions: [
                TextButton(
                    child: Text('Ok'),
                    onPressed: () {
                      Navigator.of(context).pop();
                    })
              ]);
        });
  }

  onEncrypt2(BuildContext context) {
    var encrypted =
        RNCryptor.encryptWithKey(encryptionKey, hmacKey, conteoller.text);
    var decrypted = RNCryptor.decryptWithKey(encryptionKey, hmacKey, encrypted,
        checkHmac: false);
    showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
              title: Text("Encrypted text"),
              content: Column(children: [
                Text(encrypted),
                SizedBox(height: 12),
                Text('Decrypted: $decrypted')
              ]),
              actions: [
                TextButton(
                    child: Text('Ok'),
                    onPressed: () {
                      Navigator.of(context).pop();
                    })
              ]);
        });
  }
}
