import 'dart:typed_data';
import 'dart:convert';
import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:pointycastle/export.dart';

AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRSAkeyPair(
    SecureRandom secureRandom,
    {int bitLength = 2048}) {
  // Create an RSA key generator and initialize it

  final keyGen = RSAKeyGenerator()
      ..init(ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
          secureRandom));

  // Use the generator

  final pair = keyGen.generateKeyPair();

  // Cast the generated key pair into the RSA key types

  final myPublic = pair.publicKey as RSAPublicKey;
  final myPrivate = pair.privateKey as RSAPrivateKey;

  return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(myPublic, myPrivate);
}

SecureRandom exampleSecureRandom() {

  final secureRandom = SecureRandom('Fortuna')
    ..seed(KeyParameter(
        Platform.instance.platformEntropySource().getBytes(32)));
  return secureRandom;
}

final pair = generateRSAkeyPair(exampleSecureRandom());
final public = pair.publicKey;
final private = pair.privateKey;


// This is working when we validate on https://8gwifi.org/RSAFunctionality?rsasignverifyfunctions=rsasignverifyfunctions&keysize=1024
// the key size is 1024
// te algorizm is SHA256withRSA 
void main() {
	final dataToSign = "mahmoud";

	final signature = rsaSign(private, Uint8List.fromList(dataToSign.codeUnits));

	print("signature");
	print(base64.encode(signature));
	print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
	print(signature);
	print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");


	final ok = rsaVerify(public, Uint8List.fromList(dataToSign.codeUnits), signature);

	print("is valid");
	print(ok);
	print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

	print("public key pem");
	print(CryptoUtils.encodeRSAPublicKeyToPem(public));
	print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
	print(public.publicExponent);
	print(public.n);
	print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
}

Uint8List rsaSign(RSAPrivateKey privateKey, Uint8List dataToSign) {

  final signer = RSASigner(SHA256Digest(), '0609608648016503040201');

  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey)); // true=sign

  final sig = signer.generateSignature(dataToSign);

  return sig.bytes;
}

bool rsaVerify(
    RSAPublicKey publicKey, Uint8List signedData, Uint8List signature) {
  final sig = RSASignature(signature);

  final verifier = RSASigner(SHA256Digest(), '0609608648016503040201');

  verifier.init(false, PublicKeyParameter<RSAPublicKey>(publicKey)); // false=verify

  try {
    return verifier.verifySignature(signedData, sig);
  } on ArgumentError {
	return false; // for Pointy Castle 1.0.2 when signature has been modified
  }
}
