import unittest
from python_dalton_s2s import s2s
import json

class ServerToServerSignatureTest(unittest.TestCase):
  def test_build_base_str(self):
    method = "POST"
    uri = "http://localhost:8080"
    params = {}
    params['p1'] = "foo"
    params['p2'] = "bar"
    params['fooparam'] = "barval"

    base_str = s2s.SignatureGenerator.build_base_sig_string(method, uri, params)
    print(base_str)

  def test_sign_get_data(self):
    qParams = {}
    qParams['p1'] = "foo"
    qParams['p2'] = "bar"
    qParams['fooparams'] = "barval"

    uri = "http://localhost:8080"
    secret_key = "fooAppSecret"
    calling_application_name = "fooApp"
    encoding_algorithm = "sha1"
    sig = s2s.SignatureGenerator.sign_get_data(qParams, calling_application_name, uri, secret_key, encoding_algorithm)
    print(sig)
    print(sig.signature)

  def test_generate_signature(self):
    params = {}
    params['nonce'] = "nonceVal"
    params['timestamp'] = "1234567890"
    params['applicationName'] = "fooApp"

    base_sig_string = s2s.SignatureGenerator.build_base_sig_string("GET", "http://localhost:8080", params)
    print(base_sig_string)
    sig = s2s.SignatureGenerator.encode(base_sig_string.encode(), "fooAppSecret", "sha1")

    self.assertEqual(sig, "Rb/nZpXg+6+ZJYljbaDA9TwMXlc=")

  def test_sign_post_data1(self):
    body = "This is the body"
    calling_app = "fooApp"
    secret = "fooAppSecret"
    s2sToken = s2s.SignatureGenerator.sign_body_post_data(body.encode(), None, calling_app, "http://localhost:8080", secret, "HmacSHA1")
    print("Post signature: ", s2sToken.signature)


  def test_unknown_algorithm(self):
    with self.assertRaises(s2s.UnknownAlgorithmException):
      s2s.SignatureGenerator.encode("testStr".encode(), "Secret", "rot13")

  def test_sign_body_put_data_with_json_body(self):
    body =  '''{
  "entitlement" : "cnn_subs_video",
  "universalProductIndicator" : "",
  "qualifier" : "",
  "expiration" : 0
}'''

    # json_string = json.dumps(body, indent=2)  # keeps spaces and indentation
    # body_bytes = json_string.encode('utf-8')
    body_bytes = body.encode('utf-8')

    print(body)
    print(body_bytes)

    qParams = {}
    uri = "https://audience.qa.cnn.com/steg/api/1/server/user/08e7671e-cb8d-45ea-bb43-61a44555a416/entitlement"
    secret_key = "Q0k6MRX3sLw1cPwgoMJ2GhzJOUHWonYk"
    calling_application_name = "bolt-load-test"
    encoding_algorithm = "HmacSHA1"
    token = s2s.SignatureGenerator.sign_body_put_data(
      body=body_bytes,
      qParams=qParams,
      calling_application_name=calling_application_name,
      uri=uri,
      secret_key=secret_key,
      encoding_algorithm=encoding_algorithm
    )
    print("Signature token object (body PUT):", token)
    print("Signature string:", token.signature)
    print("Nonce:", token.nonce)
    print("Timestamp:", token.timestamp)
    print("Body hash:", token.body_hash)


if __name__ == '__main__':
    unittest.main()
