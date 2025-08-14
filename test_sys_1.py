import unittest
import csv
import requests
from python_dalton_s2s import s2s_1


class ServerToServerSignatureTest(unittest.TestCase):

  # Read the UUIDs from the CSV file and attach the entitlement to each UUID

  def read_uuids_from_csv(self, csv_file_path):
    uuids = []
    with open(csv_file_path, mode='r', newline='') as csvfile:
      reader = csv.reader(csvfile)
      for row in reader:
        if row:  # Ensure the row is not empty
          uuids.append(row[0])
    return uuids

  def test_sign_body_put_data_with_json_body(self):
    csv_path = "CNNUsers_Updated.csv"
    uuids = self.read_uuids_from_csv(csv_path)

    body = '''{
    "entitlement": "cnn_subs_video",
    "qualifier": "",
    "expiration": "1767162037000"
}'''
    body_bytes = body.encode('utf-8')

    qParams = {}
    secret_key = "Q0k6MRX3sLw1cPwgoMJ2GhzJOUHWonYk"
    calling_application_name = "bolt-load-test"
    encoding_algorithm = "HmacSHA1"

    for uuid in uuids:
      with self.subTest(uuid=uuid):
        print(f"uuid value: {uuid}, type: {type(uuid)}")
        uri = f"https://audience.qa.cnn.com/steg/api/1/server/user/{uuid}/entitlement"
        token = s2s_1.SignatureGenerator.sign_body_put_data(
          body=body_bytes,
          qParams=qParams,
          calling_application_name=calling_application_name,
          uri=uri,
          secret_key=secret_key,
          encoding_algorithm=encoding_algorithm
        )

        token_str = str(token)


        headers = {
          'authorization': token_str,
          'Content-Type': 'application/json'
        }
        response = requests.put(uri, headers=headers, data=body)
        print("Status Code:", response.status_code)
        print("Response Body:", response.text)
        with open("failed_responses.csv", mode="a", newline="") as file:
          writer = csv.writer(file)
          writer.writerow([uuid, response.status_code])





    # def send_put_request_with_token(url, token):
    #   headers = {
    #     'authorization': token,
    #     'Content-Type': 'text/plain'
    #   }
    #
    #   print("the request token is:", token)
    #
    #   data = '''{
    #       "entitlement": "cnn_subs_video",
    #       "qualifier": "",
    #       "expiration": "1767162037000"
    #   }'''
    #
    #   response = requests.put(url, headers=headers, data=data)
    #
    #   print("Status Code:", response.status_code)
    #   print("Response Body:", response.text)
    #
    #   if __name__ == "__main__":
    #     url = "https://audience.qa.cnn.com/steg/api/1/server/user/976450c5-1ad0-4959-bf2c-9bb8e2ef39a6/entitlement"
    #   token = "authtoek"
    #   send_put_request_with_token(url, token)


if __name__ == '__main__':
  unittest.main()
