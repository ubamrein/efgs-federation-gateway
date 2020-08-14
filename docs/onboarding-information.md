#Onboarding Information EU Federation Gateway Service
The following document describes how to transmit diagnosis keys of the Exposure Notification API to the EU Federation Gateway Service (EFGS).
Please read the software design document for more detailed and technical information.

##Prerequisites
In order to transmit diagnosis keys you need two certificates:

###Signing Certificate
A signing certificate is needed to create signatures for the batches of diagnosis keys.
You can create the signing certificate by your own.
Either create a self signed certificate or issue a certificate which is signed by a CA of your choice.
Please notice: The country attribute of you signing certificate must be your 2-letter country abbreviation. 
For the uploaded data to be accepted, the SHA-256 hash of the certificate (not the private key) must be transmitted to the operations team. (please ask your personal contact person)

###Authentication Certificate
The REST service itself is secured with mTLS. The personal client certificate will be issued by EFGS team. (please ask your personal contact person)

###Infrastructure
The server on which your federation client runs needs to be publicly reachable.
This is needed because the EFGS will notify your service about new diagnosis key batches via the callback feature.

###Callback Certificate
The callback request will be done with mTLS, too.
To be able to get notified via callbacks the EFGS team needs a client certificate to access your infrastructure.
Please ask your personal contact person to transmit the certificate.

##Upload keys
The uploading of keys has to be done in batches. (At the moment 5000 keys at once can be uploaded - this value can change in future).
To upload your keys it is suggested to transmit them in Protobuf format. You can find a Protobuf format file in this repository (src/main/proto/Efgs.proto).
If it is not possible for you to transmit data in Protobuf format also a JSON formatted upload would be possible.

The upload is done by a POST request against the ```/efgs/diagnosiskeys/upload``` endpoint.

The following headers must be set:

| Header name | example value | description |
| --- | --- | --- |
| Accept | application/json; version=1.0 | The Mime-Type you are expecting the EFGS should answer. Please note the special MIME types which requires a version parameter. |
| Content-Type | application/protobuf; version=1.0 | The Mime-Type of the content you are sending. Please note the special MIME types which requires a version parameter. |
| batchTag | bt-de-14082020-00001 | Tag you uploaded data with a custom string (for future features) |
| batchSignature | MSMSdklw....AAAA= | The calculated signature of the batch (see [Upload Signing](#upload-signing)) |

The backend will respond with a 201 status code if all diagnosis keys could be added. For further details about status codes and possible errors please consult the OpenAPI documentation.

###Upload Signing

Each batch of uploaded data needs to be signed. The signing is done over the raw data to avoid different signatures because of different property fields.
Detailed information about the signing process can be found in software-design document in section 3.2 Signature Verification.

The following Java code snippet can be used to calculate the bytes that have to be signed for a diagnosis key batch:

```java
public static byte[] createBytesToSign(final DiagnosisKeyBatch batch) {
    final ByteArrayOutputStream batchBytes = new ByteArrayOutputStream();
    final List<DiagnosisKey> sortedBatch = batch.getKeysList()
        .stream()
        .sorted(Comparator.comparing(diagnosisKey -> diagnosisKey.getKeyData().toStringUtf8()))
        .collect(Collectors.toList());
    
    for (DiagnosisKey diagnosisKey : sortedBatch) {
      batchBytes.writeBytes(diagnosisKey.getKeyData().toStringUtf8().getBytes(StandardCharsets.UTF_8));
      batchBytes.writeBytes(ByteBuffer.allocate(4).putInt(diagnosisKey.getRollingStartIntervalNumber()).array());
      batchBytes.writeBytes(ByteBuffer.allocate(4).putInt(diagnosisKey.getRollingPeriod()).array());
      batchBytes.writeBytes(ByteBuffer.allocate(4).putInt(diagnosisKey.getTransmissionRiskLevel()).array());
    
      diagnosisKey.getVisitedCountriesList().forEach(country -> {
        batchBytes.writeBytes(country.getBytes(StandardCharsets.UTF_8));
      });
    
      batchBytes.writeBytes(diagnosisKey.getOrigin().getBytes(StandardCharsets.UTF_8));
      batchBytes.writeBytes(ByteBuffer.allocate(4).putInt(diagnosisKey.getReportTypeValue()).array());
      batchBytes.writeBytes(ByteBuffer.allocate(4).putInt(diagnosisKey.getDaysSinceOnsetOfSymptoms()).array());
    }
    return batchBytes.toByteArray();
}
```

With this method the signature of the previously calculated bytes can be calculated (This examples uses BouncyCastle, please consult their documentation for setup):

```java
  private String sign(final byte[] data, X509Certificate cert, KeyPair keyPair) throws CertificateEncodingException, OperatorCreationException, IOException, CMSException {
    final CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

    final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA")
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(keyPair.getPrivate());

    signedDataGenerator.addSignerInfoGenerator(
      new JcaSignerInfoGeneratorBuilder(createDigestBuilder()).build(contentSigner, cert));

    signedDataGenerator.addCertificate(new X509CertificateHolder(cert.getEncoded()));

    CMSSignedData singedData = signedDataGenerator.generate(new CMSProcessableByteArray(data), false);
    return Base64.getEncoder().encodeToString(singedData.getEncoded());
  }
```

##Download batches
The EFGS automaticaly bundles uploaded diagnosis keys to batches.
These batches are tagged with a batchtag (not the upload batchtag!).
It is not possible to download keys from your own country!

Downloading of keys works also via REST API. A GET request against the ```/efgs/diagnosiskeys/download/{{data}}``` endpoint is needed.

The path has one parameter: The date of the data you want to download. The date has to be in the following format: ```YYYY-MM-DD```

Performing this request the first batch of diagnosis keys of the day will be answered.
To get any further batches the ```batchTag``` response header has to be used as request header in the following request against this endpoint.
If a download response has the response header ```batchTag``` with the string value "null" then no further batches for this day are available.

The data is - like the uploaded data - primary transferred as Protobuf messages. (JSON as fallback is possible)

##Verify Batch Integrity

tbd

##Automatically receive updates (Callbacks, not yet implemented)
The EFGS automatically notifies national backends about newly created batches which are ready to download.

###Register Callback
To receive the updates at first the registration of a callback is required. To do this send a PUT request against the ```/efgs/callback/{{id}}``` endpoint.
It is required to provide two parameters.
The first ```id``` is provided in request path. This id is your personal identifier to manage your callback subscriptions. You can choose this identifier randomly.
The second parameter is a query parameter which needs to be appended to the request url: ```url```. The url parameter contains the url the EFGS should send the callback notification to.

###Unregister Callback
To stop receiving updates just perform a DELETE request against the ```/efgs/callback/{{id}}``` endpoint. As id you have to use the id from the registration of the callback.

###Receive a Callback
The backend will perform a GET request against the url you have provided at registration. The request has no body, but two query parameters:

| query parameter | example | content |
| --- | --- | --- |
| batchTag | 20200813-04 | The batchtag of the newly created batch |
| date | 20200813 | The corresponding date to the batch |

With the help of these two parameters a download request can be made.
 


